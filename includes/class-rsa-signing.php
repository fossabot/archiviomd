<?php
/**
 * RSA Compatibility Signing — ArchivioMD  ⚠ Enterprise / Legacy Mode
 *
 * Produces RSA-PSS (SHA-256) or PKCS#1 v1.5 (SHA-256) detached signatures
 * over the same canonical message as the core Ed25519 / SLH-DSA / ECDSA
 * algorithms. Intended for legacy enterprise middleware that cannot consume
 * modern key types.
 *
 * ── Post meta keys ───────────────────────────────────────────────────────────
 *
 *   _mdsm_rsa_sig        Hex-encoded raw signature bytes
 *   _mdsm_rsa_signed_at  Unix timestamp of signing time
 *   _mdsm_rsa_scheme     'rsa-pss-sha256' or 'rsa-pkcs1v15-sha256'
 *   _mdsm_rsa_pubkey     PEM public key (cached for offline verification)
 *
 * ── wp-config.php constants ──────────────────────────────────────────────────
 *
 *   ARCHIVIOMD_RSA_PRIVATE_KEY_PEM   PEM-encoded RSA private key (PKCS#8 or PKCS#1)
 *   ARCHIVIOMD_RSA_CERTIFICATE_PEM   PEM X.509 cert (optional; public key published
 *                                     instead when absent)
 *   ARCHIVIOMD_RSA_SCHEME            'rsa-pss-sha256' (default) or 'rsa-pkcs1v15-sha256'
 *
 * Public key is served at /.well-known/rsa-pubkey.pem
 *
 * @package ArchivioMD
 * @since   1.16.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_RSA_Signing {

	// ── wp-config.php constant names ─────────────────────────────────────────
	const CONSTANT_PRIVATE_KEY  = 'ARCHIVIOMD_RSA_PRIVATE_KEY_PEM';
	const CONSTANT_CERTIFICATE  = 'ARCHIVIOMD_RSA_CERTIFICATE_PEM';
	const CONSTANT_SCHEME       = 'ARCHIVIOMD_RSA_SCHEME';

	// ── Post meta keys ───────────────────────────────────────────────────────
	const META_SIG              = '_mdsm_rsa_sig';
	const META_SIGNED_AT        = '_mdsm_rsa_signed_at';
	const META_SCHEME           = '_mdsm_rsa_scheme';
	const META_PUBKEY           = '_mdsm_rsa_pubkey';

	// ── Signing schemes ──────────────────────────────────────────────────────
	const SCHEME_PSS            = 'rsa-pss-sha256';
	const SCHEME_PKCS1          = 'rsa-pkcs1v15-sha256';
	const SCHEME_DEFAULT        = self::SCHEME_PSS;

	// ── Well-known URL slug ──────────────────────────────────────────────────
	const WELL_KNOWN_PUBKEY     = 'rsa-pubkey.pem';

	// ── Option key for filesystem path fallback ──────────────────────────────
	const OPTION_KEY_PATH       = 'archiviomd_rsa_key_path';

	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'save_post',      array( $this, 'maybe_sign_post' ),  35, 2 );
		add_action( 'add_attachment', array( $this, 'maybe_sign_media' ), 35    );
	}

	// ── Prerequisite checks ──────────────────────────────────────────────────

	public static function is_openssl_available(): bool {
		return extension_loaded( 'openssl' )
			&& function_exists( 'openssl_sign' )
			&& function_exists( 'openssl_pkey_get_private' )
			&& function_exists( 'openssl_pkey_get_details' );
	}

	public static function is_mode_enabled(): bool {
		return (bool) get_option( 'archiviomd_rsa_enabled', false );
	}

	public static function is_private_key_defined(): bool {
		if ( defined( self::CONSTANT_PRIVATE_KEY ) && '' !== constant( self::CONSTANT_PRIVATE_KEY ) ) {
			return true;
		}
		return (bool) get_option( self::OPTION_KEY_PATH, '' );
	}

	public static function get_scheme(): string {
		if ( defined( self::CONSTANT_SCHEME ) ) {
			$s = constant( self::CONSTANT_SCHEME );
			if ( in_array( $s, array( self::SCHEME_PSS, self::SCHEME_PKCS1 ), true ) ) {
				return $s;
			}
		}
		$stored = get_option( 'archiviomd_rsa_scheme', self::SCHEME_DEFAULT );
		return in_array( $stored, array( self::SCHEME_PSS, self::SCHEME_PKCS1 ), true )
			? $stored
			: self::SCHEME_DEFAULT;
	}

	// ── PEM retrieval — constants take priority over filesystem paths ─────────

	private static function load_private_key_pem(): string {
		if ( defined( self::CONSTANT_PRIVATE_KEY ) ) {
			$pem = constant( self::CONSTANT_PRIVATE_KEY );
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}
		$path = get_option( self::OPTION_KEY_PATH, '' );
		if ( $path && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}
		return '';
	}

	public static function load_certificate_pem(): string {
		if ( defined( self::CONSTANT_CERTIFICATE ) ) {
			$pem = constant( self::CONSTANT_CERTIFICATE );
			if ( is_string( $pem ) && str_contains( $pem, 'CERTIFICATE' ) ) {
				return $pem;
			}
		}
		$path = get_option( 'archiviomd_rsa_cert_path', '' );
		if ( $path && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'CERTIFICATE' ) ) {
				return $pem;
			}
		}
		return '';
	}

	// ── Status ───────────────────────────────────────────────────────────────

	public static function status(): array {
		$mode_enabled      = self::is_mode_enabled();
		$openssl_available = self::is_openssl_available();
		$key_configured    = self::is_private_key_defined();
		$ready             = $mode_enabled && $openssl_available && $key_configured;

		$notice_level   = 'ok';
		$notice_message = __( 'RSA signing is active and operational.', 'archiviomd' );

		if ( $mode_enabled ) {
			if ( ! $openssl_available ) {
				$notice_level   = 'error';
				$notice_message = __( 'ext-openssl is not available — required for RSA signing. Contact your host.', 'archiviomd' );
			} elseif ( ! $key_configured ) {
				$notice_level   = 'error';
				$notice_message = sprintf(
					/* translators: %s: wp-config.php constant name */
					__( 'RSA mode is enabled but no private key is configured. Define %s in wp-config.php or upload a PEM key in the Extended settings.', 'archiviomd' ),
					self::CONSTANT_PRIVATE_KEY
				);
			}
		}

		return array(
			'mode_enabled'      => $mode_enabled,
			'openssl_available' => $openssl_available,
			'key_configured'    => $key_configured,
			'ready'             => $ready,
			'scheme'            => self::get_scheme(),
			'notice_level'      => $notice_level,
			'notice_message'    => $notice_message,
		);
	}

	// ── Canonical message builders ────────────────────────────────────────────
	// Identical format as Ed25519 / SLH-DSA / ECDSA — same bytes, additional sig format.

	public static function canonical_message_post( int $post_id ): string {
		$post = get_post( $post_id );
		if ( ! $post ) {
			return '';
		}
		return implode( "\n", array(
			'mdsm-ed25519-v1',
			(string) $post_id,
			$post->post_title,
			$post->post_name,
			wp_strip_all_tags( $post->post_content ),
			$post->post_date_gmt,
		) );
	}

	public static function canonical_message_media( int $attachment_id ): string {
		$post = get_post( $attachment_id );
		if ( ! $post || $post->post_type !== 'attachment' ) {
			return '';
		}
		$filepath = get_attached_file( $attachment_id );
		$filename = $filepath ? basename( $filepath ) : '';
		$filesize = ( $filepath && file_exists( $filepath ) ) ? (string) filesize( $filepath ) : '0';

		return implode( "\n", array(
			'mdsm-ed25519-media-v1',
			(string) $attachment_id,
			$filename,
			$filesize,
			(string) get_post_mime_type( $attachment_id ),
			(string) $post->post_author,
			$post->post_date_gmt,
		) );
	}

	// ── Sign ─────────────────────────────────────────────────────────────────

	/**
	 * Sign a message with the configured RSA private key.
	 *
	 * @param  string $message  Canonical message to sign.
	 * @return array|WP_Error   Array{sig_hex:string, scheme:string}, or WP_Error on failure.
	 */
	public static function sign( string $message ) {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'rsa_no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$key_pem = self::load_private_key_pem();
		if ( ! $key_pem ) {
			return new WP_Error( 'rsa_no_key', __( 'RSA private key is not configured.', 'archiviomd' ) );
		}

		$pkey = openssl_pkey_get_private( $key_pem );
		if ( ! $pkey ) {
			return new WP_Error( 'rsa_bad_key', __( 'Failed to load RSA private key — check PEM format.', 'archiviomd' ) );
		}

		$key_details = openssl_pkey_get_details( $pkey );
		if ( ! $key_details || $key_details['type'] !== OPENSSL_KEYTYPE_RSA ) {
			return new WP_Error( 'rsa_wrong_key_type', __( 'Configured key is not an RSA key.', 'archiviomd' ) );
		}
		if ( $key_details['bits'] < 2048 ) {
			return new WP_Error( 'rsa_key_too_small', __( 'RSA key must be at least 2048 bits.', 'archiviomd' ) );
		}

		$scheme  = self::get_scheme();
		$sig_raw = '';

		if ( $scheme === self::SCHEME_PSS ) {
			// PHP 8.1+ with a sufficiently modern OpenSSL may support the PSS algorithm string.
			if ( version_compare( PHP_VERSION, '8.1.0', '>=' ) ) {
				$ok = @openssl_sign( $message, $sig_raw, $pkey, 'sha256WithRSAPSS' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( ! $ok || ! $sig_raw ) {
					// Graceful fall-through to PKCS1v15 on older OpenSSL builds.
					$ok     = openssl_sign( $message, $sig_raw, $pkey, OPENSSL_ALGO_SHA256 );
					$scheme = self::SCHEME_PKCS1;
				}
			} else {
				// PHP < 8.1 cannot produce true RSA-PSS via openssl_sign; use PKCS1v15.
				$ok     = openssl_sign( $message, $sig_raw, $pkey, OPENSSL_ALGO_SHA256 );
				$scheme = self::SCHEME_PKCS1;
			}
		} else {
			// PKCS#1 v1.5 / SHA-256.
			$ok = openssl_sign( $message, $sig_raw, $pkey, OPENSSL_ALGO_SHA256 );
		}

		if ( ! $ok || ! $sig_raw ) {
			return new WP_Error( 'rsa_sign_failed', __( 'OpenSSL RSA signing failed. Check PHP error log for details.', 'archiviomd' ) );
		}

		return array(
			'sig_hex' => bin2hex( $sig_raw ),
			'scheme'  => $scheme,
		);
	}

	// ── Verify ───────────────────────────────────────────────────────────────

	/**
	 * Verify the stored RSA signature for a post.
	 *
	 * @param  int    $post_id
	 * @param  string $type    'post' or 'media'
	 * @return array|WP_Error  Array with 'valid' bool, or WP_Error.
	 */
	public static function verify( int $post_id, string $type = 'post' ) {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'rsa_no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$sig_hex = get_post_meta( $post_id, self::META_SIG, true );
		if ( ! $sig_hex ) {
			return new WP_Error( 'rsa_no_signature', __( 'No RSA signature stored for this post.', 'archiviomd' ) );
		}

		$sig_raw = hex2bin( $sig_hex );
		if ( false === $sig_raw || strlen( $sig_raw ) < 64 ) {
			return new WP_Error( 'rsa_bad_sig_format', __( 'Stored RSA signature has unexpected format.', 'archiviomd' ) );
		}

		// Resolve public key: prefer certificate, fall back to deriving from private key.
		$cert_pem = self::load_certificate_pem();
		if ( $cert_pem ) {
			$pubkey = openssl_pkey_get_public( $cert_pem );
		} else {
			$key_pem = self::load_private_key_pem();
			if ( ! $key_pem ) {
				return new WP_Error( 'rsa_no_pubkey', __( 'No RSA public key or certificate available for verification.', 'archiviomd' ) );
			}
			$pkey    = openssl_pkey_get_private( $key_pem );
			$details = openssl_pkey_get_details( $pkey );
			$pubkey  = openssl_pkey_get_public( $details['key'] );
		}

		if ( ! $pubkey ) {
			return new WP_Error( 'rsa_bad_pubkey', __( 'Failed to load RSA public key.', 'archiviomd' ) );
		}

		$message = ( $type === 'media' )
			? self::canonical_message_media( $post_id )
			: self::canonical_message_post( $post_id );

		$scheme = get_post_meta( $post_id, self::META_SCHEME, true ) ?: self::SCHEME_PKCS1;

		if ( $scheme === self::SCHEME_PSS && version_compare( PHP_VERSION, '8.1.0', '>=' ) ) {
			$result = @openssl_verify( $message, $sig_raw, $pubkey, 'sha256WithRSAPSS' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $result === -1 ) {
				// Retry with PKCS1v15 in case the sig was actually produced that way.
				$result = openssl_verify( $message, $sig_raw, $pubkey, OPENSSL_ALGO_SHA256 );
			}
		} else {
			$result = openssl_verify( $message, $sig_raw, $pubkey, OPENSSL_ALGO_SHA256 );
		}

		return array(
			'valid'     => ( 1 === $result ),
			'post_id'   => $post_id,
			'signed_at' => (int) get_post_meta( $post_id, self::META_SIGNED_AT, true ),
			'scheme'    => $scheme,
			'method'    => 'openssl-rsa',
		);
	}

	// ── Auto-sign hooks ──────────────────────────────────────────────────────

	public function maybe_sign_post( int $post_id, \WP_Post $post ): void {
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( ! self::is_mode_enabled() || ! self::is_openssl_available() || ! self::is_private_key_defined() ) {
			return;
		}
		if ( ! in_array( $post->post_status, array( 'publish', 'private' ), true ) ) {
			return;
		}

		$message = self::canonical_message_post( $post_id );
		$result  = self::sign( $message );

		if ( is_wp_error( $result ) ) {
			return; // Silent fail — do not block the save.
		}

		update_post_meta( $post_id, self::META_SIG,       $result['sig_hex'] );
		update_post_meta( $post_id, self::META_SCHEME,    $result['scheme'] );
		update_post_meta( $post_id, self::META_SIGNED_AT, time() );

		$pubkey_pem = self::get_public_key_pem();
		if ( $pubkey_pem ) {
			update_post_meta( $post_id, self::META_PUBKEY, $pubkey_pem );
		}
	}

	public function maybe_sign_media( int $attachment_id ): void {
		if ( ! self::is_mode_enabled() || ! self::is_openssl_available() || ! self::is_private_key_defined() ) {
			return;
		}

		$message = self::canonical_message_media( $attachment_id );
		$result  = self::sign( $message );

		if ( is_wp_error( $result ) ) {
			return;
		}

		update_post_meta( $attachment_id, self::META_SIG,       $result['sig_hex'] );
		update_post_meta( $attachment_id, self::META_SCHEME,    $result['scheme'] );
		update_post_meta( $attachment_id, self::META_SIGNED_AT, time() );

		$pubkey_pem = self::get_public_key_pem();
		if ( $pubkey_pem ) {
			update_post_meta( $attachment_id, self::META_PUBKEY, $pubkey_pem );
		}
	}

	// ── Public key helpers ────────────────────────────────────────────────────

	/**
	 * Derive PEM-encoded public key from the configured cert or private key.
	 */
	public static function get_public_key_pem(): string {
		if ( ! self::is_openssl_available() ) {
			return '';
		}

		$cert_pem = self::load_certificate_pem();
		if ( $cert_pem ) {
			$cert_res = openssl_x509_read( $cert_pem );
			if ( $cert_res ) {
				$pub     = openssl_pkey_get_public( $cert_res );
				$details = openssl_pkey_get_details( $pub );
				return $details['key'] ?? '';
			}
		}

		$key_pem = self::load_private_key_pem();
		if ( $key_pem ) {
			$pkey    = openssl_pkey_get_private( $key_pem );
			if ( $pkey ) {
				$details = openssl_pkey_get_details( $pkey );
				return $details['key'] ?? '';
			}
		}

		return '';
	}

	// ── Serve public key at well-known endpoint ──────────────────────────────

	public static function serve_public_key(): void {
		$pubkey_pem = self::get_public_key_pem();
		if ( ! $pubkey_pem ) {
			status_header( 404 );
			exit;
		}

		$site   = get_bloginfo( 'url' );
		$name   = get_bloginfo( 'name' );
		$scheme = self::get_scheme();

		$output  = "# RSA public key for {$name}\n";
		$output .= "# Site: {$site}\n";
		$output .= "# Scheme: {$scheme}\n";
		$output .= "# Generated by ArchivioMD\n";
		$output .= "# Verify (PKCS1v15): openssl dgst -sha256 -verify rsa-pubkey.pem -signature sig.bin message.txt\n";
		$output .= "\n";
		$output .= $pubkey_pem;

		header( 'Content-Type: application/x-pem-file; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
		nocache_headers();
		echo $output; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

}
