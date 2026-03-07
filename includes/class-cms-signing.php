<?php
/**
 * CMS / PKCS#7 Detached Signatures — ArchivioMD  ⚠ Enterprise / Compatibility Mode
 *
 * Produces DER-encoded CMS SignedData detached signatures over the canonical
 * post content hash, verifiable with OpenSSL, Adobe Acrobat, Java Bouncy
 * Castle, Windows CertUtil, and regulated-industry audit tooling.
 *
 * Reuses the ECDSA P-256 certificate and key when configured, falling back
 * to the RSA key when present. No new key material is introduced.
 *
 * ── Post meta keys ───────────────────────────────────────────────────────────
 *
 *   _mdsm_cms_sig        Base64-encoded DER CMS SignedData blob
 *   _mdsm_cms_signed_at  Unix timestamp of signing time
 *   _mdsm_cms_key_source 'ecdsa' or 'rsa' — which key produced this signature
 *
 * ── Offline verification ─────────────────────────────────────────────────────
 *
 *   openssl cms -verify -inform DER -in sig.der -content message.txt -noverify
 *   openssl cms -verify -inform DER -in sig.der -content message.txt -CAfile ca-bundle.pem
 *
 * @package ArchivioMD
 * @since   1.16.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_CMS_Signing {

	// ── Post meta keys ───────────────────────────────────────────────────────
	const META_SIG              = '_mdsm_cms_sig';
	const META_SIGNED_AT        = '_mdsm_cms_signed_at';
	const META_KEY_SOURCE       = '_mdsm_cms_key_source';

	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'save_post',      array( $this, 'maybe_sign_post' ),  40, 2 );
		add_action( 'add_attachment', array( $this, 'maybe_sign_media' ), 40    );
	}

	// ── Prerequisite checks ──────────────────────────────────────────────────

	public static function is_openssl_available(): bool {
		return extension_loaded( 'openssl' )
			&& function_exists( 'openssl_pkcs7_sign' )
			&& function_exists( 'openssl_x509_read' )
			&& function_exists( 'openssl_pkey_get_private' );
	}

	public static function is_mode_enabled(): bool {
		return (bool) get_option( 'archiviomd_cms_enabled', false );
	}

	/**
	 * True when at least one compatible key source (ECDSA P-256 or RSA) is
	 * configured and ready to sign.
	 */
	public static function is_key_available(): bool {
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::status()['ready'] ) {
			return true;
		}
		if ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::status()['ready'] ) {
			return true;
		}
		return false;
	}

	/**
	 * Returns which key source would be used: 'ecdsa', 'rsa', or null.
	 */
	public static function get_key_source(): ?string {
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::status()['ready'] ) {
			return 'ecdsa';
		}
		if ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::status()['ready'] ) {
			return 'rsa';
		}
		return null;
	}

	// ── Status ───────────────────────────────────────────────────────────────

	public static function status(): array {
		$mode_enabled      = self::is_mode_enabled();
		$openssl_available = self::is_openssl_available();
		$key_available     = self::is_key_available();
		$key_source        = self::get_key_source();
		$ready             = $mode_enabled && $openssl_available && $key_available;

		$notice_level   = 'ok';
		$notice_message = __( 'CMS/PKCS#7 signing is active and operational.', 'archiviomd' );

		if ( $mode_enabled ) {
			if ( ! $openssl_available ) {
				$notice_level   = 'error';
				$notice_message = __( 'ext-openssl is not available — required for CMS/PKCS#7 signing. Contact your host.', 'archiviomd' );
			} elseif ( ! $key_available ) {
				$notice_level   = 'error';
				$notice_message = __( 'CMS/PKCS#7 mode is enabled but no compatible key is configured. Configure either ECDSA P-256 or RSA signing in the Extended settings.', 'archiviomd' );
			}
		}

		return array(
			'mode_enabled'      => $mode_enabled,
			'openssl_available' => $openssl_available,
			'key_available'     => $key_available,
			'key_source'        => $key_source,
			'ready'             => $ready,
			'notice_level'      => $notice_level,
			'notice_message'    => $notice_message,
		);
	}

	// ── Canonical message builders ────────────────────────────────────────────

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
	 * Produce a CMS SignedData detached signature over $message.
	 *
	 * Uses openssl_pkcs7_sign() to produce an S/MIME message, then strips
	 * the S/MIME headers and base64-decodes the payload to get raw DER bytes
	 * which are re-encoded as base64 for storage.
	 *
	 * @param  string $message Canonical message to sign.
	 * @return string|WP_Error Base64-encoded DER CMS SignedData blob, or WP_Error.
	 */
	public static function sign( string $message ) {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'cms_no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$key_source = self::get_key_source();
		if ( null === $key_source ) {
			return new WP_Error( 'cms_no_key', __( 'No compatible key source available for CMS signing.', 'archiviomd' ) );
		}

		// ── Resolve cert + private key PEM strings ────────────────────────
		if ( 'ecdsa' === $key_source && class_exists( 'MDSM_ECDSA_Signing' ) ) {
			$cert_pem = MDSM_ECDSA_Signing::load_certificate_pem();
			// Access private key through the ECDSA class (it's private, so we
			// call the public sign path — but for CMS we need raw PEM access).
			// As a workaround we re-check the ECDSA constant/option here.
			$key_pem  = self::resolve_ecdsa_private_key_pem();
		} else {
			// RSA path.
			$cert_pem = class_exists( 'MDSM_RSA_Signing' ) ? MDSM_RSA_Signing::load_certificate_pem() : '';
			$key_pem  = self::resolve_rsa_private_key_pem();
		}

		if ( ! $key_pem ) {
			return new WP_Error( 'cms_no_privkey', __( 'Private key PEM could not be loaded for CMS signing.', 'archiviomd' ) );
		}

		// If no cert, build a self-signed cert wrapper so openssl_pkcs7_sign has something to attach.
		if ( ! $cert_pem ) {
			$self_signed = self::generate_self_signed_cert( $key_pem );
			if ( is_wp_error( $self_signed ) ) {
				return $self_signed;
			}
			$cert_pem = $self_signed;
		}

		// ── Write message to a temp file ──────────────────────────────────
		$tmp_in  = wp_tempnam( 'cms_in_' );
		$tmp_out = wp_tempnam( 'cms_out_' );

		if ( false === file_put_contents( $tmp_in, $message ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return new WP_Error( 'cms_tmp_write', __( 'Failed to write temporary file for CMS signing.', 'archiviomd' ) );
		}

		// ── Sign via openssl_pkcs7_sign ────────────────────────────────────
		// Flags: PKCS7_DETACHED = detached sig, PKCS7_BINARY = treat input as binary.
		$ok = openssl_pkcs7_sign(
			$tmp_in,
			$tmp_out,
			$cert_pem,
			$key_pem,
			array(), // extra headers
			PKCS7_DETACHED | PKCS7_BINARY
		);

		@unlink( $tmp_in ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		if ( ! $ok ) {
			@unlink( $tmp_out ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new WP_Error( 'cms_sign_failed', __( 'openssl_pkcs7_sign() failed. Check PHP error log for OpenSSL details.', 'archiviomd' ) );
		}

		$smime = file_get_contents( $tmp_out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		@unlink( $tmp_out ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		if ( ! $smime ) {
			return new WP_Error( 'cms_empty_output', __( 'CMS signing produced empty output.', 'archiviomd' ) );
		}

		// ── Extract DER from S/MIME output ────────────────────────────────
		// openssl_pkcs7_sign produces S/MIME with headers + base64 body.
		// Strip everything up to the first blank line, collect base64 payload.
		$der_b64 = self::extract_der_from_smime( $smime );
		if ( ! $der_b64 ) {
			return new WP_Error( 'cms_parse_failed', __( 'Failed to extract DER blob from S/MIME output.', 'archiviomd' ) );
		}

		return $der_b64;
	}

	/**
	 * Extract the base64-encoded DER payload from an S/MIME string.
	 *
	 * S/MIME format:
	 *   MIME-Version: 1.0\r\n
	 *   Content-Type: ...\r\n
	 *   \r\n
	 *   <base64 data>
	 */
	private static function extract_der_from_smime( string $smime ): string {
		// Find the blank line separating headers from body.
		$sep = strpos( $smime, "\r\n\r\n" );
		if ( false === $sep ) {
			$sep = strpos( $smime, "\n\n" );
		}
		if ( false === $sep ) {
			return '';
		}
		$body = substr( $smime, $sep );
		$body = ltrim( $body, "\r\n" );

		// Strip any trailing MIME boundary or whitespace.
		$body = preg_replace( '/\s+$/', '', $body );

		// The body may be multi-part; we want the first base64 block.
		// Find the first line that looks like a MIME boundary and truncate.
		$lines = explode( "\n", $body );
		$b64_lines = array();
		foreach ( $lines as $line ) {
			$line = rtrim( $line, "\r" );
			if ( str_starts_with( $line, '--' ) ) {
				break;
			}
			$b64_lines[] = $line;
		}

		$b64 = implode( '', $b64_lines );
		$b64 = preg_replace( '/\s+/', '', $b64 );

		// Validate it's actually base64.
		if ( ! preg_match( '/^[A-Za-z0-9+\/]+=*$/', $b64 ) || strlen( $b64 ) < 32 ) {
			return '';
		}

		return $b64;
	}

	/**
	 * Generate a transient self-signed certificate wrapping a given private key PEM.
	 * Used only when a full X.509 cert is not configured.
	 *
	 * @return string|WP_Error PEM certificate string, or WP_Error.
	 */
	private static function generate_self_signed_cert( string $key_pem ) {
		$pkey = openssl_pkey_get_private( $key_pem );
		if ( ! $pkey ) {
			return new WP_Error( 'cms_bad_key', __( 'Cannot load private key for self-signed cert generation.', 'archiviomd' ) );
		}

		$dn = array(
			'commonName'   => wp_parse_url( get_site_url(), PHP_URL_HOST ),
			'organization' => get_bloginfo( 'name' ),
		);

		$cert = openssl_csr_sign(
			openssl_csr_new( $dn, $pkey ),
			null,   // self-signed
			$pkey,
			365,    // 1-year validity
			array( 'digest_alg' => 'sha256' )
		);

		if ( ! $cert ) {
			return new WP_Error( 'cms_cert_gen_failed', __( 'Failed to generate self-signed certificate for CMS signing.', 'archiviomd' ) );
		}

		openssl_x509_export( $cert, $cert_pem );
		return $cert_pem;
	}

	/**
	 * Attempt to load ECDSA private key PEM by mirroring ECDSA class's priority order.
	 */
	private static function resolve_ecdsa_private_key_pem(): string {
		$const = 'ARCHIVIOMD_ECDSA_PRIVATE_KEY_PEM';
		if ( defined( $const ) ) {
			$pem = constant( $const );
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}
		$path = get_option( 'archiviomd_ecdsa_key_path', '' );
		if ( $path && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}
		return '';
	}

	/**
	 * Attempt to load RSA private key PEM via the RSA class or direct constant.
	 */
	private static function resolve_rsa_private_key_pem(): string {
		$const = 'ARCHIVIOMD_RSA_PRIVATE_KEY_PEM';
		if ( defined( $const ) ) {
			$pem = constant( $const );
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}
		$path = get_option( 'archiviomd_rsa_key_path', '' );
		if ( $path && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}
		return '';
	}

	// ── Verify ───────────────────────────────────────────────────────────────

	/**
	 * Verify the stored CMS signature for a post.
	 *
	 * @param  int    $post_id
	 * @param  string $type    'post' or 'media'
	 * @return array|WP_Error  Array with 'valid' bool, or WP_Error.
	 */
	public static function verify( int $post_id, string $type = 'post' ) {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'cms_no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$sig_b64 = get_post_meta( $post_id, self::META_SIG, true );
		if ( ! $sig_b64 ) {
			return new WP_Error( 'cms_no_signature', __( 'No CMS/PKCS#7 signature stored for this post.', 'archiviomd' ) );
		}

		$der = base64_decode( $sig_b64, true );
		if ( false === $der || strlen( $der ) < 16 ) {
			return new WP_Error( 'cms_bad_sig_format', __( 'Stored CMS signature has unexpected format.', 'archiviomd' ) );
		}

		$key_source = get_post_meta( $post_id, self::META_KEY_SOURCE, true ) ?: self::get_key_source();

		$message = ( $type === 'media' )
			? self::canonical_message_media( $post_id )
			: self::canonical_message_post( $post_id );

		// Reconstruct S/MIME wrapper so openssl_pkcs7_verify can process it.
		$smime = self::wrap_der_as_smime( $der );

		$tmp_smime   = wp_tempnam( 'cms_verify_sig_' );
		$tmp_content = wp_tempnam( 'cms_verify_msg_' );
		$tmp_out     = wp_tempnam( 'cms_verify_out_' );
		$tmp_cert    = wp_tempnam( 'cms_verify_cert_' );

		file_put_contents( $tmp_smime,   $smime );   // phpcs:ignore WordPress.WP.AlternativeFunctions
		file_put_contents( $tmp_content, $message ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		// Use PKCS7_NOVERIFY to skip chain verification (self-signed certs are fine here).
		$valid = openssl_pkcs7_verify(
			$tmp_smime,
			PKCS7_NOVERIFY | PKCS7_BINARY,
			$tmp_cert,    // extracted signers
			array(),      // CA bundle (not required with PKCS7_NOVERIFY)
			null,         // extra certs
			$tmp_out,     // decrypted content output (unused for detached)
			$tmp_content  // detached content file
		);

		foreach ( array( $tmp_smime, $tmp_content, $tmp_out, $tmp_cert ) as $f ) {
			@unlink( $f ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		return array(
			'valid'      => ( true === $valid ),
			'post_id'    => $post_id,
			'signed_at'  => (int) get_post_meta( $post_id, self::META_SIGNED_AT, true ),
			'key_source' => $key_source,
			'method'     => 'openssl-cms-pkcs7',
		);
	}

	/**
	 * Wrap raw DER bytes back into an S/MIME string for openssl_pkcs7_verify.
	 */
	private static function wrap_der_as_smime( string $der ): string {
		$b64  = chunk_split( base64_encode( $der ), 76, "\r\n" );
		return "MIME-Version: 1.0\r\n"
			. "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\r\n"
			. "Content-Transfer-Encoding: base64\r\n"
			. "\r\n"
			. $b64;
	}

	// ── Auto-sign hooks ──────────────────────────────────────────────────────

	public function maybe_sign_post( int $post_id, \WP_Post $post ): void {
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( ! self::is_mode_enabled() || ! self::is_openssl_available() || ! self::is_key_available() ) {
			return;
		}
		if ( ! in_array( $post->post_status, array( 'publish', 'private' ), true ) ) {
			return;
		}

		$message    = self::canonical_message_post( $post_id );
		$der_b64    = self::sign( $message );
		$key_source = self::get_key_source();

		if ( is_wp_error( $der_b64 ) ) {
			return;
		}

		update_post_meta( $post_id, self::META_SIG,        $der_b64 );
		update_post_meta( $post_id, self::META_KEY_SOURCE, $key_source );
		update_post_meta( $post_id, self::META_SIGNED_AT,  time() );
	}

	public function maybe_sign_media( int $attachment_id ): void {
		if ( ! self::is_mode_enabled() || ! self::is_openssl_available() || ! self::is_key_available() ) {
			return;
		}

		$message    = self::canonical_message_media( $attachment_id );
		$der_b64    = self::sign( $message );
		$key_source = self::get_key_source();

		if ( is_wp_error( $der_b64 ) ) {
			return;
		}

		update_post_meta( $attachment_id, self::META_SIG,        $der_b64 );
		update_post_meta( $attachment_id, self::META_KEY_SOURCE, $key_source );
		update_post_meta( $attachment_id, self::META_SIGNED_AT,  time() );
	}

}
