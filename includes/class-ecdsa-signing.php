<?php
/**
 * ECDSA P-256 Document Signing — ArchivioMD  ⚠ Enterprise / Compliance Mode
 *
 * ── Why this exists ──────────────────────────────────────────────────────────
 *
 * Certain regulated environments (eIDAS, SOC 2, HIPAA audit chains) require
 * X.509-backed signatures from a CA-issued certificate rather than a bare
 * public key.  ECDSA P-256 (secp256r1) with SHA-256 is the dominant curve in
 * that world and is mandated by many government PKI frameworks.
 *
 * This is NOT a general-purpose signing mode. For most sites, Ed25519 (via
 * php-sodium) is simpler, faster, and equally secure. Use ECDSA only when an
 * external compliance requirement explicitly demands X.509 certificate chains.
 *
 * ── Security architecture — NEVER roll your own ──────────────────────────────
 *
 * ECDSA security collapses completely if:
 *   1. The per-signature nonce (k) is ever reused — even once leaks the private key.
 *   2. The nonce has any statistical bias — partial bias also leaks the private key.
 *
 * This implementation delegates 100% of nonce generation to OpenSSL (libssl).
 * PHP's openssl_sign() with OPENSSL_ALGO_SHA256 calls EVP_DigestSign internally,
 * which sources nonces from the OS CSPRNG (getrandom(2) / CryptGenRandom).
 * We never touch nonce generation, never implement signing math, never use
 * raw bcmath / GMP for EC operations. If ext-openssl is absent we hard-fail.
 *
 * ── Key & certificate storage ────────────────────────────────────────────────
 *
 * Two storage paths are supported (priority order):
 *
 *   A) wp-config.php constants (preferred for automation / CI):
 *        define( 'ARCHIVIOMD_ECDSA_PRIVATE_KEY_PEM', '-----BEGIN EC PRIVATE KEY-----\n...' );
 *        define( 'ARCHIVIOMD_ECDSA_CERTIFICATE_PEM', '-----BEGIN CERTIFICATE-----\n...'  );
 *        define( 'ARCHIVIOMD_ECDSA_CA_BUNDLE_PEM',   '-----BEGIN CERTIFICATE-----\n...'  ); // optional chain
 *
 *   B) PEM files uploaded via the admin UI and stored outside webroot:
 *        Path written to wp_option 'archiviomd_ecdsa_key_path'
 *        Path written to wp_option 'archiviomd_ecdsa_cert_path'
 *        Path written to wp_option 'archiviomd_ecdsa_ca_path'   (optional)
 *
 * The private key is NEVER stored in the database. Only the filesystem path or
 * the wp-config constant is recorded. If a path is used the file must be:
 *   - Outside DOCUMENT_ROOT (enforced on save)
 *   - Readable by the web-server user
 *   - Not world-readable (mode checked on load; warning emitted if ≥ 0o004)
 *
 * ── Certificate validation ───────────────────────────────────────────────────
 *
 * On every signing operation:
 *   1. Certificate is parsed with openssl_x509_parse().
 *   2. Certificate validity window (notBefore / notAfter) is checked.
 *   3. If a CA bundle is configured, openssl_x509_checkpurpose() verifies the
 *      chain.  We do NOT skip CA validation silently — if a bundle is provided
 *      and the chain fails, signing is refused.
 *   4. The leaf certificate's public key is confirmed to be EC / secp256r1.
 *   5. The private key is confirmed to correspond to the certificate's public key.
 *
 * ── Output format ────────────────────────────────────────────────────────────
 *
 * Bare signature (DER, then hex-encoded) stored in:
 *   _mdsm_ecdsa_sig        — hex of DER-encoded ECDSA signature (variable length, ~70–72 bytes → 140–144 hex chars)
 *   _mdsm_ecdsa_cert       — PEM of the leaf certificate (public, safe to store)
 *   _mdsm_ecdsa_signed_at  — Unix timestamp
 *
 * DSSE envelope (when DSSE mode enabled) stored in:
 *   _mdsm_ecdsa_dsse       — JSON DSSE envelope; sig field is base64(DER bytes)
 *
 * ── Signing message format ───────────────────────────────────────────────────
 *
 * Identical canonical format as Ed25519 / SLH-DSA (all algorithms sign the same bytes):
 *   Posts/pages:
 *     mdsm-ed25519-v1\n{post_id}\n{post_title}\n{post_slug}\n{content}\n{date_gmt}
 *   Media:
 *     mdsm-ed25519-media-v1\n{id}\n{filename}\n{filesize}\n{mime}\n{author}\n{date_gmt}
 *
 * ── Well-known endpoint ──────────────────────────────────────────────────────
 *
 *   /.well-known/ecdsa-cert.pem — leaf certificate (PEM), plain text
 *
 * @package ArchivioMD
 * @since   1.15.0
 *
 * ⚠  ENTERPRISE / COMPLIANCE MODE — Not recommended for general use.
 *    Requires a CA-issued X.509 certificate. See documentation.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_ECDSA_Signing {

	// ── wp-config constants ────────────────────────────────────────────────
	const CONSTANT_PRIVATE_KEY  = 'ARCHIVIOMD_ECDSA_PRIVATE_KEY_PEM';
	const CONSTANT_CERTIFICATE  = 'ARCHIVIOMD_ECDSA_CERTIFICATE_PEM';
	const CONSTANT_CA_BUNDLE    = 'ARCHIVIOMD_ECDSA_CA_BUNDLE_PEM';

	// ── wp_options ────────────────────────────────────────────────────────
	const OPTION_MODE_ENABLED   = 'archiviomd_ecdsa_enabled';
	const OPTION_DSSE_ENABLED   = 'archiviomd_ecdsa_dsse_enabled';
	const OPTION_POST_TYPES     = 'archiviomd_ecdsa_post_types';
	const OPTION_KEY_PATH       = 'archiviomd_ecdsa_key_path';
	const OPTION_CERT_PATH      = 'archiviomd_ecdsa_cert_path';
	const OPTION_CA_PATH        = 'archiviomd_ecdsa_ca_path';

	// ── Post meta keys ────────────────────────────────────────────────────
	const META_SIG              = '_mdsm_ecdsa_sig';
	const META_CERT             = '_mdsm_ecdsa_cert';
	const META_SIGNED_AT        = '_mdsm_ecdsa_signed_at';
	const META_DSSE             = '_mdsm_ecdsa_dsse';

	// ── Well-known slug ───────────────────────────────────────────────────
	const WELL_KNOWN_SLUG       = 'ecdsa-cert.pem';

	// ── DSSE payload type ────────────────────────────────────────────────
	const DSSE_PAYLOAD_TYPE_POST  = 'application/vnd.archiviomd.document';
	const DSSE_PAYLOAD_TYPE_MEDIA = 'application/vnd.archiviomd.media';

	// ── Expected EC curve OID ─────────────────────────────────────────────
	// PHP openssl_pkey_get_details() returns curve_name for EC keys.
	const REQUIRED_CURVE = 'prime256v1'; // secp256r1 / P-256

	private static $instance = null;

	// ─────────────────────────────────────────────────────────────────────
	// Singleton
	// ─────────────────────────────────────────────────────────────────────

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'save_post',      array( $this, 'maybe_sign_post' ),  30, 2 );
		add_action( 'add_attachment', array( $this, 'maybe_sign_media' ),  30    );

		add_action( 'wp_ajax_archivio_ecdsa_save_settings',   array( $this, 'ajax_save_settings'   ) );
		add_action( 'wp_ajax_archivio_ecdsa_upload_key',      array( $this, 'ajax_upload_key'      ) );
		add_action( 'wp_ajax_archivio_ecdsa_upload_cert',     array( $this, 'ajax_upload_cert'     ) );
		add_action( 'wp_ajax_archivio_ecdsa_upload_ca',       array( $this, 'ajax_upload_ca'       ) );
		add_action( 'wp_ajax_archivio_ecdsa_clear_key',       array( $this, 'ajax_clear_key'       ) );
		add_action( 'wp_ajax_archivio_ecdsa_clear_cert',      array( $this, 'ajax_clear_cert'      ) );
		add_action( 'wp_ajax_archivio_ecdsa_clear_ca',        array( $this, 'ajax_clear_ca'        ) );
	}

	// ─────────────────────────────────────────────────────────────────────
	// Environment checks
	// ─────────────────────────────────────────────────────────────────────

	public static function is_openssl_available(): bool {
		return extension_loaded( 'openssl' )
			&& function_exists( 'openssl_sign' )
			&& function_exists( 'openssl_x509_parse' )
			&& function_exists( 'openssl_pkey_get_details' );
	}

	public static function is_mode_enabled(): bool {
		return (bool) get_option( self::OPTION_MODE_ENABLED, false );
	}

	public static function set_mode( bool $enabled ): void {
		update_option( self::OPTION_MODE_ENABLED, $enabled );
		self::clear_status_cache();
	}

	public static function is_dsse_enabled(): bool {
		return (bool) get_option( self::OPTION_DSSE_ENABLED, false );
	}

	public static function set_dsse_mode( bool $enabled ): void {
		update_option( self::OPTION_DSSE_ENABLED, $enabled );
		self::clear_status_cache();
	}

	public static function get_configured_post_types(): array {
		$saved = get_option( self::OPTION_POST_TYPES, '' );
		if ( $saved ) {
			$types = array_filter( array_map( 'sanitize_key', explode( ',', $saved ) ) );
			if ( ! empty( $types ) ) {
				return array_values( $types );
			}
		}
		return array( 'post', 'page' );
	}

	// ─────────────────────────────────────────────────────────────────────
	// PEM retrieval — constants take priority over filesystem paths
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Load the private key PEM string.
	 * Returns the raw PEM string, or empty string if not configured.
	 * NEVER logs or stores the returned value.
	 */
	private static function load_private_key_pem(): string {
		// Priority 1: wp-config constant.
		if ( defined( self::CONSTANT_PRIVATE_KEY ) ) {
			$pem = constant( self::CONSTANT_PRIVATE_KEY );
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}

		// Priority 2: filesystem path stored in options.
		$path = get_option( self::OPTION_KEY_PATH, '' );
		if ( $path && self::is_safe_pem_path( $path ) && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'PRIVATE KEY' ) ) {
				return $pem;
			}
		}

		return '';
	}

	/**
	 * Load the certificate PEM string (leaf cert; public data).
	 */
	public static function load_certificate_pem(): string {
		// Priority 1: wp-config constant.
		if ( defined( self::CONSTANT_CERTIFICATE ) ) {
			$pem = constant( self::CONSTANT_CERTIFICATE );
			if ( is_string( $pem ) && str_contains( $pem, 'CERTIFICATE' ) ) {
				return $pem;
			}
		}

		// Priority 2: filesystem path.
		$path = get_option( self::OPTION_CERT_PATH, '' );
		if ( $path && self::is_safe_pem_path( $path ) && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'CERTIFICATE' ) ) {
				return $pem;
			}
		}

		return '';
	}

	/**
	 * Load the CA bundle PEM string (optional; may contain chain certs).
	 */
	private static function load_ca_bundle_pem(): string {
		// Priority 1: wp-config constant.
		if ( defined( self::CONSTANT_CA_BUNDLE ) ) {
			$pem = constant( self::CONSTANT_CA_BUNDLE );
			if ( is_string( $pem ) && str_contains( $pem, 'CERTIFICATE' ) ) {
				return $pem;
			}
		}

		// Priority 2: filesystem path.
		$path = get_option( self::OPTION_CA_PATH, '' );
		if ( $path && self::is_safe_pem_path( $path ) && is_readable( $path ) ) {
			$pem = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_string( $pem ) && str_contains( $pem, 'CERTIFICATE' ) ) {
				return $pem;
			}
		}

		return '';
	}

	// ─────────────────────────────────────────────────────────────────────
	// Path safety enforcement
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Ensure a PEM file path is:
	 *  - An absolute path
	 *  - Outside DOCUMENT_ROOT / webroot
	 *  - Has a .pem extension
	 *  - Does not contain path-traversal sequences
	 *
	 * @param string $path
	 * @return bool
	 */
	public static function is_safe_pem_path( string $path ): bool {
		if ( empty( $path ) ) {
			return false;
		}

		// Must be absolute.
		if ( substr( $path, 0, 1 ) !== '/' ) {
			return false;
		}

		// No path traversal.
		if ( str_contains( $path, '..' ) ) {
			return false;
		}

		// Must end in .pem.
		if ( strtolower( substr( $path, -4 ) ) !== '.pem' ) {
			return false;
		}

		// Must be outside webroot.
		$webroot = rtrim( $_SERVER['DOCUMENT_ROOT'] ?? ABSPATH, '/' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( $webroot && str_starts_with( realpath( dirname( $path ) ) ?: $path, $webroot ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Emit a notice if a key file has world-readable permissions.
	 */
	private static function warn_if_world_readable( string $path ): void {
		if ( ! $path || ! file_exists( $path ) ) {
			return;
		}
		$perms = fileperms( $path );
		if ( $perms !== false && ( $perms & 0o004 ) ) {
			// translators: %s: file path
			trigger_error( sprintf( 'ArchivioMD ECDSA: private key file %s is world-readable. Set permissions to 0600.', esc_html( $path ) ), E_USER_WARNING );
		}
	}

	// ─────────────────────────────────────────────────────────────────────
	// Certificate validation helpers
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Parse and validate the configured certificate. Returns the parsed
	 * openssl_x509_parse() array on success, or WP_Error on failure.
	 *
	 * Checks:
	 *   - Certificate can be parsed
	 *   - notBefore / notAfter validity window
	 *   - Public key is EC / prime256v1
	 *   - Private key matches certificate public key
	 *   - CA chain (if bundle configured)
	 *
	 * @return array|WP_Error
	 */
	public static function validate_certificate() {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$cert_pem = self::load_certificate_pem();
		if ( ! $cert_pem ) {
			return new WP_Error( 'no_cert', __( 'No certificate configured. Upload a PEM certificate or set ARCHIVIOMD_ECDSA_CERTIFICATE_PEM in wp-config.php.', 'archiviomd' ) );
		}

		// Parse certificate.
		$parsed = openssl_x509_parse( $cert_pem );
		if ( ! $parsed ) {
			return new WP_Error( 'bad_cert_parse', __( 'Certificate could not be parsed. Ensure it is a valid PEM-encoded X.509 certificate.', 'archiviomd' ) );
		}

		// Validity window.
		$now = time();
		if ( isset( $parsed['validFrom_time_t'] ) && $now < $parsed['validFrom_time_t'] ) {
			return new WP_Error( 'cert_not_yet_valid', __( 'Certificate is not yet valid (notBefore is in the future).', 'archiviomd' ) );
		}
		if ( isset( $parsed['validTo_time_t'] ) && $now > $parsed['validTo_time_t'] ) {
			return new WP_Error( 'cert_expired', sprintf(
				/* translators: %s: expiry date */
				__( 'Certificate expired on %s.', 'archiviomd' ),
				gmdate( 'Y-m-d H:i:s T', $parsed['validTo_time_t'] )
			) );
		}

		// Extract public key and confirm it is EC / P-256.
		$cert_res = openssl_x509_read( $cert_pem );
		if ( ! $cert_res ) {
			return new WP_Error( 'bad_cert_read', __( 'Certificate could not be read by OpenSSL.', 'archiviomd' ) );
		}

		$pubkey_res = openssl_pkey_get_public( $cert_res );
		if ( ! $pubkey_res ) {
			return new WP_Error( 'bad_cert_pubkey', __( 'Could not extract public key from certificate.', 'archiviomd' ) );
		}

		$key_details = openssl_pkey_get_details( $pubkey_res );
		if ( ! $key_details ) {
			return new WP_Error( 'bad_key_details', __( 'Could not read public key details from certificate.', 'archiviomd' ) );
		}

		// Must be EC type (OPENSSL_KEYTYPE_EC = 3).
		if ( ( $key_details['type'] ?? -1 ) !== OPENSSL_KEYTYPE_EC ) {
			return new WP_Error( 'not_ec_key', __( 'Certificate does not contain an EC public key. ECDSA mode requires an EC P-256 certificate.', 'archiviomd' ) );
		}

		// Must be P-256 (prime256v1 / secp256r1).
		$curve = $key_details['ec']['curve_name'] ?? '';
		if ( $curve !== self::REQUIRED_CURVE ) {
			return new WP_Error( 'wrong_curve', sprintf(
				/* translators: 1: found curve name, 2: required curve name */
				__( 'Certificate uses curve "%1$s". ECDSA mode requires "%2$s" (P-256 / secp256r1).', 'archiviomd' ),
				$curve,
				self::REQUIRED_CURVE
			) );
		}

		// Confirm private key matches certificate (if private key is configured).
		$key_pem = self::load_private_key_pem();
		if ( $key_pem ) {
			if ( ! openssl_x509_check_private_key( $cert_res, $key_pem ) ) {
				return new WP_Error( 'key_cert_mismatch', __( 'Private key does not match the configured certificate. Ensure both files come from the same keypair.', 'archiviomd' ) );
			}
		}

		// CA chain validation (only when a bundle is provided).
		$ca_pem = self::load_ca_bundle_pem();
		if ( $ca_pem ) {
			// Write CA bundle to a temp file — openssl_x509_checkpurpose requires a path.
			$tmp = wp_tempnam( 'mdsm_ca_' );
			file_put_contents( $tmp, $ca_pem ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$purpose_ok = openssl_x509_checkpurpose( $cert_res, X509_PURPOSE_ANY, array( $tmp ) );
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

			if ( $purpose_ok === false ) {
				return new WP_Error( 'chain_invalid', __( 'Certificate chain validation failed. Verify that the CA bundle contains the correct intermediate and root certificates.', 'archiviomd' ) );
			}
		}

		return $parsed;
	}

	/**
	 * Return a human-readable certificate summary for the admin UI.
	 * Never includes private key material.
	 *
	 * @return array|WP_Error
	 */
	public static function certificate_info() {
		$parsed = self::validate_certificate();
		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		$cert_pem = self::load_certificate_pem();
		$cert_res = openssl_x509_read( $cert_pem );
		$pubkey   = openssl_pkey_get_public( $cert_res );
		$details  = openssl_pkey_get_details( $pubkey );

		// Build fingerprint (SHA-256 of DER representation).
		$der         = '';
		openssl_x509_export( $cert_res, $pem_out );
		// Extract DER from PEM for fingerprint.
		$b64 = preg_replace( '/-----[^-]+-----|\s/', '', $pem_out );
		$der = base64_decode( $b64 ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		$fingerprint = strtoupper( implode( ':', str_split( hash( 'sha256', $der ), 2 ) ) );

		$now     = time();
		$expires = $parsed['validTo_time_t'] ?? 0;
		$days_left = $expires ? (int) round( ( $expires - $now ) / DAY_IN_SECONDS ) : null;

		return array(
			'subject'      => $parsed['subject']  ?? array(),
			'issuer'       => $parsed['issuer']   ?? array(),
			'serial'       => $parsed['serialNumberHex'] ?? ( $parsed['serialNumber'] ?? '' ),
			'not_before'   => isset( $parsed['validFrom_time_t'] ) ? gmdate( 'Y-m-d H:i:s T', $parsed['validFrom_time_t'] ) : '',
			'not_after'    => isset( $parsed['validTo_time_t']   ) ? gmdate( 'Y-m-d H:i:s T', $parsed['validTo_time_t']   ) : '',
			'days_left'    => $days_left,
			'expired'      => ( $expires && $now > $expires ),
			'curve'        => $details['ec']['curve_name'] ?? '',
			'fingerprint'  => $fingerprint,
			'has_ca_bundle'=> (bool) self::load_ca_bundle_pem(),
		);
	}

	// ─────────────────────────────────────────────────────────────────────
	// Status (mirrors Ed25519::status() shape exactly)
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * @return array{
	 *   mode_enabled: bool,
	 *   openssl_available: bool,
	 *   private_key_configured: bool,
	 *   certificate_configured: bool,
	 *   certificate_valid: bool,
	 *   ca_bundle_configured: bool,
	 *   ready: bool,
	 *   dsse_enabled: bool,
	 *   notice_level: string,
	 *   notice_message: string,
	 *   cert_info: array|null
	 * }
	 */
	/** @var array|null Per-request status cache — flushed on option changes via clear_status_cache(). */
	private static $status_cache = null;

	/** Flush the cached status (called after saving key/cert options so the UI shows live state). */
	public static function clear_status_cache(): void {
		self::$status_cache = null;
	}

	public static function status(): array {
		if ( null !== self::$status_cache ) {
			return self::$status_cache;
		}

		$mode_enabled            = self::is_mode_enabled();
		$openssl_available       = self::is_openssl_available();
		$private_key_configured  = (bool) self::load_private_key_pem();
		$certificate_configured  = (bool) self::load_certificate_pem();
		$ca_bundle_configured    = (bool) self::load_ca_bundle_pem();
		$certificate_valid       = false;
		$cert_info               = null;

		$notice_level   = 'ok';
		$notice_message = '';

		if ( $mode_enabled ) {
			if ( ! $openssl_available ) {
				$notice_level   = 'error';
				$notice_message = __( 'PHP ext-openssl is not available on this server. ECDSA signing cannot function without it.', 'archiviomd' );
			} elseif ( ! $private_key_configured ) {
				$notice_level   = 'error';
				$notice_message = __( 'ECDSA mode is enabled but no private key is configured. Upload a PEM key or set ARCHIVIOMD_ECDSA_PRIVATE_KEY_PEM in wp-config.php.', 'archiviomd' );
			} elseif ( ! $certificate_configured ) {
				$notice_level   = 'error';
				$notice_message = __( 'ECDSA mode is enabled but no certificate is configured. Upload a PEM certificate or set ARCHIVIOMD_ECDSA_CERTIFICATE_PEM in wp-config.php.', 'archiviomd' );
			} else {
				$validation = self::validate_certificate();
				if ( is_wp_error( $validation ) ) {
					$notice_level   = 'error';
					$notice_message = $validation->get_error_message();
				} else {
					$certificate_valid = true;
					$cert_info         = self::certificate_info();
					if ( is_wp_error( $cert_info ) ) {
						$cert_info = null;
					}

					// Warn if certificate is expiring soon (< 30 days).
					if ( $cert_info && isset( $cert_info['days_left'] ) && $cert_info['days_left'] <= 30 ) {
						$notice_level   = 'warning';
						$notice_message = sprintf(
							/* translators: %d: days until expiry */
							_n(
								'⚠ ECDSA certificate expires in %d day. Renew it before expiry to avoid signing failures.',
								'⚠ ECDSA certificate expires in %d days. Renew it before expiry to avoid signing failures.',
								$cert_info['days_left'],
								'archiviomd'
							),
							$cert_info['days_left']
						);
					} else {
						$notice_message = __( 'ECDSA Enterprise Signing is active. Documents are signed with your X.509 certificate on save.', 'archiviomd' );
					}
				}
			}
		}

		$ready = $mode_enabled && $openssl_available && $private_key_configured && $certificate_configured && $certificate_valid;

		self::$status_cache = array(
			'mode_enabled'           => $mode_enabled,
			'openssl_available'      => $openssl_available,
			'private_key_configured' => $private_key_configured,
			'certificate_configured' => $certificate_configured,
			'certificate_valid'      => $certificate_valid,
			'ca_bundle_configured'   => $ca_bundle_configured,
			'ready'                  => $ready,
			'dsse_enabled'           => self::is_dsse_enabled(),
			'notice_level'           => $notice_level,
			'notice_message'         => $notice_message,
			'cert_info'              => $cert_info,
		);
		return self::$status_cache;
	}

	// ─────────────────────────────────────────────────────────────────────
	// Canonical message builders (shared format with Ed25519 / SLH-DSA)
	// ─────────────────────────────────────────────────────────────────────

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

	// ─────────────────────────────────────────────────────────────────────
	// Core sign — 100% delegated to OpenSSL, zero manual nonce handling
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Sign a message using ECDSA P-256 via OpenSSL.
	 *
	 * openssl_sign() with OPENSSL_ALGO_SHA256 internally calls EVP_DigestSign,
	 * which generates the per-signature nonce via the OS CSPRNG.  We never
	 * touch nonce generation.  The output is a DER-encoded ECDSA signature.
	 *
	 * @param  string $message  Raw canonical message bytes.
	 * @return string|WP_Error  Hex-encoded DER signature, or WP_Error on failure.
	 */
	public static function sign( string $message ) {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$key_pem = self::load_private_key_pem();
		if ( ! $key_pem ) {
			return new WP_Error( 'no_key', __( 'No ECDSA private key configured.', 'archiviomd' ) );
		}

		// Validate certificate before signing — refuse if cert is invalid/expired.
		$cert_check = self::validate_certificate();
		if ( is_wp_error( $cert_check ) ) {
			return $cert_check;
		}

		$pkey = openssl_pkey_get_private( $key_pem );
		if ( ! $pkey ) {
			return new WP_Error( 'bad_privkey', __( 'Private key could not be loaded by OpenSSL. Verify the PEM format and that it is an EC key.', 'archiviomd' ) );
		}

		// Confirm private key is EC / P-256.
		$key_details = openssl_pkey_get_details( $pkey );
		if ( ( $key_details['type'] ?? -1 ) !== OPENSSL_KEYTYPE_EC ) {
			return new WP_Error( 'not_ec_privkey', __( 'Private key is not an EC key. ECDSA mode requires an EC P-256 private key.', 'archiviomd' ) );
		}
		if ( ( $key_details['ec']['curve_name'] ?? '' ) !== self::REQUIRED_CURVE ) {
			return new WP_Error( 'wrong_curve_privkey', sprintf(
				/* translators: 1: found curve, 2: required curve */
				__( 'Private key uses curve "%1$s". ECDSA mode requires "%2$s".', 'archiviomd' ),
				$key_details['ec']['curve_name'] ?? 'unknown',
				self::REQUIRED_CURVE
			) );
		}

		// ── THE ONLY SIGNING CALL — nonce generated by OpenSSL / OS CSPRNG ──
		$sig_der = '';
		$ok = openssl_sign( $message, $sig_der, $pkey, OPENSSL_ALGO_SHA256 );

		// Overwrite key resource ASAP (PHP will GC but be explicit about intent).
		unset( $pkey );

		if ( ! $ok || ! $sig_der ) {
			return new WP_Error( 'sign_failed', __( 'OpenSSL signing failed. Check PHP error log for OpenSSL error details.', 'archiviomd' ) );
		}

		return bin2hex( $sig_der );
	}

	// ─────────────────────────────────────────────────────────────────────
	// Verify
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Verify a stored ECDSA signature for a post.
	 *
	 * @param  int    $post_id
	 * @param  string $type  'post' or 'media'
	 * @return array|WP_Error
	 */
	public static function verify( int $post_id, string $type = 'post' ) {
		if ( ! self::is_openssl_available() ) {
			return new WP_Error( 'no_openssl', __( 'PHP ext-openssl is not available.', 'archiviomd' ) );
		}

		$cert_pem = self::load_certificate_pem();
		if ( ! $cert_pem ) {
			return new WP_Error( 'no_cert', __( 'No certificate configured for verification.', 'archiviomd' ) );
		}

		$sig_hex = get_post_meta( $post_id, self::META_SIG, true );
		if ( ! $sig_hex ) {
			return new WP_Error( 'no_sig', __( 'No ECDSA signature stored for this content.', 'archiviomd' ) );
		}

		// Basic hex sanity — DER ECDSA P-256 sigs are 70–72 bytes → 140–144 hex chars.
		if ( ! preg_match( '/^[0-9a-f]{100,200}$/i', $sig_hex ) ) {
			return new WP_Error( 'bad_sig_format', __( 'Stored ECDSA signature has unexpected format.', 'archiviomd' ) );
		}

		$sig_der = hex2bin( $sig_hex );
		$message  = ( $type === 'media' )
			? self::canonical_message_media( $post_id )
			: self::canonical_message_post( $post_id );

		$pubkey = openssl_pkey_get_public( $cert_pem );
		if ( ! $pubkey ) {
			return new WP_Error( 'bad_pubkey', __( 'Could not extract public key from certificate for verification.', 'archiviomd' ) );
		}

		$result = openssl_verify( $message, $sig_der, $pubkey, OPENSSL_ALGO_SHA256 );

		return array(
			'valid'     => ( $result === 1 ),
			'post_id'   => $post_id,
			'signed_at' => (int) get_post_meta( $post_id, self::META_SIGNED_AT, true ),
			'method'    => 'openssl-ecdsa-p256',
		);
	}

	// ─────────────────────────────────────────────────────────────────────
	// DSSE envelope
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Build a DSSE envelope signed with ECDSA P-256.
	 *
	 * @param  string $payload
	 * @param  string $payload_type
	 * @return array|WP_Error
	 */
	public static function sign_dsse( string $payload, string $payload_type = self::DSSE_PAYLOAD_TYPE_POST ) {
		// Build PAE per DSSE §3.
		$pae = 'DSSEv1 '
			. strlen( $payload_type ) . ' ' . $payload_type
			. ' '
			. strlen( $payload ) . ' ' . $payload;

		$sig_hex = self::sign( $pae );
		if ( is_wp_error( $sig_hex ) ) {
			return $sig_hex;
		}

		// Derive a keyid from SHA-256 of the certificate DER.
		$cert_pem = self::load_certificate_pem();
		$cert_res = openssl_x509_read( $cert_pem );
		openssl_x509_export( $cert_res, $pem_out );
		$b64 = preg_replace( '/-----[^-]+-----|\s/', '', $pem_out );
		$der = base64_decode( $b64 ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		$keyid = hash( 'sha256', $der );

		return array(
			'payload'     => base64_encode( $payload ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			'payloadType' => $payload_type,
			'signatures'  => array(
				array(
					'keyid' => $keyid,
					'sig'   => base64_encode( hex2bin( $sig_hex ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
					'alg'   => 'ecdsa-p256-sha256',
					'x5c'   => base64_encode( $cert_pem ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions — embed leaf cert for verifiers
				),
			),
		);
	}

	// ─────────────────────────────────────────────────────────────────────
	// Auto-sign hooks (priority 30 — after Ed25519 at 20, SLH-DSA at 25)
	// ─────────────────────────────────────────────────────────────────────

	public function maybe_sign_post( int $post_id, \WP_Post $post ): void {
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( ! self::is_mode_enabled() || ! self::is_openssl_available() ) {
			return;
		}

		$post_types = self::get_configured_post_types();
		if ( ! in_array( $post->post_type, $post_types, true ) ) {
			return;
		}
		if ( ! in_array( $post->post_status, array( 'publish', 'private' ), true ) ) {
			return;
		}

		// Pre-flight certificate validation — bail silently rather than blocking save.
		if ( is_wp_error( self::validate_certificate() ) ) {
			return;
		}

		$message = self::canonical_message_post( $post_id );
		$sig_hex = self::sign( $message );
		if ( is_wp_error( $sig_hex ) ) {
			return;
		}

		$cert_pem = self::load_certificate_pem();

		update_post_meta( $post_id, self::META_SIG,       $sig_hex );
		update_post_meta( $post_id, self::META_CERT,      $cert_pem );
		update_post_meta( $post_id, self::META_SIGNED_AT, time() );

		if ( self::is_dsse_enabled() ) {
			$envelope = self::sign_dsse( $message, self::DSSE_PAYLOAD_TYPE_POST );
			if ( ! is_wp_error( $envelope ) ) {
				update_post_meta( $post_id, self::META_DSSE,
					wp_json_encode( $envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
			}
		}
	}

	public function maybe_sign_media( int $attachment_id ): void {
		if ( ! self::is_mode_enabled() || ! self::is_openssl_available() ) {
			return;
		}
		if ( is_wp_error( self::validate_certificate() ) ) {
			return;
		}

		$message = self::canonical_message_media( $attachment_id );
		$sig_hex = self::sign( $message );
		if ( is_wp_error( $sig_hex ) ) {
			return;
		}

		$cert_pem = self::load_certificate_pem();

		update_post_meta( $attachment_id, self::META_SIG,       $sig_hex );
		update_post_meta( $attachment_id, self::META_CERT,      $cert_pem );
		update_post_meta( $attachment_id, self::META_SIGNED_AT, time() );

		if ( self::is_dsse_enabled() ) {
			$envelope = self::sign_dsse( $message, self::DSSE_PAYLOAD_TYPE_MEDIA );
			if ( ! is_wp_error( $envelope ) ) {
				update_post_meta( $attachment_id, self::META_DSSE,
					wp_json_encode( $envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
			}
		}
	}

	// ─────────────────────────────────────────────────────────────────────
	// Well-known endpoint  /.well-known/ecdsa-cert.pem
	// ─────────────────────────────────────────────────────────────────────

	public static function serve_certificate(): void {
		$cert_pem = self::load_certificate_pem();
		if ( ! $cert_pem ) {
			status_header( 404 );
			exit;
		}

		header( 'Content-Type: application/x-pem-file; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
		// Surface DANE corroboration metadata as response headers.
		// PEM format does not allow embedded comments, so headers are the
		// only way to convey this to HTTP clients.
		if ( class_exists( 'MDSM_DANE_Corroboration' ) && MDSM_DANE_Corroboration::is_enabled() ) {
			header( 'X-ArchivioMD-DNS-Record: ' . MDSM_DANE_Corroboration::dns_record_name( 'ecdsa' ) );
			header( 'X-ArchivioMD-DNS-Discovery: ' . home_url( '/.well-known/' . MDSM_DANE_Corroboration::JSON_SLUG ) );
		}
		nocache_headers();
		echo $cert_pem; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	// ─────────────────────────────────────────────────────────────────────
	// AJAX: settings toggle
	// ─────────────────────────────────────────────────────────────────────

	public function ajax_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$enable = isset( $_POST['ecdsa_enabled'] )
			&& sanitize_text_field( wp_unslash( $_POST['ecdsa_enabled'] ) ) === 'true';

		if ( $enable ) {
			if ( ! self::is_openssl_available() ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Cannot enable ECDSA signing: PHP ext-openssl is not available on this server.', 'archiviomd' ) ) );
			}
			if ( ! self::load_private_key_pem() ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Cannot enable ECDSA signing: no private key configured. Upload a key or set the constant in wp-config.php first.', 'archiviomd' ) ) );
			}
			if ( ! self::load_certificate_pem() ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Cannot enable ECDSA signing: no certificate configured. Upload a PEM certificate first.', 'archiviomd' ) ) );
			}
			$cert_check = self::validate_certificate();
			if ( is_wp_error( $cert_check ) ) {
				wp_send_json_error( array( 'message' => esc_html( $cert_check->get_error_message() ) ) );
			}
		}

		self::set_mode( $enable );
		self::clear_status_cache(); // flush cache so status() reflects new option immediately

		if ( isset( $_POST['dsse_enabled'] ) ) {
			$dsse_enable = sanitize_text_field( wp_unslash( $_POST['dsse_enabled'] ) ) === 'true';
			self::set_dsse_mode( $enable && $dsse_enable );
		}

		$status = self::status();
		wp_send_json_success( array(
			'message'        => $enable
				? esc_html__( 'ECDSA Enterprise Signing enabled.', 'archiviomd' )
				: esc_html__( 'ECDSA Enterprise Signing disabled.', 'archiviomd' ),
			'notice_level'   => $status['notice_level'],
			'notice_message' => wp_strip_all_tags( $status['notice_message'] ),
			'dsse_enabled'   => $status['dsse_enabled'],
		) );
	}

	// ─────────────────────────────────────────────────────────────────────
	// AJAX: PEM file uploads  (key / cert / CA bundle)
	//
	// Files are written OUTSIDE webroot.  Path is validated before save.
	// Private key PEM is never echoed back — only success/failure.
	// ─────────────────────────────────────────────────────────────────────

	/**
	 * Shared upload handler.
	 *
	 * @param string $post_field   $_FILES key
	 * @param string $option_key   wp_options key to store path
	 * @param string $type_label   Human label for error messages
	 * @param bool   $is_private   True for private key (stricter validation, no echo of content)
	 */
	private function handle_pem_upload( string $post_field, string $option_key, string $type_label, bool $is_private ): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		if ( empty( $_FILES[ $post_field ]['tmp_name'] ) ) {
			wp_send_json_error( array( 'message' => sprintf(
				/* translators: %s: file type label */
				esc_html__( 'No %s file received.', 'archiviomd' ), $type_label
			) ) );
		}

		$tmp = $_FILES[ $post_field ]['tmp_name'];
		if ( ! is_uploaded_file( $tmp ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'File upload error.', 'archiviomd' ) ) );
		}

		$pem = file_get_contents( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $pem ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Uploaded file is empty.', 'archiviomd' ) ) );
		}

		// Validate PEM structure.
		if ( $is_private ) {
			if ( ! str_contains( $pem, 'PRIVATE KEY' ) ) {
				wp_send_json_error( array( 'message' => esc_html__( 'File does not appear to be a PEM private key (missing "PRIVATE KEY" header).', 'archiviomd' ) ) );
			}
			// Validate it is actually an EC key before storing.
			$pkey = openssl_pkey_get_private( $pem );
			if ( ! $pkey ) {
				wp_send_json_error( array( 'message' => esc_html__( 'OpenSSL could not parse the private key. Ensure it is PEM-encoded and not password-protected.', 'archiviomd' ) ) );
			}
			$details = openssl_pkey_get_details( $pkey );
			if ( ( $details['type'] ?? -1 ) !== OPENSSL_KEYTYPE_EC ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Private key is not an EC key. ECDSA mode requires an EC P-256 private key.', 'archiviomd' ) ) );
			}
			if ( ( $details['ec']['curve_name'] ?? '' ) !== self::REQUIRED_CURVE ) {
				wp_send_json_error( array( 'message' => sprintf(
					/* translators: %s: curve name */
					esc_html__( 'Private key uses the wrong curve (%s). Only P-256 (prime256v1) is accepted.', 'archiviomd' ),
					esc_html( $details['ec']['curve_name'] ?? 'unknown' )
				) ) );
			}
		} else {
			if ( ! str_contains( $pem, 'CERTIFICATE' ) ) {
				wp_send_json_error( array( 'message' => esc_html__( 'File does not appear to be a PEM certificate (missing "CERTIFICATE" header).', 'archiviomd' ) ) );
			}
		}

		// Store PEM files two directory levels above ABSPATH so they sit
		// outside the webroot on every standard layout:
		//   /var/www/html/            ← ABSPATH (webroot)
		//   /var/www/archiviomd-pem/  ← store (two levels up = /var/www/)
		// dirname(uploads_basedir) only goes to wp-content, which is still
		// inside the webroot and unprotected on nginx without AllowOverride.
		$base_dir  = dirname( ABSPATH ); // one level above webroot
		$store_dir = $base_dir . '/archiviomd-pem';
		if ( ! wp_mkdir_p( $store_dir ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Could not create secure PEM storage directory. Check filesystem permissions.', 'archiviomd' ) ) );
		}

		// Add an .htaccess guard (belt + suspenders — directory should be outside webroot anyway).
		$htaccess = $store_dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Deny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		$filename    = sanitize_file_name( $type_label ) . '.pem';
		$destination = $store_dir . '/' . $filename;

		// Verify destination is safe before writing.
		if ( ! self::is_safe_pem_path( $destination ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Destination path failed safety check. Contact your server administrator.', 'archiviomd' ) ) );
		}

		if ( file_put_contents( $destination, $pem ) === false ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			wp_send_json_error( array( 'message' => esc_html__( 'Could not write PEM file. Check filesystem permissions.', 'archiviomd' ) ) );
		}

		// Restrict permissions on private key.
		if ( $is_private ) {
			chmod( $destination, 0600 );
		}

		update_option( $option_key, $destination );
		self::clear_status_cache();

		wp_send_json_success( array(
			'message' => sprintf(
				/* translators: %s: file type label */
				esc_html__( '%s uploaded and stored successfully.', 'archiviomd' ),
				$type_label
			),
		) );
	}

	public function ajax_upload_key(): void {
		$this->handle_pem_upload( 'ecdsa_cert_pem', self::OPTION_CERT_PATH, 'ecdsa-certificate', false );
	}

	public function ajax_upload_ca(): void {
		$this->handle_pem_upload( 'ecdsa_ca_pem', self::OPTION_CA_PATH, 'ecdsa-ca-bundle', false );
	}

	// ─────────────────────────────────────────────────────────────────────
	// AJAX: clear stored paths
	// ─────────────────────────────────────────────────────────────────────

	private function handle_pem_clear( string $option_key, string $type_label ): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$path = get_option( $option_key, '' );
		if ( $path && file_exists( $path ) ) {
			// Overwrite with zeros before unlinking (best-effort for private keys).
			$len = filesize( $path );
			if ( $len > 0 ) {
				file_put_contents( $path, str_repeat( "\0", $len ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		delete_option( $option_key );
		self::clear_status_cache();

		// Disable signing if the private key was cleared.
		if ( $option_key === self::OPTION_KEY_PATH ) {
			self::set_mode( false );
		}

		wp_send_json_success( array(
			'message' => sprintf(
				/* translators: %s: file type */
				esc_html__( '%s cleared.', 'archiviomd' ),
				$type_label
			),
		) );
	}

	public function ajax_clear_key(): void {
		$this->handle_pem_clear( self::OPTION_KEY_PATH, 'Private key' );
	}

	public function ajax_clear_cert(): void {
		$this->handle_pem_clear( self::OPTION_CERT_PATH, 'Certificate' );
	}

	public function ajax_clear_ca(): void {
		$this->handle_pem_clear( self::OPTION_CA_PATH, 'CA bundle' );
	}
}
