<?php
/**
 * DANE / DNS Key Corroboration — ArchivioMD
 *
 * Publishes all active signing keys as DNSSEC-protected DNS TXT records so
 * that any verifier can authenticate them independently of the web server —
 * no trust-on-first-use required.
 *
 * ── DNS record format (modelled on DKIM, RFC 6376) ───────────────────────
 *
 *   Ed25519:
 *     _archiviomd._domainkey.example.com        IN TXT "v=amd1; k=ed25519; p=<base64>"
 *
 *   SLH-DSA:
 *     _archiviomd-slhdsa._domainkey.example.com IN TXT "v=amd1; k=slh-dsa; a=<param>; p=<base64>"
 *
 *   ECDSA P-256:
 *     _archiviomd-ecdsa._domainkey.example.com  IN TXT "v=amd1; k=ecdsa-p256; p=<base64-cert-sha256>"
 *     (p= is base64 of the SHA-256 hash of the certificate DER)
 *
 *   RSA:
 *     _archiviomd-rsa._domainkey.example.com    IN TXT "v=amd1; k=rsa; p=<base64-cert-sha256>"
 *     (p= is base64 of the SHA-256 hash of the certificate DER when a cert is
 *      configured, otherwise SHA-256 of the DER-encoded public key)
 *
 *   v=amd1   — version tag.
 *   k=       — algorithm identifier.
 *   a=       — algorithm parameter (SLH-DSA only).
 *   p=       — key material or fingerprint (base64).
 *
 * ── TLSA record format (RFC 6698 / DANE-EE) ──────────────────────────────
 *
 *   ECDSA certificate:
 *     _443._tcp.example.com  IN TLSA  3 1 1 <spki-sha256-hex>
 *
 *   Parameters:
 *     Usage         3  — DANE-EE: verifier trusts the leaf cert directly,
 *                        no CA chain required.
 *     Selector      1  — SubjectPublicKeyInfo (SPKI DER), not full cert.
 *     Matching-type 1  — SHA-256 hash of the selected bytes.
 *
 *   The certificate-data field is the hex-encoded SHA-256 of the
 *   SubjectPublicKeyInfo DER extracted from the ECDSA leaf certificate.
 *   Using selector=1 (SPKI) instead of selector=0 (full cert) means the
 *   record survives certificate renewal without changing the key.
 *
 *   DNSSEC MUST be active on the zone for TLSA to provide any security
 *   guarantee; without DNSSEC the record is trivially spoofable.
 *
 *   Port / protocol override:
 *     define( 'ARCHIVIOMD_TLSA_PORT',     '443' ); // default 443
 *     define( 'ARCHIVIOMD_TLSA_PROTOCOL', 'tcp' ); // default tcp
 *
 *   The TLSA health check uses the same DoH resolver as the TXT checks
 *   (ARCHIVIOMD_DOH_URL constant / archiviomd_doh_url filter).
 *
 * ── Machine-readable discovery endpoint ──────────────────────────────────
 *
 *   /.well-known/archiviomd-dns.json
 *
 *   {
 *     "version": "amd1",
 *     "site": "https://example.com",
 *     "records": [
 *       { "algorithm": "ed25519",
 *         "dns_name":  "_archiviomd._domainkey.example.com",
 *         "key_id":    "<sha256-fingerprint-hex>",
 *         "txt_value": "v=amd1; k=ed25519; p=..." }
 *     ]
 *   }
 *
 * ── Passive health monitoring via wp-cron ────────────────────────────────
 *
 *   A weekly cron job runs the full health check for all active keys.
 *   Failures are surfaced as a dismissible admin notice on the next
 *   wp-admin page load.
 *
 * ── Staleness detection ───────────────────────────────────────────────────
 *
 *   Warns when a signer is active but DANE is off (no DNS trust anchor),
 *   or when DANE is on but a covered key is no longer configured.
 *
 * ── Key rotation ──────────────────────────────────────────────────────────
 *
 *   1. Call start_rotation() — suppresses mismatch warnings during TTL window.
 *   2. Publish new TXT records alongside existing ones.
 *   3. Wait one TTL (3600 s).
 *   4. Update wp-config.php constants to new keypair.
 *   5. Call finish_rotation().
 *   6. Remove old TXT records after one more TTL.
 *
 * ── DoH resolver override ─────────────────────────────────────────────────
 *
 *   define( 'ARCHIVIOMD_DOH_URL', 'https://8.8.8.8/resolve' );
 *   add_filter( 'archiviomd_doh_url', fn() => 'https://8.8.8.8/resolve' );
 *
 * ── DNS TTL override ──────────────────────────────────────────────────────
 *
 *   define( 'ARCHIVIOMD_DANE_TTL', 300 ); // default 3600
 *
 *   Controls the TTL shown in the admin UI record tables and the rotation
 *   timeout threshold (2× TTL). Useful during initial setup when a short
 *   TTL lets you iterate quickly.
 *
 * @package ArchivioMD
 * @since   1.17.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_DANE_Corroboration {

	// ── Option / transient keys ───────────────────────────────────────────
	const OPTION_ENABLED          = 'archiviomd_dane_enabled';
	const OPTION_TLSA_ENABLED     = 'archiviomd_dane_tlsa_enabled';
	const OPTION_ROTATION_MODE    = 'archiviomd_dane_rotation_mode';
	const OPTION_ROTATION_STARTED = 'archiviomd_dane_rotation_started_at';
	const OPTION_CRON_NOTICE      = 'archiviomd_dane_cron_notice';
	const TRANSIENT_HEALTH        = 'archiviomd_dane_health';
	const TRANSIENT_TLSA_HEALTH   = 'archiviomd_dane_tlsa_health';
	const TRANSIENT_TTL           = 300; // 5 minutes

	// ── DNS record naming prefixes ────────────────────────────────────────
	const DNS_PREFIX_ED25519 = '_archiviomd._domainkey';
	const DNS_PREFIX_SLHDSA  = '_archiviomd-slhdsa._domainkey';
	const DNS_PREFIX_ECDSA   = '_archiviomd-ecdsa._domainkey';
	const DNS_PREFIX_RSA     = '_archiviomd-rsa._domainkey';

	// ── TLSA record defaults (RFC 6698) ───────────────────────────────────
	// Usage=3 (DANE-EE), Selector=1 (SPKI), Matching-type=1 (SHA-256)
	const TLSA_USAGE    = 3;
	const TLSA_SELECTOR = 1;
	const TLSA_MTYPE    = 1;

	// ── TXT record version tag ────────────────────────────────────────────
	const TXT_VERSION = 'amd1';

	// ── DoH resolver default ──────────────────────────────────────────────
	const DOH_URL_DEFAULT = 'https://1.1.1.1/dns-query';

	// ── Cron hook ─────────────────────────────────────────────────────────
	const CRON_HOOK = 'archiviomd_dane_cron_check';

	// ── Well-known JSON discovery slug ────────────────────────────────────
	const JSON_SLUG = 'archiviomd-dns.json';

	// ── Well-known machine-readable spec slug ─────────────────────────────
	const SPEC_SLUG = 'archiviomd-dns-spec.json';

	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'wp_ajax_archivio_dane_save_settings',    array( $this, 'ajax_save_settings'   ) );
		add_action( 'wp_ajax_archivio_dane_health_check',     array( $this, 'ajax_health_check'    ) );
		add_action( 'wp_ajax_archivio_dane_tlsa_check',       array( $this, 'ajax_tlsa_check'      ) );
		add_action( 'wp_ajax_archivio_dane_start_rotation',   array( $this, 'ajax_start_rotation'  ) );
		add_action( 'wp_ajax_archivio_dane_finish_rotation',  array( $this, 'ajax_finish_rotation' ) );
		add_action( 'wp_ajax_archivio_dane_dismiss_notice',   array( $this, 'ajax_dismiss_notice'  ) );

		// Register the 'weekly' cron schedule (WordPress ships hourly/twicedaily/daily only).
		add_filter( 'cron_schedules', array( $this, 'register_weekly_schedule' ) );

		// Passive cron check.
		add_action( self::CRON_HOOK, array( $this, 'run_cron_check' ) );

		// Schedule / unschedule cron when the module is toggled.
		add_action( 'update_option_' . self::OPTION_ENABLED, array( $this, 'sync_cron_schedule' ), 10, 2 );

		// Admin notice surfaced by cron.
		add_action( 'admin_notices', array( $this, 'maybe_show_cron_notice' ) );

		// Bootstrap cron schedule if enabled but not yet scheduled.
		if ( self::is_enabled() && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'weekly', self::CRON_HOOK );
		}
	}

	// ── Enable / disable ──────────────────────────────────────────────────

	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	public static function set_enabled( bool $enabled ): void {
		update_option( self::OPTION_ENABLED, $enabled );
		delete_transient( self::TRANSIENT_HEALTH );
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
		// Clear any stale cron notice when the module is disabled.
		if ( ! $enabled ) {
			delete_option( self::OPTION_CRON_NOTICE );
		}
	}

	// ── Cron schedule registration ────────────────────────────────────────

	/**
	 * Add a 'weekly' interval to WordPress's built-in cron schedules.
	 * WordPress ships with hourly, twicedaily, and daily — 'weekly' is not
	 * included and wp_schedule_event() silently fails if given an unknown
	 * interval, so we must register it ourselves.
	 */
	public function register_weekly_schedule( array $schedules ): array {
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once Weekly', 'archiviomd' ),
			);
		}
		return $schedules;
	}

	// ── Cron ──────────────────────────────────────────────────────────────

	/**
	 * Called when the OPTION_ENABLED option changes.
	 * Schedule or unschedule the weekly cron accordingly.
	 *
	 * @param mixed $old_value
	 * @param mixed $new_value
	 */
	public function sync_cron_schedule( $old_value, $new_value ): void {
		if ( $new_value ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', self::CRON_HOOK );
			}
		} else {
			$ts = wp_next_scheduled( self::CRON_HOOK );
			if ( $ts ) {
				wp_unschedule_event( $ts, self::CRON_HOOK );
			}
		}
	}

	/**
	 * Passive cron job — check all active keys silently and store a notice
	 * option if anything is wrong.
	 */
	public function run_cron_check(): void {
		if ( ! self::is_enabled() ) {
			return;
		}

		delete_transient( self::TRANSIENT_HEALTH );
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
		$results  = self::run_all_health_checks();
		$failures = array();

		foreach ( $results as $algo => $r ) {
			if ( ! $r['found'] ) {
				$failures[] = sprintf(
					/* translators: %s: algorithm name */
					__( '%s: TXT record not found in DNS.', 'archiviomd' ),
					strtoupper( $algo )
				);
			} elseif ( ! $r['key_match'] && ! self::is_rotation_mode() ) {
				$failures[] = sprintf(
					/* translators: %s: algorithm name */
					__( '%s: DNS record does not match the configured key.', 'archiviomd' ),
					strtoupper( $algo )
				);
			} elseif ( ! empty( $r['dnssec_checked'] ) && ! $r['dnssec_ad'] ) {
				// Only flag DNSSEC when the DoH call actually succeeded — a network
				// timeout sets dnssec_checked=false and should not masquerade as a
				// DNSSEC failure.
				$failures[] = sprintf(
					/* translators: %s: algorithm name */
					__( '%s: DNSSEC not validated (AD flag absent).', 'archiviomd' ),
					strtoupper( $algo )
				);
			}
		}

		// TLSA passive check.
		if ( self::is_tlsa_enabled() && self::tlsa_cert_data_hex() ) {
			$tlsa = self::run_tlsa_health_check();
			if ( ! $tlsa['found'] ) {
				$failures[] = __( 'TLSA: record not found in DNS.', 'archiviomd' );
			} elseif ( ! $tlsa['cert_match'] ) {
				$failures[] = __( 'TLSA: record does not match the configured ECDSA certificate.', 'archiviomd' );
			} elseif ( $tlsa['dnssec_checked'] && ! $tlsa['dnssec_ad'] ) {
				$failures[] = __( 'TLSA: DNSSEC not validated (AD flag absent) — TLSA provides no security without DNSSEC.', 'archiviomd' );
			}
		}

		if ( ! empty( $failures ) ) {
			update_option( self::OPTION_CRON_NOTICE, array(
				'time'     => time(),
				'failures' => $failures,
			) );
		} else {
			delete_option( self::OPTION_CRON_NOTICE );
		}
	}

	// ── Admin notice ──────────────────────────────────────────────────────

	public function maybe_show_cron_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$notice = get_option( self::OPTION_CRON_NOTICE );
		if ( ! is_array( $notice ) || empty( $notice['failures'] ) ) {
			return;
		}

		$age_hours = (int) round( ( time() - (int) ( $notice['time'] ?? 0 ) ) / HOUR_IN_SECONDS );
		$nonce     = wp_create_nonce( 'archivio_post_nonce' );
		$review_url = admin_url( 'admin.php?page=archivio-post&tab=extended' );

		echo '<div class="notice notice-warning" id="archiviomd-dane-cron-notice">';
		echo '<p><strong>' . esc_html__( 'ArchivioMD DANE Health Check — issues detected', 'archiviomd' ) . '</strong>';
		if ( $age_hours > 0 ) {
			echo ' <em style="font-weight:normal;color:#666;">(' . sprintf( esc_html__( 'detected %d hour(s) ago', 'archiviomd' ), $age_hours ) . ')</em>';
		}
		echo '</p>';
		echo '<ul style="margin:.4em 0 .6em 1.4em;list-style:disc;">';
		foreach ( $notice['failures'] as $f ) {
			echo '<li>' . esc_html( $f ) . '</li>';
		}
		echo '</ul>';
		echo '<p>';
		echo '<a href="' . esc_url( $review_url ) . '" style="margin-right:12px;">' . esc_html__( 'Review DANE settings', 'archiviomd' ) . '</a>';
		echo '<a href="#" id="archiviomd-dane-dismiss-link">' . esc_html__( 'Dismiss', 'archiviomd' ) . '</a>';
		echo '</p></div>';
		// Inline dismiss handler — no extra JS file dependency.
		echo '<script>document.getElementById("archiviomd-dane-dismiss-link").addEventListener("click",function(e){e.preventDefault();';
		echo 'var fd=new FormData();fd.append("action","archivio_dane_dismiss_notice");fd.append("nonce","' . esc_js( $nonce ) . '");';
		echo 'fetch("' . esc_url( admin_url( 'admin-ajax.php' ) ) . '",{method:"POST",body:fd});';
		echo 'document.getElementById("archiviomd-dane-cron-notice").remove();';
		echo '});</script>';
	}

	// ── DoH URL resolution ────────────────────────────────────────────────

	public static function doh_url(): string {
		if ( defined( 'ARCHIVIOMD_DOH_URL' ) && filter_var( constant( 'ARCHIVIOMD_DOH_URL' ), FILTER_VALIDATE_URL ) ) {
			return constant( 'ARCHIVIOMD_DOH_URL' );
		}
		return (string) apply_filters( 'archiviomd_doh_url', self::DOH_URL_DEFAULT );
	}

	/**
	 * Return the configured DNS TTL in seconds.
	 *
	 * Defaults to 3600 (1 hour). Override with:
	 *   define( 'ARCHIVIOMD_DANE_TTL', 300 ); // e.g. during initial setup
	 *
	 * Used by:
	 *   - Admin UI TTL display on TXT/TLSA record tables
	 *   - Rotation timeout warning (fires at 2× TTL)
	 */
	public static function dane_ttl(): int {
		if ( defined( 'ARCHIVIOMD_DANE_TTL' ) ) {
			$ttl = (int) constant( 'ARCHIVIOMD_DANE_TTL' );
			if ( $ttl > 0 ) {
				return $ttl;
			}
		}
		return 3600;
	}

	// ── Rotation mode ─────────────────────────────────────────────────────

	public static function is_rotation_mode(): bool {
		return (bool) get_option( self::OPTION_ROTATION_MODE, false );
	}

	public static function start_rotation(): void {
		update_option( self::OPTION_ROTATION_MODE,    true );
		update_option( self::OPTION_ROTATION_STARTED, time() );
		delete_transient( self::TRANSIENT_HEALTH );
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
	}

	public static function finish_rotation(): void {
		update_option( self::OPTION_ROTATION_MODE, false );
		delete_option( self::OPTION_ROTATION_STARTED );
		delete_transient( self::TRANSIENT_HEALTH );
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
	}

	public static function rotation_elapsed_seconds(): int {
		$started = (int) get_option( self::OPTION_ROTATION_STARTED, 0 );
		return $started > 0 ? max( 0, time() - $started ) : 0;
	}

	// ── Prerequisite / staleness ──────────────────────────────────────────

	public static function is_prerequisite_met(): bool {
		// DANE can be enabled as long as at least one key is available to publish.
		// Previously gated on Ed25519 only — now any active algorithm qualifies.
		return ! empty( self::active_algorithms() );
	}

	/**
	 * Return array of human-readable staleness warnings.
	 *
	 * Conditions checked:
	 *   - Any corroboratable signer is active but DANE is disabled.
	 *   - DANE is enabled but no corroboratable key is configured any more.
	 *   - Key rotation has been running longer than 2× the DNS TTL (7200 s),
	 *     meaning the old record is almost certainly gone and mismatch suppression
	 *     is now counterproductive.
	 */
	public static function staleness_warnings(): array {
		$warnings = array();

		if ( ! self::is_enabled() ) {
			// Warn for every active signer that has no DNS trust anchor.
			$signer_map = array(
				'ed25519' => array( 'MDSM_Ed25519_Signing', 'Ed25519' ),
				'slhdsa'  => array( 'MDSM_SLHDSA_Signing',  'SLH-DSA' ),
				'ecdsa'   => array( 'MDSM_ECDSA_Signing',   'ECDSA'   ),
				'rsa'     => array( 'MDSM_RSA_Signing',     'RSA'     ),
			);
			foreach ( $signer_map as $algo => $info ) {
				list( $class, $label ) = $info;
				if ( ! class_exists( $class ) ) {
					continue;
				}
				// Ed25519 / SLH-DSA expose is_mode_enabled() + is_public_key_defined().
				// ECDSA / RSA expose is_mode_enabled() + load_certificate_pem() / is_private_key_defined().
				$active = false;
				if ( method_exists( $class, 'is_mode_enabled' ) && $class::is_mode_enabled() ) {
					if ( method_exists( $class, 'is_public_key_defined' ) ) {
						$active = $class::is_public_key_defined();
					} elseif ( method_exists( $class, 'is_private_key_defined' ) ) {
						$active = $class::is_private_key_defined();
					} else {
						$active = true; // mode enabled, assume key present
					}
				}
				if ( $active ) {
					$warnings[] = sprintf(
						/* translators: %s: algorithm label e.g. "Ed25519" */
						__( '%s signing is active but DANE Corroboration is disabled — your key has no DNS trust anchor.', 'archiviomd' ),
						$label
					);
				}
			}
		} else {
			// DANE is on — warn if no key at all is publishable.
			if ( empty( self::active_algorithms() ) ) {
				$warnings[] = __( 'DANE is enabled but no signing keys are configured. DNS records are now unverifiable — define at least one key constant in wp-config.php.', 'archiviomd' );
			}
			// Warn if rotation has been running too long.
			if ( self::is_rotation_mode() && self::rotation_elapsed_seconds() > ( self::dane_ttl() * 2 ) ) {
				$minutes = (int) ceil( self::rotation_elapsed_seconds() / 60 );
				$warnings[] = sprintf(
					/* translators: %d: minutes elapsed */
					__( 'Key rotation has been active for %d minutes (more than 2× the DNS TTL). The old TXT record is likely gone — mismatch-warning suppression may now hide real problems. Run "Finish Rotation" unless you are still waiting for propagation.', 'archiviomd' ),
					$minutes
				);
			}
			// Warn when TLSA is enabled but the ECDSA certificate is expiring soon or expired.
			if ( self::is_tlsa_enabled() && class_exists( 'MDSM_ECDSA_Signing' ) ) {
				$cert_pem = MDSM_ECDSA_Signing::load_certificate_pem();
				if ( $cert_pem && function_exists( 'openssl_x509_parse' ) ) {
					$parsed = openssl_x509_parse( $cert_pem );
					if ( is_array( $parsed ) ) {
						$expires   = (int) ( $parsed['validTo_time_t'] ?? 0 );
						$days_left = $expires ? (int) round( ( $expires - time() ) / DAY_IN_SECONDS ) : null;
						if ( null !== $days_left && $days_left <= 0 ) {
							$warnings[] = __( 'TLSA is enabled but the ECDSA certificate has expired. The TLSA record now points to an expired certificate — renew the certificate and update the DNS record immediately.', 'archiviomd' );
						} elseif ( null !== $days_left && $days_left <= 30 ) {
							$warnings[] = sprintf(
								/* translators: %d: days until expiry */
								_n(
									'TLSA is enabled and the ECDSA certificate expires in %d day. Renew it and update the TLSA record before expiry.',
									'TLSA is enabled and the ECDSA certificate expires in %d days. Renew it and update the TLSA record before expiry.',
									$days_left,
									'archiviomd'
								),
								$days_left
							);
						}
					}
				}
			}
		}

		return $warnings;
	}

	// ── Per-algorithm key helpers ─────────────────────────────────────────

	/**
	 * Return DNS record name for a given algorithm.
	 *
	 * @param string $algo  'ed25519' | 'slhdsa' | 'ecdsa'
	 */
	public static function dns_record_name( string $algo = 'ed25519' ): string {
		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );
		switch ( $algo ) {
			case 'slhdsa':
				return self::DNS_PREFIX_SLHDSA . '.' . $host;
			case 'ecdsa':
				return self::DNS_PREFIX_ECDSA . '.' . $host;
			case 'rsa':
				return self::DNS_PREFIX_RSA . '.' . $host;
			default:
				return self::DNS_PREFIX_ED25519 . '.' . $host;
		}
	}

	public static function ed25519_key_b64(): string {
		if ( ! class_exists( 'MDSM_Ed25519_Signing' ) || ! MDSM_Ed25519_Signing::is_public_key_defined() ) {
			return '';
		}
		return base64_encode( hex2bin( constant( MDSM_Ed25519_Signing::PUBLIC_KEY_CONSTANT ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	public static function slhdsa_key_b64(): string {
		if ( ! class_exists( 'MDSM_SLHDSA_Signing' ) || ! MDSM_SLHDSA_Signing::is_public_key_defined() ) {
			return '';
		}
		return base64_encode( hex2bin( constant( MDSM_SLHDSA_Signing::PUBLIC_KEY_CONSTANT ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * For ECDSA we publish base64 of SHA-256(cert DER) in the p= field.
	 * This is consistent with the fingerprint already shown in the admin UI.
	 */
	public static function ecdsa_key_b64(): string {
		if ( ! class_exists( 'MDSM_ECDSA_Signing' ) ) {
			return '';
		}
		$cert_pem = MDSM_ECDSA_Signing::load_certificate_pem();
		if ( ! $cert_pem || ! function_exists( 'openssl_x509_read' ) ) {
			return '';
		}
		$cert_res = openssl_x509_read( $cert_pem );
		if ( ! $cert_res ) {
			return '';
		}
		openssl_x509_export( $cert_res, $pem_out );
		$b64_raw = preg_replace( '/-----[^-]+-----|\\s/', '', $pem_out );
		$der     = base64_decode( $b64_raw ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( ! $der ) {
			return '';
		}
		return base64_encode( hash( 'sha256', $der, true ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * For RSA we publish base64 of SHA-256(cert DER) when a certificate is
	 * available, falling back to SHA-256 of the DER-encoded public key.
	 * Consistent with how ECDSA fingerprinting works.
	 */
	public static function rsa_key_b64(): string {
		if ( ! class_exists( 'MDSM_RSA_Signing' ) ) {
			return '';
		}
		if ( ! function_exists( 'openssl_x509_read' ) ) {
			return '';
		}
		// Prefer certificate fingerprint.
		if ( method_exists( 'MDSM_RSA_Signing', 'load_certificate_pem' ) ) {
			$cert_pem = MDSM_RSA_Signing::load_certificate_pem();
			if ( $cert_pem ) {
				$cert_res = openssl_x509_read( $cert_pem );
				if ( $cert_res ) {
					openssl_x509_export( $cert_res, $pem_out );
					$b64_raw = preg_replace( '/-----[^-]+-----|\\s/', '', $pem_out );
					$der     = base64_decode( $b64_raw ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
					if ( $der ) {
						return base64_encode( hash( 'sha256', $der, true ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
					}
				}
			}
		}
		// Fall back: SHA-256 of the DER public key.
		if ( method_exists( 'MDSM_RSA_Signing', 'is_private_key_defined' ) && MDSM_RSA_Signing::is_private_key_defined() ) {
			$pem_pub = method_exists( 'MDSM_RSA_Signing', 'get_public_key_pem' )
				? MDSM_RSA_Signing::get_public_key_pem()
				: '';
			if ( $pem_pub ) {
				$b64_raw = preg_replace( '/-----[^-]+-----|\\s/', '', $pem_pub );
				$der     = base64_decode( $b64_raw ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				if ( $der ) {
					return base64_encode( hash( 'sha256', $der, true ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				}
			}
		}
		return '';
	}

	/**
	 * Build the full TXT record value for a given algorithm.
	 * Returns '' if the key is not available.
	 */
	public static function expected_txt_value( string $algo = 'ed25519' ): string {
		switch ( $algo ) {
			case 'ed25519':
				$p = self::ed25519_key_b64();
				return $p ? sprintf( 'v=%s; k=ed25519; p=%s', self::TXT_VERSION, $p ) : '';

			case 'slhdsa':
				$p = self::slhdsa_key_b64();
				if ( ! $p ) {
					return '';
				}
				$param = class_exists( 'MDSM_SLHDSA_Signing' ) ? MDSM_SLHDSA_Signing::get_param() : '';
				return sprintf( 'v=%s; k=slh-dsa; a=%s; p=%s', self::TXT_VERSION, $param, $p );

			case 'ecdsa':
				$p = self::ecdsa_key_b64();
				return $p ? sprintf( 'v=%s; k=ecdsa-p256; p=%s', self::TXT_VERSION, $p ) : '';

			case 'rsa':
				$p = self::rsa_key_b64();
				return $p ? sprintf( 'v=%s; k=rsa; p=%s', self::TXT_VERSION, $p ) : '';
		}
		return '';
	}

	/**
	 * Return the hex SHA-256 key fingerprint for a given algorithm.
	 * Used in the JSON discovery document and CLI --porcelain output.
	 */
	public static function key_fingerprint( string $algo ): string {
		switch ( $algo ) {
			case 'ed25519':
				return class_exists( 'MDSM_Ed25519_Signing' ) ? MDSM_Ed25519_Signing::public_key_fingerprint() : '';
			case 'slhdsa':
				return class_exists( 'MDSM_SLHDSA_Signing' ) ? MDSM_SLHDSA_Signing::public_key_fingerprint() : '';
			case 'ecdsa':
				$b64 = self::ecdsa_key_b64();
				return $b64 ? bin2hex( base64_decode( $b64 ) ) : ''; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			case 'rsa':
				$b64 = self::rsa_key_b64();
				return $b64 ? bin2hex( base64_decode( $b64 ) ) : ''; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		}
		return '';
	}

	/**
	 * Return all algorithms that currently have a publishable key.
	 *
	 * @return string[]  Subset of ['ed25519', 'slhdsa', 'ecdsa', 'rsa'].
	 */
	public static function active_algorithms(): array {
		$active = array();
		if ( self::ed25519_key_b64() ) {
			$active[] = 'ed25519';
		}
		if ( self::slhdsa_key_b64() ) {
			$active[] = 'slhdsa';
		}
		if ( self::ecdsa_key_b64() ) {
			$active[] = 'ecdsa';
		}
		if ( self::rsa_key_b64() ) {
			$active[] = 'rsa';
		}
		return $active;
	}

	// ── Status array ──────────────────────────────────────────────────────

	public static function status(): array {
		$enabled    = self::is_enabled();
		$prereq_met = self::is_prerequisite_met();
		$ready      = $enabled && $prereq_met;
		$algos      = self::active_algorithms();

		$notice_level   = 'ok';
		$notice_message = '';

		if ( $enabled ) {
			if ( ! $prereq_met ) {
				$notice_level   = 'error';
				$notice_message = __( 'DANE DNS Corroboration is enabled but no signing keys are configured. Define at least one key constant (e.g. ARCHIVIOMD_ED25519_PUBLIC_KEY) in wp-config.php.', 'archiviomd' );
			} else {
				$notice_message = __( 'DANE DNS Corroboration is active. Publish the TXT records shown below and run a health check to verify DNSSEC.', 'archiviomd' );
			}
		}

		$records = array();
		foreach ( $algos as $algo ) {
			$records[ $algo ] = array(
				'dns_name'    => self::dns_record_name( $algo ),
				'txt_value'   => self::expected_txt_value( $algo ),
				'fingerprint' => self::key_fingerprint( $algo ),
			);
		}

		return array(
			'mode_enabled'     => $enabled,
			'prereq_met'       => $prereq_met,
			'ready'            => $ready,
			'active_algos'     => $algos,
			'records'          => $records,
			// Legacy single-key fields for backward compatibility.
			'dns_record_name'  => self::dns_record_name( 'ed25519' ),
			'expected_txt'     => self::expected_txt_value( 'ed25519' ),
			'public_key_b64'   => self::ed25519_key_b64(),
			'notice_level'     => $notice_level,
			'notice_message'   => $notice_message,
			'rotation_mode'    => self::is_rotation_mode(),
			'rotation_elapsed' => self::rotation_elapsed_seconds(),
			'doh_url'          => self::doh_url(),
			'dane_ttl'         => self::dane_ttl(),
			'staleness'        => self::staleness_warnings(),
			'json_endpoint'    => home_url( '/.well-known/' . self::JSON_SLUG ),
			// TLSA fields.
			'tlsa_enabled'     => self::is_tlsa_enabled(),
			'tlsa_prereq_met'  => (bool) self::tlsa_cert_data_hex(),
			'tlsa_record_name' => self::tlsa_record_name(),
			'tlsa_record_value'=> self::tlsa_record_value(),
		);
	}

	// ── DNS health checks ─────────────────────────────────────────────────

	/**
	 * Run a health check for a single algorithm via DoH.
	 *
	 * @param  string $algo  'ed25519' | 'slhdsa' | 'ecdsa'
	 * @return array{ found: bool, key_match: bool, dnssec_ad: bool, raw_txt: string, error: string }
	 */
	public static function run_health_check( string $algo = 'ed25519' ): array {
		$result = array(
			'found'          => false,
			'key_match'      => false,
			'dnssec_ad'      => false,
			'dnssec_checked' => false, // true once a DoH response is successfully parsed
			'raw_txt'        => '',
			'error'          => '',
			'from_cache'     => false,
		);

		$expected_txt = self::expected_txt_value( $algo );
		if ( ! $expected_txt ) {
			$result['error'] = sprintf(
				/* translators: %s: algorithm name */
				__( 'No %s key is configured.', 'archiviomd' ),
				strtoupper( $algo )
			);
			return $result;
		}

		$record_name = self::dns_record_name( $algo );
		$doh_url     = add_query_arg(
			array( 'name' => $record_name, 'type' => 'TXT' ),
			self::doh_url()
		);

		$response = wp_remote_get( $doh_url, array(
			'headers' => array( 'Accept' => 'application/dns-json' ),
			'timeout' => 8,
		) );

		if ( is_wp_error( $response ) ) {
			$result['error'] = sprintf(
				/* translators: %s: error message */
				__( 'DNS-over-HTTPS request failed: %s', 'archiviomd' ),
				$response->get_error_message()
			);
			return $result;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			$result['error'] = __( 'DNS-over-HTTPS returned an unreadable response.', 'archiviomd' );
			return $result;
		}

		$result['dnssec_checked'] = true;
		$result['dnssec_ad']      = ! empty( $data['AD'] );

		// Extract p= value from the expected TXT string for comparison.
		$expected_p = '';
		if ( preg_match( '/(?:^|;\s*)p=([A-Za-z0-9+\/=]+)/', $expected_txt, $pm ) ) {
			$expected_p = $pm[1];
		}

		if ( ! empty( $data['Answer'] ) ) {
			foreach ( (array) $data['Answer'] as $rr ) {
				if ( empty( $rr['type'] ) || (int) $rr['type'] !== 16 ) {
					continue;
				}
				$txt = trim( $rr['data'] ?? '', '"' );
				if ( strpos( $txt, 'v=' . self::TXT_VERSION ) === false ) {
					continue;
				}
				$result['found']   = true;
				$result['raw_txt'] = $txt;

				if ( $expected_p && preg_match( '/(?:^|;\s*)p=([A-Za-z0-9+\/=]+)/', $txt, $m ) ) {
					$result['key_match'] = hash_equals( $expected_p, $m[1] );
				}
				break;
			}
		}

		if ( ! $result['found'] ) {
			$result['error'] = sprintf(
				/* translators: %s: DNS record name */
				__( 'No TXT record found at %s. Publish the record shown below and try again.', 'archiviomd' ),
				$record_name
			);
		} elseif ( ! $result['key_match'] ) {
			if ( self::is_rotation_mode() ) {
				$minutes = (int) ceil( self::rotation_elapsed_seconds() / 60 );
				$result['error'] = sprintf(
					/* translators: %d: minutes elapsed */
					__( 'Rotation in progress (%d min elapsed) — old TXT record still in DNS. This is expected during the TTL window. Update wp-config.php once the new record propagates, then remove the old record.', 'archiviomd' ),
					$minutes
				);
			} else {
				$result['error'] = __( 'TXT record found but the p= value does not match the configured key. Update the DNS record, or use rotation mode if you are mid-rotation.', 'archiviomd' );
			}
		}

		return $result;
	}

	/**
	 * Run health checks for ALL active algorithms and cache the combined result.
	 *
	 * @return array  Keyed by algorithm name.
	 */
	public static function run_all_health_checks(): array {
		$cached = get_transient( self::TRANSIENT_HEALTH );
		if ( is_array( $cached ) ) {
			foreach ( $cached as &$r ) {
				if ( is_array( $r ) ) {
					$r['from_cache'] = true;
				}
			}
			unset( $r );
			return $cached;
		}

		$results = array();
		foreach ( self::active_algorithms() as $algo ) {
			$results[ $algo ] = self::run_health_check( $algo );
		}

		set_transient( self::TRANSIENT_HEALTH, $results, self::TRANSIENT_TTL );
		return $results;
	}

	// ── TLSA (RFC 6698) ──────────────────────────────────────────────────

	/**
	 * Whether TLSA support is enabled by the administrator.
	 * Requires DANE to be enabled AND the ECDSA certificate to be configured.
	 */
	public static function is_tlsa_enabled(): bool {
		return (bool) get_option( self::OPTION_TLSA_ENABLED, false );
	}

	public static function set_tlsa_enabled( bool $enabled ): void {
		update_option( self::OPTION_TLSA_ENABLED, $enabled );
		delete_transient( self::TRANSIENT_HEALTH );
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
	}

	/**
	 * Return the configured TLSA port.
	 * Defaults to 443; override with ARCHIVIOMD_TLSA_PORT in wp-config.php.
	 */
	public static function tlsa_port(): string {
		if ( defined( 'ARCHIVIOMD_TLSA_PORT' ) ) {
			$p = (string) constant( 'ARCHIVIOMD_TLSA_PORT' );
			if ( ctype_digit( $p ) && (int) $p > 0 && (int) $p <= 65535 ) {
				return $p;
			}
		}
		return '443';
	}

	/**
	 * Return the configured TLSA protocol.
	 * Defaults to 'tcp'; override with ARCHIVIOMD_TLSA_PROTOCOL in wp-config.php.
	 */
	public static function tlsa_protocol(): string {
		if ( defined( 'ARCHIVIOMD_TLSA_PROTOCOL' ) ) {
			$proto = strtolower( (string) constant( 'ARCHIVIOMD_TLSA_PROTOCOL' ) );
			if ( in_array( $proto, array( 'tcp', 'udp', 'sctp' ), true ) ) {
				return $proto;
			}
		}
		return 'tcp';
	}

	/**
	 * Derive the TLSA DNS owner name for the configured port/protocol.
	 *
	 * Format: _<port>._<protocol>.<host>
	 * e.g.    _443._tcp.example.com
	 */
	public static function tlsa_record_name(): string {
		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );
		return sprintf( '_%s._%s.%s', self::tlsa_port(), self::tlsa_protocol(), $host );
	}

	/**
	 * Compute the TLSA certificate-data field for the ECDSA leaf certificate.
	 *
	 * We use:
	 *   Usage         3 — DANE-EE (trust anchor is the leaf cert itself)
	 *   Selector      1 — SubjectPublicKeyInfo (survives cert renewal)
	 *   Matching-type 1 — SHA-256
	 *
	 * Returns the hex-encoded SHA-256 of the SPKI DER, or '' if no cert.
	 */
	public static function tlsa_cert_data_hex(): string {
		if ( ! class_exists( 'MDSM_ECDSA_Signing' ) || ! function_exists( 'openssl_x509_read' ) ) {
			return '';
		}
		$cert_pem = MDSM_ECDSA_Signing::load_certificate_pem();
		if ( ! $cert_pem ) {
			return '';
		}
		$cert_res = openssl_x509_read( $cert_pem );
		if ( ! $cert_res ) {
			return '';
		}
		$pubkey_res = openssl_pkey_get_public( $cert_res );
		if ( ! $pubkey_res ) {
			return '';
		}
		// Export the SubjectPublicKeyInfo DER.
		// openssl_pkey_get_details returns the public key PEM; we strip headers to get DER.
		$details = openssl_pkey_get_details( $pubkey_res );
		$pub_pem = $details['key'] ?? '';
		if ( ! $pub_pem ) {
			return '';
		}
		$b64_raw = preg_replace( '/-----[^-]+-----|\\s/', '', $pub_pem );
		$spki_der = base64_decode( $b64_raw ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( ! $spki_der ) {
			return '';
		}
		return hash( 'sha256', $spki_der );
	}

	/**
	 * Build the full TLSA record value string as it should appear in DNS.
	 *
	 * Format: "<usage> <selector> <matching-type> <cert-data-hex>"
	 * e.g.:   "3 1 1 abcdef1234..."
	 *
	 * Returns '' if no ECDSA certificate is configured.
	 */
	public static function tlsa_record_value(): string {
		$hex = self::tlsa_cert_data_hex();
		if ( ! $hex ) {
			return '';
		}
		return sprintf( '%d %d %d %s', self::TLSA_USAGE, self::TLSA_SELECTOR, self::TLSA_MTYPE, $hex );
	}

	/**
	 * Run a TLSA health check via DNS-over-HTTPS (RFC 8484).
	 *
	 * Queries the TLSA record at _<port>._<protocol>.<host> (DNS type 52)
	 * and compares the certificate-data field against the configured ECDSA
	 * leaf certificate.
	 *
	 * @return array{
	 *   found:          bool,
	 *   cert_match:     bool,
	 *   dnssec_ad:      bool,
	 *   dnssec_checked: bool,
	 *   raw_value:      string,
	 *   error:          string,
	 *   from_cache:     bool
	 * }
	 */
	public static function run_tlsa_health_check(): array {
		$cached = get_transient( self::TRANSIENT_TLSA_HEALTH );
		if ( is_array( $cached ) ) {
			$cached['from_cache'] = true;
			return $cached;
		}

		$result = array(
			'found'          => false,
			'cert_match'     => false,
			'dnssec_ad'      => false,
			'dnssec_checked' => false,
			'raw_value'      => '',
			'error'          => '',
			'from_cache'     => false,
		);

		$expected_hex = self::tlsa_cert_data_hex();
		if ( ! $expected_hex ) {
			$result['error'] = __( 'No ECDSA certificate is configured. A leaf certificate is required for TLSA.', 'archiviomd' );
			return $result;
		}

		$record_name = self::tlsa_record_name();
		// DNS type 52 = TLSA. DoH JSON API accepts numeric types.
		$doh_url = add_query_arg(
			array( 'name' => $record_name, 'type' => '52' ),
			self::doh_url()
		);

		$response = wp_remote_get( $doh_url, array(
			'headers' => array( 'Accept' => 'application/dns-json' ),
			'timeout' => 8,
		) );

		if ( is_wp_error( $response ) ) {
			$result['error'] = sprintf(
				/* translators: %s: error message */
				__( 'DNS-over-HTTPS request failed: %s', 'archiviomd' ),
				$response->get_error_message()
			);
			return $result;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			$result['error'] = __( 'DNS-over-HTTPS returned an unreadable response.', 'archiviomd' );
			return $result;
		}

		$result['dnssec_checked'] = true;
		$result['dnssec_ad']      = ! empty( $data['AD'] );

		if ( ! empty( $data['Answer'] ) ) {
			foreach ( (array) $data['Answer'] as $rr ) {
				// Type 52 = TLSA
				if ( empty( $rr['type'] ) || (int) $rr['type'] !== 52 ) {
					continue;
				}

				// RFC 8005 / RFC 6698: DoH JSON presents TLSA rdata as a space-separated
				// string: "<usage> <selector> <matching-type> <cert-data-hex>"
				$raw = trim( $rr['data'] ?? '' );
				$parts = preg_split( '/\s+/', $raw );
				if ( count( $parts ) < 4 ) {
					continue;
				}

				$usage    = (int) $parts[0];
				$selector = (int) $parts[1];
				$mtype    = (int) $parts[2];
				$cert_hex = strtolower( implode( '', array_slice( $parts, 3 ) ) );

				// Only match records with our expected parameters.
				if ( $usage !== self::TLSA_USAGE || $selector !== self::TLSA_SELECTOR || $mtype !== self::TLSA_MTYPE ) {
					continue;
				}

				$result['found']     = true;
				$result['raw_value'] = $raw;
				$result['cert_match'] = hash_equals( strtolower( $expected_hex ), $cert_hex );
				break;
			}
		}

		if ( ! $result['found'] ) {
			$result['error'] = sprintf(
				/* translators: %s: DNS record name */
				__( 'No TLSA record (3 1 1) found at %s. Publish the record shown below and try again.', 'archiviomd' ),
				$record_name
			);
		} elseif ( ! $result['cert_match'] ) {
			$result['error'] = __( 'TLSA record found but the certificate-data hex does not match the configured ECDSA certificate. Update the DNS record.', 'archiviomd' );
		} elseif ( ! $result['dnssec_ad'] ) {
			$result['error'] = __( 'TLSA record matches but DNSSEC is not validated (AD flag absent). Enable DNSSEC on your zone — without it TLSA provides no security.', 'archiviomd' );
		}

		set_transient( self::TRANSIENT_TLSA_HEALTH, $result, self::TRANSIENT_TTL );
		return $result;
	}

	// ── JSON discovery endpoint ───────────────────────────────────────────

	/**
	 * Serve /.well-known/archiviomd-dns.json
	 *
	 * Machine-readable index of all active DANE records for external verifier
	 * tooling. No DANE module dependency required on the consumer side — any
	 * HTTP client can fetch this endpoint to discover DNS names to query.
	 */
	public static function serve_dns_json(): void {
		if ( ! self::is_enabled() ) {
			// Return a parseable 200 rather than an opaque 404 so verifiers can
			// distinguish "module disabled" from "wrong URL / server error".
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'Cache-Control: no-store' );
			echo wp_json_encode( array(
				'version' => self::TXT_VERSION,
				'site'    => get_site_url(),
				'enabled' => false,
			) ); // phpcs:ignore WordPress.Security.EscapeOutput
			exit;
		}

		$algos   = self::active_algorithms();
		$records = array();

		foreach ( $algos as $algo ) {
			$records[] = array(
				'algorithm' => $algo,
				'dns_name'  => self::dns_record_name( $algo ),
				'key_id'    => self::key_fingerprint( $algo ),
				'txt_value' => self::expected_txt_value( $algo ),
			);
		}

		$doc = array(
			'version'  => self::TXT_VERSION,
			'site'     => get_site_url(),
			'spec_url' => home_url( '/.well-known/' . self::SPEC_SLUG ),
			'records'  => $records,
		);

		// Include TLSA record in the discovery document when enabled.
		if ( self::is_tlsa_enabled() ) {
			$tlsa_value = self::tlsa_record_value();
			if ( $tlsa_value ) {
				$doc['tlsa'] = array(
					'dns_name'    => self::tlsa_record_name(),
					'record_type' => 'TLSA',
					'value'       => $tlsa_value,
					'usage'       => self::TLSA_USAGE,
					'selector'    => self::TLSA_SELECTOR,
					'mtype'       => self::TLSA_MTYPE,
					'cert_sha256' => self::tlsa_cert_data_hex(),
					'note'        => 'DANE-EE; SubjectPublicKeyInfo SHA-256; RFC 6698',
				);
			}
		}

		$json = wp_json_encode( $doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$etag = '"' . md5( $json ) . '"';

		// Conditional-request support — lets CDNs and proxies revalidate efficiently.
		$if_none_match = isset( $_SERVER['HTTP_IF_NONE_MATCH'] )
			? trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_IF_NONE_MATCH'] ) ) )
			: '';
		if ( $if_none_match && $if_none_match === $etag ) {
			status_header( 304 );
			exit;
		}

		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: public, max-age=' . self::dane_ttl() );
		header( 'ETag: ' . $etag );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s', time() ) . ' GMT' );
		header( 'X-Robots-Tag: noindex' );
		echo $json; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	/**
	 * Serve /.well-known/archiviomd-dns-spec.json
	 *
	 * Machine-readable specification for the amd1 TXT record format and the
	 * TLSA profile used by this plugin. Embedded in the discovery document as
	 * spec_url so that any verifier consuming archiviomd-dns.json can resolve
	 * the full format description without consulting external documentation.
	 *
	 * This endpoint is always served regardless of whether DANE is enabled —
	 * the spec describes the format, not a specific site's key configuration.
	 */
	public static function serve_dns_spec(): void {
		$spec = array(
			'spec'        => 'archiviomd-dns-v1',
			'description' => 'Machine-readable specification for the ArchivioMD DANE / DNS Key Corroboration record format (amd1). Verifiers can use this document to implement independent DNS-based key authentication without consulting external documentation.',
			'spec_url'    => home_url( '/.well-known/' . self::SPEC_SLUG ),
			'issued_by'   => get_site_url(),

			// ── TXT record format ───────────────────────────────────────────
			'txt_format'  => array(
				'description' => 'DNS TXT records in the amd1 format. Modelled on DKIM (RFC 6376) tag-value syntax. One record per algorithm, each at its own owner name.',
				'syntax'      => 'v=amd1; k=<algorithm>; [a=<param>;] p=<key-material>',
				'tags'        => array(
					'v' => array(
						'required'    => true,
						'value'       => 'amd1',
						'description' => 'Version tag. Must be the literal string "amd1". Records with any other version value must be ignored.',
					),
					'k' => array(
						'required'    => true,
						'values'      => array( 'ed25519', 'slh-dsa', 'ecdsa-p256', 'rsa' ),
						'description' => 'Algorithm identifier. Determines how the p= field is interpreted.',
					),
					'a' => array(
						'required'    => false,
						'applies_to'  => array( 'slh-dsa' ),
						'description' => 'Algorithm parameter. Required for slh-dsa; absent for all other algorithms.',
						'values'      => array( 'SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-128f', 'SLH-DSA-SHA2-192s', 'SLH-DSA-SHA2-256s' ),
					),
					'p' => array(
						'required'    => true,
						'description' => 'Key material or fingerprint encoded as base64. Interpretation depends on k= value — see algorithms below.',
					),
				),
			),

			// ── Per-algorithm DNS owner names and p= semantics ──────────────
			'algorithms'  => array(
				array(
					'id'           => 'ed25519',
					'dns_prefix'   => '_archiviomd._domainkey',
					'owner_name'   => '_archiviomd._domainkey.<host>',
					'example'      => '_archiviomd._domainkey.example.com. 3600 IN TXT "v=amd1; k=ed25519; p=<base64>"',
					'p_field'      => 'base64( raw 32-byte Ed25519 public key )',
					'verification' => 'Retrieve the public key bytes as base64_decode(p=). Verify the Ed25519 signature stored in _mdsm_ed25519_sig post meta against the canonical message using any sodium-compatible library. The public key is also available at /.well-known/ed25519-pubkey.txt as raw hex.',
				),
				array(
					'id'           => 'slh-dsa',
					'dns_prefix'   => '_archiviomd-slhdsa._domainkey',
					'owner_name'   => '_archiviomd-slhdsa._domainkey.<host>',
					'example'      => '_archiviomd-slhdsa._domainkey.example.com. 3600 IN TXT "v=amd1; k=slh-dsa; a=SLH-DSA-SHA2-128s; p=<base64>"',
					'p_field'      => 'base64( raw SLH-DSA public key bytes for the parameter set named in a= )',
					'a_field'      => 'SLH-DSA parameter set name per NIST FIPS 205. Verifier must use the matching parameter set.',
					'verification' => 'Retrieve the public key bytes as base64_decode(p=). Verify the SLH-DSA signature stored in _mdsm_slhdsa_sig post meta against the canonical message using any FIPS 205-compliant library (e.g. pyspx). The public key is also available at /.well-known/slhdsa-pubkey.txt as raw hex.',
				),
				array(
					'id'           => 'ecdsa-p256',
					'dns_prefix'   => '_archiviomd-ecdsa._domainkey',
					'owner_name'   => '_archiviomd-ecdsa._domainkey.<host>',
					'example'      => '_archiviomd-ecdsa._domainkey.example.com. 3600 IN TXT "v=amd1; k=ecdsa-p256; p=<base64>"',
					'p_field'      => 'base64( SHA-256( DER-encoded X.509 leaf certificate ) ) — i.e. the SHA-256 certificate fingerprint, base64-encoded',
					'verification' => 'Retrieve the leaf certificate from /.well-known/ecdsa-cert.pem. Compute SHA-256 of its DER form and compare base64-encoded against p= to confirm the DNS record covers the live certificate. Then verify the ECDSA P-256 signature stored in _mdsm_ecdsa_sig post meta (hex DER) against the canonical message using the certificate public key.',
				),
				array(
					'id'           => 'rsa',
					'dns_prefix'   => '_archiviomd-rsa._domainkey',
					'owner_name'   => '_archiviomd-rsa._domainkey.<host>',
					'example'      => '_archiviomd-rsa._domainkey.example.com. 3600 IN TXT "v=amd1; k=rsa; p=<base64>"',
					'p_field'      => 'base64( SHA-256( DER-encoded X.509 certificate ) ) when a certificate is configured, otherwise base64( SHA-256( DER-encoded SubjectPublicKeyInfo ) )',
					'verification' => 'Retrieve the public key from /.well-known/rsa-pubkey.pem. Compute SHA-256 of the DER form and compare base64-encoded against p=. Then verify the RSA signature stored in _mdsm_rsa_sig post meta against the canonical message using openssl dgst -sha256 -verify.',
				),
			),

			// ── TLSA profile ────────────────────────────────────────────────
			'tlsa_profile' => array(
				'rfc'          => 'RFC 6698',
				'description'  => 'DANE-EE TLSA record binding the ECDSA P-256 leaf certificate to the HTTPS service. Requires DNSSEC on the zone — without DNSSEC the record provides no security.',
				'owner_name'   => '_<port>._<protocol>.<host>',
				'default_owner'=> '_443._tcp.<host>',
				'usage'        => 3,
				'usage_name'   => 'DANE-EE',
				'usage_note'   => 'Trust anchor is the leaf certificate itself; no CA chain required.',
				'selector'     => 1,
				'selector_name'=> 'SPKI',
				'selector_note'=> 'SubjectPublicKeyInfo DER. Record survives certificate renewal as long as the key pair is unchanged.',
				'mtype'        => 1,
				'mtype_name'   => 'SHA-256',
				'cert_data'    => 'hex( SHA-256( SubjectPublicKeyInfo DER extracted from the ECDSA leaf certificate ) )',
				'example'      => '_443._tcp.example.com. 3600 IN TLSA 3 1 1 <spki-sha256-hex>',
				'verification' => 'Extract the SubjectPublicKeyInfo DER from the leaf certificate at /.well-known/ecdsa-cert.pem. Compute SHA-256 and compare in hex against the cert-data field of the TLSA record. The owner name port and protocol are configurable via ARCHIVIOMD_TLSA_PORT and ARCHIVIOMD_TLSA_PROTOCOL constants.',
			),

			// ── Canonical message format ────────────────────────────────────
			'canonical_message' => array(
				'description' => 'All signing algorithms (Ed25519, SLH-DSA, ECDSA P-256, RSA) sign the exact same canonical message bytes. The message is a newline-delimited UTF-8 string with no trailing newline.',
				'post_format' => implode( '\n', array(
					'mdsm-ed25519-v1',
					'{post_id}',
					'{post_title}',
					'{post_slug}',
					'{post_content_strip_tags}',
					'{post_date_gmt}',
				) ),
				'media_format' => implode( '\n', array(
					'mdsm-ed25519-media-v1',
					'{attachment_id}',
					'{filename}',
					'{filesize_bytes}',
					'{mime_type}',
					'{post_author_id}',
					'{post_date_gmt}',
				) ),
				'notes' => array(
					'post_content_strip_tags: WordPress wp_strip_all_tags() applied to post_content before signing.',
					'post_date_gmt: stored WordPress post_date_gmt value, format "Y-m-d H:i:s".',
					'The prefix "mdsm-ed25519-v1" is shared by all algorithms for historical reasons — it does not imply Ed25519 is the only signer.',
				),
			),

			// ── Discovery endpoint ──────────────────────────────────────────
			'discovery_endpoint' => array(
				'url'         => home_url( '/.well-known/archiviomd-dns.json' ),
				'description' => 'Lists all active TXT and TLSA records for this site. Cacheable; ETag and Cache-Control headers are set. Returns {"enabled":false} with no records when DANE Corroboration is disabled.',
				'fields'      => array(
					'version'  => 'amd1 — format version tag.',
					'site'     => 'Canonical site URL.',
					'spec_url' => 'URL of this document.',
					'records'  => 'Array of active TXT record objects, one per algorithm.',
					'tlsa'     => '(Optional) Active TLSA record object. Present only when TLSA is enabled and an ECDSA certificate is configured.',
				),
			),

			// ── Verification flow for external tooling ──────────────────────
			'verification_flow' => array(
				'step_1' => 'Fetch /.well-known/archiviomd-dns.json to obtain the list of active record names, expected TXT values, and (optionally) the TLSA record.',
				'step_2' => 'For each record in records[], query the dns_name over DNSSEC-validating DNS (DoH recommended, e.g. 1.1.1.1/dns-query?name=<dns_name>&type=TXT). Confirm the AD flag is set.',
				'step_3' => 'Compare the p= field from the live TXT record against the p= field in txt_value from the discovery document. They must match exactly.',
				'step_4' => 'Retrieve the public key material for the algorithm as described in algorithms[].verification above.',
				'step_5' => 'Verify the stored signature (from post meta or the verification file download) against the canonical message.',
				'step_6' => '(TLSA, optional) If tlsa is present in the discovery document, query the dns_name over DNSSEC-validating DNS with type=TLSA (52). Confirm the AD flag and compare the cert-data hex against tlsa.cert_sha256.',
				'dnssec_note' => 'Steps 2 and 6 depend on DNSSEC for security. Without DNSSEC validation (AD flag set by a validating resolver), DNS responses are unauthenticated and the corroboration provides no additional trust over the web server alone.',
			),
		);

		$json = wp_json_encode( $spec, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$etag = '"' . md5( $json ) . '"';

		$if_none_match = isset( $_SERVER['HTTP_IF_NONE_MATCH'] )
			? trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_IF_NONE_MATCH'] ) ) )
			: '';
		if ( $if_none_match && $if_none_match === $etag ) {
			status_header( 304 );
			exit;
		}

		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: public, max-age=86400' ); // spec changes rarely — 24 h
		header( 'ETag: ' . $etag );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s', time() ) . ' GMT' );
		header( 'X-Robots-Tag: noindex' );
		echo $json; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	// ── AJAX handlers ─────────────────────────────────────────────────────

	public function ajax_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$enabled = isset( $_POST['dane_enabled'] )
			&& sanitize_text_field( wp_unslash( $_POST['dane_enabled'] ) ) === 'true';

		if ( $enabled && ! self::is_prerequisite_met() ) {
			wp_send_json_error( array(
				'message' => esc_html__( 'Cannot enable DANE Corroboration: no signing key constants are defined in wp-config.php. At minimum, define ARCHIVIOMD_ED25519_PUBLIC_KEY.', 'archiviomd' ),
			) );
		}

		self::set_enabled( $enabled );

		// TLSA toggle — only allowed when DANE is on and an ECDSA cert exists.
		$tlsa_enabled = isset( $_POST['tlsa_enabled'] )
			&& sanitize_text_field( wp_unslash( $_POST['tlsa_enabled'] ) ) === 'true';
		if ( $tlsa_enabled && ( ! $enabled || ! self::tlsa_cert_data_hex() ) ) {
			$tlsa_enabled = false; // silently downgrade — client will see updated status
		}
		self::set_tlsa_enabled( $tlsa_enabled );

		$status = self::status();

		wp_send_json_success( array(
			'message'        => $enabled
				? esc_html__( 'DANE DNS Corroboration enabled.', 'archiviomd' )
				: esc_html__( 'DANE DNS Corroboration disabled.', 'archiviomd' ),
			'notice_level'   => $status['notice_level'],
			'notice_message' => wp_strip_all_tags( $status['notice_message'] ),
			'tlsa_enabled'   => $status['tlsa_enabled'],
		) );
	}

	public function ajax_tlsa_check(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		if ( ! self::is_tlsa_enabled() ) {
			wp_send_json_error( array( 'message' => esc_html__( 'TLSA is not enabled.', 'archiviomd' ) ) );
		}
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
		$result = self::run_tlsa_health_check();
		wp_send_json_success( $result );
	}

	public function ajax_health_check(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		delete_transient( self::TRANSIENT_HEALTH );
		delete_transient( self::TRANSIENT_TLSA_HEALTH );
		$results = self::run_all_health_checks();
		wp_send_json_success( $results );
	}

	public function ajax_start_rotation(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		self::start_rotation();
		wp_send_json_success( array(
			'message' => esc_html__( 'Rotation mode started. Publish the new TXT records alongside the existing ones, then wait one TTL period (3600 s) before updating wp-config.php.', 'archiviomd' ),
			'started' => time(),
		) );
	}

	public function ajax_finish_rotation(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		self::finish_rotation();
		wp_send_json_success( array(
			'message' => esc_html__( 'Rotation complete. Remove the old TXT records from DNS after one more TTL period.', 'archiviomd' ),
		) );
	}

	public function ajax_dismiss_notice(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error();
		}
		delete_option( self::OPTION_CRON_NOTICE );
		wp_send_json_success();
	}
}
