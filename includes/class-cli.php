<?php
/**
 * ArchivioMD WP-CLI Commands
 *
 * Registered only when WP-CLI is active — completely invisible at runtime.
 *
 * Usage:
 *   wp archiviomd process-queue
 *   wp archiviomd anchor-post <post_id>
 *   wp archiviomd verify <post_id>
 *   wp archiviomd prune-log [--days=<days>]
 *   wp archiviomd dane-check [--enable] [--disable] [--rotation] [--finish-rotation] [--porcelain]
 *
 * @package ArchivioMD
 * @since   1.6.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * Manage ArchivioMD anchoring and verification from the command line.
 */
class MDSM_CLI_Commands extends WP_CLI_Command {

	/**
	 * Process all due anchor queue jobs immediately (same as cron).
	 *
	 * ## EXAMPLES
	 *
	 *   wp archiviomd process-queue
	 *
	 * @when after_wp_load
	 */
	public function process_queue() {
		$anchoring = MDSM_External_Anchoring::get_instance();

		if ( ! $anchoring->is_enabled() ) {
			WP_CLI::error( 'External anchoring is not enabled. Configure a provider first.' );
		}

		$before = MDSM_Anchor_Queue::count();
		WP_CLI::log( "Queue has {$before} pending job(s). Processing now..." );

		$anchoring->process_queue();

		$after = MDSM_Anchor_Queue::count();
		$done  = $before - $after;
		WP_CLI::success( "Processed {$done} job(s). {$after} job(s) remaining (retry or empty)." );
	}

	/**
	 * Queue a specific post for anchoring immediately.
	 *
	 * ## OPTIONS
	 *
	 * <post_id>
	 * : The WordPress post ID to anchor.
	 *
	 * ## EXAMPLES
	 *
	 *   wp archiviomd anchor-post 42
	 *
	 * @when after_wp_load
	 */
	public function anchor_post( $args ) {
		$post_id = (int) $args[0];

		if ( ! $post_id ) {
			WP_CLI::error( 'Please provide a valid post ID.' );
		}

		$post = get_post( $post_id );
		if ( ! $post ) {
			WP_CLI::error( "Post {$post_id} not found." );
		}

		$anchoring = MDSM_External_Anchoring::get_instance();

		if ( ! $anchoring->is_enabled() ) {
			WP_CLI::error( 'External anchoring is not enabled. Configure a provider first.' );
		}

		// Re-use existing hash or compute fresh.
		$stored_packed = get_post_meta( $post_id, '_archivio_post_hash', true );

		if ( ! empty( $stored_packed ) ) {
			$unpacked    = MDSM_Hash_Helper::unpack( $stored_packed );
			$hash_result = array(
				'packed'           => $stored_packed,
				'hash'             => $unpacked['hash'],
				'algorithm'        => $unpacked['algorithm'],
				'hmac_unavailable' => false,
			);
			WP_CLI::log( "Using existing hash ({$unpacked['algorithm']}): {$unpacked['hash']}" );
		} else {
			$archivio    = MDSM_Archivio_Post::get_instance();
			$canonical   = $archivio->canonicalize_content(
				$post->post_content,
				$post_id,
				$post->post_author
			);
			$hash_result = MDSM_Hash_Helper::compute_packed( $canonical );
			$unpacked    = MDSM_Hash_Helper::unpack( $hash_result['packed'] );
			$hash_result['hash']      = $unpacked['hash'];
			$hash_result['algorithm'] = $unpacked['algorithm'];
			WP_CLI::log( "Computed fresh hash ({$unpacked['algorithm']}): {$unpacked['hash']}" );
		}

		// Clear dedup transient so this forced queue call is never skipped.
		$dedup_key = 'mdsm_anchor_q_' . $post_id . '_' . substr( md5( (string) $stored_packed ), 0, 8 );
		delete_transient( $dedup_key );

		$job_id = $anchoring->queue_post_anchor( $post_id, $hash_result );

		if ( $job_id ) {
			WP_CLI::success( "Post {$post_id} queued for anchoring. Job ID: {$job_id}" );
		} else {
			WP_CLI::warning( "Post {$post_id} could not be queued (queue may be full or provider disabled)." );
		}
	}

	/**
	 * Verify the stored hash for a post against its current content.
	 *
	 * ## OPTIONS
	 *
	 * <post_id>
	 * : The WordPress post ID to verify.
	 *
	 * ## EXAMPLES
	 *
	 *   wp archiviomd verify 42
	 *
	 * @when after_wp_load
	 */
	public function verify( $args ) {
		$post_id = (int) $args[0];

		if ( ! $post_id ) {
			WP_CLI::error( 'Please provide a valid post ID.' );
		}

		$archivio = MDSM_Archivio_Post::get_instance();
		$result   = $archivio->verify_hash( $post_id );

		if ( false === $result['stored_hash'] ) {
			WP_CLI::warning( "Post {$post_id}: no hash stored. Run anchor-post to queue it." );
			return;
		}

		$status = $result['verified'] ? 'PASSED' : 'FAILED';
		$color  = $result['verified'] ? '%G' : '%R';

		WP_CLI::log( "Post ID:    {$post_id}" );
		WP_CLI::log( "Algorithm:  {$result['algorithm']}" );
		WP_CLI::log( "Mode:       {$result['mode']}" );
		WP_CLI::log( "Stored:     {$result['stored_hash']}" );
		WP_CLI::log( "Current:    " . ( $result['current_hash'] ?: '(could not compute)' ) );
		WP_CLI::log( WP_CLI::colorize( "{$color}Verification: {$status}%n" ) );

		// ── Ed25519 signature status ──────────────────────────────────────
		if ( class_exists( 'MDSM_Ed25519_Signing' ) && MDSM_Ed25519_Signing::is_mode_enabled() ) {
			$ed_result = MDSM_Ed25519_Signing::verify( $post_id );
			if ( is_wp_error( $ed_result ) ) {
				WP_CLI::log( WP_CLI::colorize( '%yEd25519:      ' . $ed_result->get_error_message() . '%n' ) );
			} else {
				$ed_color  = $ed_result['valid'] ? '%G' : '%R';
				$ed_status = $ed_result['valid'] ? 'VALID' : 'INVALID';
				WP_CLI::log( WP_CLI::colorize( "{$ed_color}Ed25519:      {$ed_status}%n" ) );
			}
		}

		// ── SLH-DSA signature status ──────────────────────────────────────
		if ( class_exists( 'MDSM_SLHDSA_Signing' ) && MDSM_SLHDSA_Signing::is_mode_enabled() ) {
			$slh_result = MDSM_SLHDSA_Signing::verify_post( $post_id );
			if ( is_wp_error( $slh_result ) ) {
				WP_CLI::log( WP_CLI::colorize( '%ySLH-DSA:      ' . $slh_result->get_error_message() . '%n' ) );
			} else {
				$slh_color  = $slh_result['valid'] ? '%G' : '%R';
				$slh_status = $slh_result['valid'] ? 'VALID' : 'INVALID';
				$slh_param  = $slh_result['param'] ?? MDSM_SLHDSA_Signing::get_param();
				WP_CLI::log( WP_CLI::colorize( "{$slh_color}SLH-DSA:      {$slh_status} ({$slh_param})%n" ) );
			}
		}

		// ── ECDSA P-256 signature status ──────────────────────────────────
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::is_mode_enabled() ) {
			$ecdsa_result = MDSM_ECDSA_Signing::verify( $post_id );
			if ( is_wp_error( $ecdsa_result ) ) {
				WP_CLI::log( WP_CLI::colorize( '%yECDSA P-256:  ' . $ecdsa_result->get_error_message() . '%n' ) );
			} else {
				$ecdsa_color  = $ecdsa_result['valid'] ? '%G' : '%R';
				$ecdsa_status = $ecdsa_result['valid'] ? 'VALID' : 'INVALID';
				WP_CLI::log( WP_CLI::colorize( "{$ecdsa_color}ECDSA P-256:  {$ecdsa_status}%n" ) );
			}
		}

		// ── RSA compatibility signature status ────────────────────────────
		if ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::is_mode_enabled() ) {
			$rsa_sig = get_post_meta( $post_id, MDSM_RSA_Signing::META_SIG, true );
			if ( $rsa_sig ) {
				$rsa_result = MDSM_RSA_Signing::verify( $post_id );
				if ( is_wp_error( $rsa_result ) ) {
					WP_CLI::log( WP_CLI::colorize( '%yRSA:          ' . $rsa_result->get_error_message() . '%n' ) );
				} else {
					$rsa_color  = $rsa_result['valid'] ? '%G' : '%R';
					$rsa_status = $rsa_result['valid'] ? 'VALID' : 'INVALID';
					$rsa_scheme = get_post_meta( $post_id, MDSM_RSA_Signing::META_SCHEME, true ) ?: MDSM_RSA_Signing::get_scheme();
					WP_CLI::log( WP_CLI::colorize( "{$rsa_color}RSA:          {$rsa_status} ({$rsa_scheme})%n" ) );
				}
			} else {
				WP_CLI::log( WP_CLI::colorize( '%yRSA:          no signature stored%n' ) );
			}
		}

		// ── CMS / PKCS#7 signature status ─────────────────────────────────
		if ( class_exists( 'MDSM_CMS_Signing' ) && MDSM_CMS_Signing::is_mode_enabled() ) {
			$cms_sig = get_post_meta( $post_id, MDSM_CMS_Signing::META_SIG, true );
			if ( $cms_sig ) {
				$cms_result = MDSM_CMS_Signing::verify( $post_id );
				if ( is_wp_error( $cms_result ) ) {
					WP_CLI::log( WP_CLI::colorize( '%yCMS/PKCS#7:   ' . $cms_result->get_error_message() . '%n' ) );
				} else {
					$cms_color  = $cms_result['valid'] ? '%G' : '%R';
					$cms_status = $cms_result['valid'] ? 'VALID' : 'INVALID';
					WP_CLI::log( WP_CLI::colorize( "{$cms_color}CMS/PKCS#7:   {$cms_status}%n" ) );
				}
			} else {
				WP_CLI::log( WP_CLI::colorize( '%yCMS/PKCS#7:   no signature stored%n' ) );
			}
		}

		// ── JSON-LD / W3C Data Integrity proof status ──────────────────────
		if ( class_exists( 'MDSM_JSONLD_Signing' ) && MDSM_JSONLD_Signing::is_mode_enabled() ) {
			$proof = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_PROOF, true );
			if ( $proof ) {
				$jsonld_result = MDSM_JSONLD_Signing::verify( $post_id );
				if ( is_wp_error( $jsonld_result ) ) {
					WP_CLI::log( WP_CLI::colorize( '%yJSON-LD:      ' . $jsonld_result->get_error_message() . '%n' ) );
				} else {
					$jsonld_color  = $jsonld_result['valid'] ? '%G' : '%R';
					$jsonld_status = $jsonld_result['valid'] ? 'VALID' : 'INVALID';
					$suite = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_SUITE, true ) ?: 'unknown';
					WP_CLI::log( WP_CLI::colorize( "{$jsonld_color}JSON-LD:      {$jsonld_status} ({$suite})%n" ) );
				}
			} else {
				WP_CLI::log( WP_CLI::colorize( '%yJSON-LD:      no proof stored%n' ) );
			}
		}

		if ( ! $result['verified'] ) {
			if ( $result['hmac_key_missing'] ) {
				WP_CLI::warning( 'HMAC key (ARCHIVIOMD_HMAC_KEY) is not defined in wp-config.php.' );
			}
			WP_CLI::halt( 1 );
		}
	}

	/**
	 * Check the DANE / DNS TXT records for all active signing keys.
	 *
	 * Queries the configured DNS-over-HTTPS resolver for each active algorithm,
	 * validates the p= field against the configured key, and reports the DNSSEC
	 * AD flag. Exits with code 1 if any check fails (unless mid-rotation).
	 *
	 * ## OPTIONS
	 *
	 * [--algo=<algo>]
	 * : Limit check to a specific algorithm: ed25519, slhdsa, ecdsa, or rsa.
	 *
	 * [--enable]
	 * : Enable DANE Corroboration (requires at least one key constant to be defined).
	 *
	 * [--disable]
	 * : Disable DANE Corroboration.
	 *
	 * [--rotation]
	 * : Start key-rotation mode.
	 *
	 * [--finish-rotation]
	 * : Exit key-rotation mode.
	 *
	 * [--porcelain]
	 * : Output machine-readable lines per algorithm:
	 *   "algo=ed25519 found=1 match=1 dnssec=1 dnssec_checked=1 fingerprint=abc123"
	 *   For TLSA: "algo=tlsa found=1 match=1 dnssec=1 dnssec_checked=1 fingerprint=-"
	 *
	 * [--tlsa]
	 * : Also run the TLSA health check (requires TLSA to be enabled and an ECDSA cert).
	 *
	 * ## EXAMPLES
	 *
	 *   wp archiviomd dane-check
	 *   wp archiviomd dane-check --algo=ed25519
	 *   wp archiviomd dane-check --porcelain
	 *   wp archiviomd dane-check --tlsa
	 *   wp archiviomd dane-check --enable
	 *   wp archiviomd dane-check --disable
	 *   wp archiviomd dane-check --rotation
	 *   wp archiviomd dane-check --finish-rotation
	 *
	 * @when after_wp_load
	 */
	public function dane_check( $args, $assoc_args ) {
		if ( ! class_exists( 'MDSM_DANE_Corroboration' ) ) {
			WP_CLI::error( 'DANE module is not loaded. Ensure class-dane-corroboration.php is present.' );
		}

		// Handle enable / disable before anything else.
		if ( isset( $assoc_args['enable'] ) ) {
			if ( ! MDSM_DANE_Corroboration::is_prerequisite_met() ) {
				WP_CLI::error( 'Cannot enable DANE Corroboration: no signing key constants are defined in wp-config.php.' );
			}
			MDSM_DANE_Corroboration::set_enabled( true );
			WP_CLI::success( 'DANE Corroboration enabled.' );
			return;
		}

		if ( isset( $assoc_args['disable'] ) ) {
			MDSM_DANE_Corroboration::set_enabled( false );
			WP_CLI::success( 'DANE Corroboration disabled.' );
			return;
		}

		// Handle rotation mode transitions first.
		if ( isset( $assoc_args['rotation'] ) ) {
			MDSM_DANE_Corroboration::start_rotation();
			WP_CLI::success( 'Rotation mode started. Publish the new TXT records alongside the existing ones, then wait one TTL period (3600 s) before updating wp-config.php.' );
			return;
		}

		if ( isset( $assoc_args['finish-rotation'] ) ) {
			MDSM_DANE_Corroboration::finish_rotation();
			WP_CLI::success( 'Rotation mode finished. Remove the old TXT records from DNS after one more TTL period.' );
			return;
		}

		if ( ! MDSM_DANE_Corroboration::is_prerequisite_met() ) {
			WP_CLI::error( 'No signing key constants are defined in wp-config.php. Cannot check DNS records.' );
		}

		$porcelain = isset( $assoc_args['porcelain'] );
		$rotation  = MDSM_DANE_Corroboration::is_rotation_mode();
		$doh_url   = MDSM_DANE_Corroboration::doh_url();

		// Determine which algorithms to check.
		if ( isset( $assoc_args['algo'] ) ) {
			$algos = array( sanitize_key( $assoc_args['algo'] ) );
		} else {
			$algos = MDSM_DANE_Corroboration::active_algorithms();
		}

		if ( empty( $algos ) ) {
			WP_CLI::error( 'No active signing keys found to check.' );
		}

		if ( ! $porcelain ) {
			WP_CLI::log( "Resolver:  {$doh_url}" );
			if ( $rotation ) {
				$elapsed = MDSM_DANE_Corroboration::rotation_elapsed_seconds();
				WP_CLI::log( WP_CLI::colorize( '%yRotation mode active (' . (int) ceil( $elapsed / 60 ) . ' min elapsed)%n' ) );
			}
			WP_CLI::log( '' );
		}

		// Bust transients so we always get live results from CLI.
		delete_transient( 'archiviomd_dane_health' );
		delete_transient( 'archiviomd_dane_tlsa_health' );

		$ok  = WP_CLI::colorize( '%G✓%n' );
		$err = WP_CLI::colorize( '%R✗%n' );
		$wrn = WP_CLI::colorize( '%y⚠%n' );

		$any_failure  = false;
		$dnssec_warns = array();

		foreach ( $algos as $algo ) {
			$result      = MDSM_DANE_Corroboration::run_health_check( $algo );
			$fingerprint = MDSM_DANE_Corroboration::key_fingerprint( $algo );
			$record_name = MDSM_DANE_Corroboration::dns_record_name( $algo );

			$is_rotation_mismatch = $rotation && $result['found'] && ! $result['key_match'];

			if ( $porcelain ) {
				WP_CLI::log( sprintf(
					'algo=%s found=%d match=%d dnssec=%d dnssec_checked=%d fingerprint=%s',
					$algo,
					(int) $result['found'],
					(int) $result['key_match'],
					(int) $result['dnssec_ad'],
					(int) ( $result['dnssec_checked'] ?? false ),
					$fingerprint ?: 'n/a'
				) );
			} else {
				WP_CLI::log( WP_CLI::colorize( "%B── {$algo} ──%n" ) );
				WP_CLI::log( "  Record:     {$record_name}" );
				WP_CLI::log( sprintf( '  Found:      %s', $result['found']     ? $ok  : $err ) );
				WP_CLI::log( sprintf( '  Key match:  %s', $result['key_match'] ? $ok  : ( $is_rotation_mismatch ? $wrn : $err ) ) );
				WP_CLI::log( sprintf( '  DNSSEC AD:  %s', $result['dnssec_ad'] ? $ok  : $wrn ) );
				if ( $fingerprint ) {
					WP_CLI::log( "  Key ID:     {$fingerprint}" );
				}
				if ( $result['error'] ) {
					WP_CLI::log( WP_CLI::colorize( "  %y{$result['error']}%n" ) );
				}
				WP_CLI::log( '' );
			}

			if ( ! $result['found'] || ( ! $result['key_match'] && ! $is_rotation_mismatch ) ) {
				$any_failure = true;
			}
			if ( ! $result['dnssec_ad'] ) {
				$dnssec_warns[] = $algo;
			}
		}

		// ── TLSA check ────────────────────────────────────────────────────
		if ( isset( $assoc_args['tlsa'] ) ) {
			if ( ! MDSM_DANE_Corroboration::is_tlsa_enabled() ) {
				WP_CLI::warning( 'TLSA is not enabled. Enable it in the admin UI or run without --tlsa.' );
			} elseif ( ! MDSM_DANE_Corroboration::tlsa_cert_data_hex() ) {
				WP_CLI::warning( 'TLSA: no ECDSA certificate configured.' );
			} else {
				$tlsa        = MDSM_DANE_Corroboration::run_tlsa_health_check();
				$tlsa_name   = MDSM_DANE_Corroboration::tlsa_record_name();
				$tlsa_value  = MDSM_DANE_Corroboration::tlsa_record_value();

				if ( $porcelain ) {
					WP_CLI::log( sprintf(
						'algo=tlsa found=%d match=%d dnssec=%d dnssec_checked=%d fingerprint=-',
						(int) $tlsa['found'],
						(int) $tlsa['cert_match'],
						(int) $tlsa['dnssec_ad'],
						(int) ( $tlsa['dnssec_checked'] ?? false )
					) );
				} else {
					WP_CLI::log( WP_CLI::colorize( '%B── TLSA (RFC 6698) ──%n' ) );
					WP_CLI::log( "  Record:     {$tlsa_name}" );
					WP_CLI::log( "  Expected:   {$tlsa_value}" );
					WP_CLI::log( sprintf( '  Found:      %s', $tlsa['found']      ? $ok  : $err ) );
					WP_CLI::log( sprintf( '  Cert match: %s', $tlsa['cert_match'] ? $ok  : $err ) );
					WP_CLI::log( sprintf( '  DNSSEC AD:  %s', $tlsa['dnssec_ad']  ? $ok  : $wrn ) );
					if ( $tlsa['error'] ) {
						WP_CLI::log( WP_CLI::colorize( "  %y{$tlsa['error']}%n" ) );
					}
					WP_CLI::log( '' );
				}

				if ( ! $tlsa['found'] || ! $tlsa['cert_match'] ) {
					$any_failure = true;
				}
				if ( $tlsa['dnssec_checked'] && ! $tlsa['dnssec_ad'] ) {
					$dnssec_warns[] = 'tlsa';
				}
			}
		}

		if ( $porcelain ) {
			if ( $any_failure ) {
				WP_CLI::halt( 1 );
			}
			return;
		}

		if ( $any_failure ) {
			WP_CLI::halt( 1 );
		}

		if ( ! empty( $dnssec_warns ) ) {
			WP_CLI::warning( 'DNSSEC not validated for: ' . implode( ', ', $dnssec_warns ) . '. Enable DNSSEC at your registrar/DNS provider.' );
		} else {
			WP_CLI::success( 'All DANE checks passed.' );
		}
	}
	public function prune_log( $args, $assoc_args ) {
		global $wpdb;

		$anchoring = MDSM_External_Anchoring::get_instance();
		$settings  = $anchoring->get_settings();

		$days = isset( $assoc_args['days'] )
			? max( 1, (int) $assoc_args['days'] )
			: (int) $settings['log_retention_days'];

		if ( $days <= 0 ) {
			WP_CLI::error( 'Retention is set to 0 (keep forever). Pass --days=<n> to override.' );
		}

		$table_name = MDSM_Anchor_Log::get_table_name();
		$cutoff     = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		$count_before = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table_name} WHERE created_at < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$cutoff
			)
		);

		$count_after  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$deleted      = $count_before - $count_after;

		WP_CLI::success( "Pruned {$deleted} log entries older than {$days} days. {$count_after} entries remaining." );
	}
}

WP_CLI::add_command( 'archiviomd', 'MDSM_CLI_Commands' );
