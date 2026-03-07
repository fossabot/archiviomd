<?php
/**
 * Canary Token – Steganographic Content Fingerprinting
 *
 * Twelve encoding channels across two resilience layers:
 *
 * ── Unicode layer (strips on OCR / retyping) ────────────────────────────────
 *   Ch.1  Zero-width chars (U+200B / U+200C)   Sequential; publicly decodable.
 *   Ch.2  Thin-space variants (U+2009)          Key-derived positions.
 *   Ch.3  Apostrophe variants (U+2019)          Key-derived positions.
 *   Ch.4  Soft hyphens (U+00AD)                Key-derived intra-word positions.
 *
 * ── Semantic layer (survives OCR, retyping, Unicode normalisation) ───────────
 *   Ch.5  Contraction encoding    "don't" ↔ "do not"   Key-derived positions.
 *   Ch.6  Synonym substitution    "start"  ↔ "begin"    Key-derived positions.
 *   Ch.7  Punctuation choice      Oxford comma; em-dash ↔ parentheses.
 *         Opt-in. Two sub-channels unified into one slot list.
 *   Ch.8  Spelling variants       "organise" ↔ "organize", "colour" ↔ "color".
 *         Opt-in. 60+ British/American pairs; same engine as Ch.6.
 *   Ch.9  Hyphenation choices     "email" ↔ "e-mail", "online" ↔ "on-line".
 *         Opt-in. Position-independent compound pairs only (safe, no POS needed).
 *   Ch.10 Number / date style     "1,000" ↔ "1000"; "10 percent" ↔ "10%";
 *         "first" ↔ "1st". Opt-in. Custom slot collector, form0/form1 model.
 *   Ch.11 Punctuation style II    Em-dash spacing "word—word" ↔ "word — word";
 *         comma-before-too "it too" ↔ "it, too"; introductory-clause comma
 *         "In 2020 the" ↔ "In 2020, the". Three sub-channels, unified slot list.
 *   Ch.12 Citation / title style  Attribution colon "said:" ↔ "said"; title
 *         italics <em>The Times</em> ↔ "The Times". High-density on journalism
 *         and academic content.
 *
 * ── Payload (14 bytes / 112 bits) ───────────────────────────────────────────
 *   [0-3]  post_id    uint32 big-endian
 *   [4-7]  timestamp  uint32 big-endian (Unix epoch)
 *   [8-13] HMAC-SHA256(key, header)[0:6]  — 48-bit MAC
 *
 * Each bit is encoded REDUNDANCY (3) times per channel; majority-vote
 * corrects single-copy corruption per redundancy group.
 *
 * @package ArchivioMD
 * @since   1.8.0  (ch.1-4)
 * @since   1.9.0  (ch.5-6)
 * @since   1.10.0 (ch.7, URL decoder, DMCA generator)
 * @since   1.11.0 (ch.8 spelling variants, ch.9 hyphenation, ch.10 number style)
 * @since   1.11.0 (ch.11 punctuation style II, ch.12 citation/title style)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_Canary_Token {

	private static $instance = null;

	// Payload v1 (legacy) — 14 bytes / 112 bits
	const PAYLOAD_BYTES_V1 = 14;
	const PAYLOAD_BITS_V1  = 112;

	// Payload v2 — 17 bytes / 136 bits  (version byte + post_id + timestamp + 64-bit MAC)
	const PAYLOAD_BYTES_V2  = 17;
	const PAYLOAD_BITS_V2   = 136;
	const PAYLOAD_VERSION_2 = 0x02;

	// Legacy aliases — remain for any direct static references in channel helpers
	const PAYLOAD_BYTES = 14;
	const PAYLOAD_BITS  = 112;

	const REDUNDANCY    = 3;

	// Ch.1 – zero-width
	const ZW_ZERO = "\xE2\x80\x8B";
	const ZW_ONE  = "\xE2\x80\x8C";
	// Ch.2 – spaces
	const SP_REGULAR = "\x20";
	const SP_THIN    = "\xE2\x80\x89";
	// Ch.3 – apostrophes
	const APOS_STRAIGHT = "\x27";
	const APOS_CURLY    = "\xE2\x80\x99";
	// Ch.4 – soft hyphens
	const SOFT_HYPHEN     = "\xC2\xAD";
	const MIN_WORD_LENGTH = 6;
	// Ch.7 – em-dash (U+2014)
	const EM_DASH = "\xE2\x80\x94";

	private static $SEMANTIC_SKIP_TAGS = array(
		'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
		'script', 'style', 'a', 'kbd', 'samp', 'var', 'tt',
	);

	// =========================================================================

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->init_hooks();
	}

	private function init_hooks() {
		// Migrate legacy readable option keys to obfuscated keys on first load.
		self::migrate_option_keys();

		if ( self::cget( 'enabled', false  ) ) {
			// HTML layer — theme output, feeds
			add_filter( 'the_content',      array( $this, 'inject_canary' ), 99 );
			add_filter( 'the_excerpt',      array( $this, 'inject_canary' ), 99 );
			add_filter( 'the_content_feed', array( $this, 'inject_canary' ), 99 );
			// REST API layer — programmatic consumers
			add_filter( 'rest_prepare_post',       array( $this, 'inject_canary_rest' ), 99, 3 );
			add_filter( 'rest_prepare_page',       array( $this, 'inject_canary_rest' ), 99, 3 );
			add_filter( 'rest_prepare_attachment', array( $this, 'inject_canary_rest' ), 99, 3 );
		}
		if ( is_admin() ) {
			add_action( 'admin_menu',            array( $this, 'add_admin_menu' ), 25 );
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
			add_action( 'admin_notices',         array( $this, 'key_health_admin_notice' ) );
			add_action( 'admin_notices',         array( $this, 'cache_health_admin_notice' ) );
		}
		add_action( 'wp_ajax_archivio_canary_save_settings',    array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_archivio_canary_decode',           array( $this, 'ajax_decode' ) );
		add_action( 'wp_ajax_archivio_canary_decode_url',       array( $this, 'ajax_decode_url' ) );
		add_action( 'wp_ajax_archivio_canary_save_dmca',        array( $this, 'ajax_save_dmca_contact' ) );
		add_action( 'wp_ajax_archivio_canary_dismiss_key_warn', array( $this, 'ajax_dismiss_key_warning' ) );
		add_action( 'wp_ajax_archivio_fallback_key_dismiss',    array( $this, 'ajax_dismiss_fallback_key_notice' ) );
		add_action( 'wp_ajax_archivio_canary_fetch_log',            array( $this, 'ajax_fetch_log' ) );
		add_action( 'wp_ajax_archivio_canary_clear_log',            array( $this, 'ajax_clear_log' ) );
		add_action( 'wp_ajax_archivio_canary_brute_force_decode',   array( $this, 'ajax_brute_force_decode' ) );
		add_action( 'wp_ajax_archivio_canary_brute_force_candidates', array( $this, 'ajax_brute_force_candidates' ) );
		add_action( 'wp_ajax_archivio_canary_download_evidence',      array( $this, 'ajax_download_evidence' ) );
		add_action( 'wp_ajax_archivio_canary_restamp_all',            array( $this, 'ajax_restamp_all' ) );
		add_action( 'wp_ajax_archivio_canary_dismiss_cache_notice',   array( $this, 'ajax_dismiss_cache_notice' ) );
		add_action( self::CACHE_CHECK_CRON_HOOK,                      array( $this, 'run_cache_health_check' ) );
		add_action( 'rest_api_init', array( $this, 'register_rest_route' ) );
		// Audit trail: log any change to the per-post opt-out meta key
		add_action( 'added_post_meta',   array( $this, 'audit_canary_disabled_meta' ), 10, 4 );
		add_action( 'updated_post_meta',  array( $this, 'audit_canary_disabled_meta' ), 10, 4 );
		add_action( 'deleted_post_meta',  array( $this, 'audit_canary_disabled_meta' ), 10, 4 );
		// Coverage meta box on post edit screen
		add_action( 'add_meta_boxes', array( $this, 'register_coverage_meta_box' ) );

		// Key health: only needed in admin context — skip all front-end page loads
		if ( is_admin() ) {
			$this->maybe_check_key_health();
		}
	}

	// =========================================================================
	// ADMIN
	// =========================================================================

	public function add_admin_menu() {
		add_submenu_page( 'archiviomd', __( 'Canary Tokens', 'archiviomd' ),
			__( 'Canary Tokens', 'archiviomd' ), 'manage_options',
			'archivio-canary', array( $this, 'render_admin_page' ) );
	}

	public function enqueue_admin_assets( $hook ) {
		if ( strpos( $hook, 'archivio-canary' ) === false ) { return; }
		wp_enqueue_style( 'archivio-post-admin',
			MDSM_PLUGIN_URL . 'assets/css/archivio-post-admin.css', array(), MDSM_VERSION );
	}

	public function render_admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'archiviomd' ) );
		}
		require_once MDSM_PLUGIN_DIR . 'admin/canary-token-page.php';
	}

	// =========================================================================
	// KEY
	// =========================================================================

	private function get_key() {
		// Require the same 32-character minimum as MDSM_Hash_Helper::HMAC_KEY_MIN_LENGTH
		// so both modules agree on what constitutes a valid key and the admin UI
		// does not show conflicting "accepted / weak" signals for 16-31 char keys.
		if ( defined( 'ARCHIVIOMD_HMAC_KEY' ) && strlen( ARCHIVIOMD_HMAC_KEY ) >= 32 ) {
			return ARCHIVIOMD_HMAC_KEY;
		}
		// Fallback: key derived from wp_salt('auth').
		// WARNING: wp_salt() can change without plugin involvement — e.g. when
		// an admin regenerates WordPress secret keys, or a host migrates the site
		// and regenerates wp-config.php. When that happens all previously embedded
		// fingerprints silently become unverifiable. The admin notice surfaced by
		// key_health_admin_notice() will fire, but it will incorrectly say the user
		// changed ARCHIVIOMD_HMAC_KEY. Defining the constant explicitly is strongly
		// recommended; see the settings page for instructions.
		return hash_hmac( 'sha256', get_site_url(), wp_salt( 'auth' ) );
	}

	/**
	 * Return true when the plugin is relying on the volatile wp_salt fallback
	 * rather than an explicitly defined ARCHIVIOMD_HMAC_KEY constant.
	 *
	 * Used by the settings page to display a persistent security advisory.
	 *
	 * @return bool
	 */
	public static function is_using_fallback_key() {
		return ! ( defined( 'ARCHIVIOMD_HMAC_KEY' ) && strlen( ARCHIVIOMD_HMAC_KEY ) >= 32 );
	}

	/**
	 * Return an obfuscated wp_options key for a logical canary option name.
	 *
	 * The mapping is derived from the site URL so it is stable across requests
	 * but different on every installation.  A database dump reveals only opaque
	 * hex strings — there is no "archivio_canary_enabled" in wp_options.
	 *
	 * The mapping is cached in a static array for the lifetime of the request.
	 *
	 * @param  string $logical  Logical key, e.g. 'enabled', 'contractions'.
	 * @return string           Obfuscated wp_options key, e.g. 'ac_3f7a2b1c'.
	 */
	public static function opt( $logical ) {
		static $map = null;
		if ( null === $map ) {
			// Site-specific seed: hash of the site URL.  Does not depend on
			// ARCHIVIOMD_HMAC_KEY so it is stable even before the key is set.
			$seed = md5( get_site_url() );
			$logicals = array(
				'enabled', 'contractions', 'synonyms', 'punctuation',
				'spelling', 'hyphenation', 'numbers', 'punctuation2',
				'citation', 'parity', 'wordcount',
				'payload_version', 'key_fingerprint', 'key_rotation_id',
				'cache_health', 'cache_notice_dismissed', 'cache_check_url',
				'cache_check_time', 'db_version',
				// These three were previously missing from the map, causing the
				// fallback hash_md5($logical) path to be used — which produces
				// the same key on every WordPress installation (no site-specific
				// seed), defeating the purpose of the obfuscation scheme.
				'key_rotated', 'key_rotated_from', 'key_warn_dismissed',
			);
			$map = array();
			foreach ( $logicals as $l ) {
				$map[ $l ] = 'ac_' . substr( md5( $seed . ':' . $l ), 0, 8 );
			}
		}
		// Unknown keys fall back to a prefixed form so they still work.
		return isset( $map[ $logical ] ) ? $map[ $logical ] : 'ac_' . md5( $logical );
	}

	/**
	 * get_option() wrapper using obfuscated key.
	 */
	public static function cget( $logical, $default = false ) {
		return get_option( self::opt( $logical ), $default );
	}

	/**
	 * update_option() wrapper using obfuscated key.
	 */
	public static function cset( $logical, $value, $autoload = false ) {
		return update_option( self::opt( $logical ), $value, $autoload );
	}

	/**
	 * Migrate legacy readable option keys to obfuscated keys on first load.
	 * Runs once; marks completion in the obfuscated db_version key.
	 * Called from init_hooks() so it fires on every page load until done.
	 */
	public static function migrate_option_keys() {
		$done_key = self::opt( 'db_version' );
		if ( get_option( $done_key ) === 'obf1' ) {
			return; // already migrated
		}
		$legacy = array(
			'archivio_canary_enabled'          => 'enabled',
			'archivio_canary_contractions'     => 'contractions',
			'archivio_canary_synonyms'         => 'synonyms',
			'archivio_canary_punctuation'      => 'punctuation',
			'archivio_canary_spelling'         => 'spelling',
			'archivio_canary_hyphenation'      => 'hyphenation',
			'archivio_canary_numbers'          => 'numbers',
			'archivio_canary_punctuation2'     => 'punctuation2',
			'archivio_canary_citation'         => 'citation',
			'archivio_canary_parity'           => 'parity',
			'archivio_canary_wordcount'        => 'wordcount',
			'archivio_canary_payload_version'  => 'payload_version',
			'archivio_canary_key_fingerprint'  => 'key_fingerprint',
			'archivio_canary_key_rotation_id'  => 'key_rotation_id',
			'archivio_canary_cache_health'     => 'cache_health',
			'archivio_canary_cache_notice_dismissed' => 'cache_notice_dismissed',
			'archivio_canary_cache_check_url'  => 'cache_check_url',
			'archivio_canary_cache_check_time' => 'cache_check_time',
		);
		foreach ( $legacy as $old_key => $logical ) {
			$val = get_option( $old_key );
			if ( false !== $val ) {
				update_option( self::opt( $logical ), $val, false );
				delete_option( $old_key );
			}
		}
		update_option( $done_key, 'obf1', false );
	}
	/**
	 * The full dictionary is shipped in the plugin source.  An adversary who
	 * reads the source knows all possible pairs, but not which subset is active
	 * on any given site — that is determined by the HMAC key.  Systematically
	 * reversing all pairs on a scraped copy would require trying every possible
	 * subset (2^N possibilities where N is the dictionary size), which is
	 * computationally equivalent to brute-forcing the key itself.
	 *
	 * The subset is stable for a given key + channel_id combination, so encode
	 * and decode always agree on the active set without any stored state.
	 *
	 * @param  array  $all_pairs   Full dictionary (key=form0, value=form1).
	 * @param  string $channel_id  Channel identifier, e.g. 'ch5', 'ch6'.
	 * @param  float  $fraction    Fraction of pairs to include (default 0.7 = 70%).
	 * @return array               Key-derived subset, preserving key=>value structure.
	 */
	private function key_derived_pairs( array $all_pairs, $channel_id, $fraction = 0.7 ) {
		$keys  = array_keys( $all_pairs );
		$total = count( $keys );
		$keep  = max( 1, (int) round( $total * $fraction ) );

		// Derive a deterministic shuffle order from the key + channel_id.
		// Each round of the PRNG advances the state by one SHA-256 hash,
		// producing 4 bytes of index material per step.
		$seed  = hash_hmac( 'sha256', 'pair_select:' . $channel_id, $this->get_key(), true );
		$state = $seed;
		$order = array();
		for ( $i = 0; $i < $total; $i++ ) {
			$state   = hash( 'sha256', $state, true );
			$order[] = array( unpack( 'N', substr( $state, 0, 4 ) )[1], $i );
		}
		// Sort by the PRNG value to get a key-specific permutation
		usort( $order, function( $a, $b ) { return $a[0] - $b[0]; } );

		// Take the first $keep indices from the permuted order
		$subset = array();
		for ( $i = 0; $i < $keep; $i++ ) {
			$original_idx = $order[ $i ][1];
			$k = $keys[ $original_idx ];
			$subset[ $k ] = $all_pairs[ $k ];
		}
		return $subset;
	}

	// =========================================================================
	// BRUTE-FORCE DECODE
	//
	// Scenario: Ch.1 (zero-width) was stripped. One or more semantic channels
	// (Ch.5-12) survived. We have the channel observations but no post_id, so
	// derive_positions() cannot reconstruct which slots carry which bits.
	//
	// Strategy: enumerate every candidate post_id, run the full multi-channel
	// decode for each, require HMAC to pass AND the decoded post_id field to
	// match the candidate — two independent cryptographic checks that must both
	// succeed before we declare a match. The probability of a false positive
	// under v1 (48-bit MAC) across 500 candidates is ~500 / 2^48 ≈ 1.8×10⁻¹²;
	// under v2 (64-bit MAC) it is ~500 / 2^64 ≈ 2.7×10⁻¹⁷. Both are
	// cryptographically negligible.
	//
	// Multi-channel confirmation: a match is only accepted when ≥2 independent
	// channels agree on the same (post_id, timestamp) pair. A single-channel
	// match is flagged as UNCONFIRMED and returned separately — useful for
	// investigation but not for evidentiary purposes.
	//
	// Chunked AJAX: the candidate list is split into batches of BRUTE_CHUNK
	// post IDs per HTTP request so PHP execution never approaches timeout.
	// The client iterates chunks sequentially, accumulating results and
	// reporting progress, until a confirmed match is found or candidates
	// are exhausted.
	// =========================================================================

	const BRUTE_CHUNK      = 50;   // post IDs processed per AJAX request
	const BRUTE_MAX_POSTS  = 500;  // hard cap on total candidates

	/**
	 * Attempt to decode $html without knowing the post_id.
	 *
	 * Only operates on channels that survive scraping: Ch.5 (contractions),
	 * Ch.6 (synonyms), Ch.7 (punctuation). Ch.2-4 require the Unicode
	 * characters to still be present, which they won't be if the scraper
	 * normalised the text. Ch.1 is the bootstrap we're trying to recover.
	 *
	 * Returns an array:
	 *   confirmed    bool   — true when ≥2 channels agree and HMAC passes
	 *   unconfirmed  bool   — true when exactly 1 channel passes HMAC
	 *   post_id      int|null
	 *   timestamp    int|null
	 *   payload_version int|null
	 *   channels_matched  array  — which channels confirmed the match
	 *   candidates_tried  int
	 *   message      string
	 *
	 * @param  string   $html        Content to scan.
	 * @param  int[]    $post_ids    Specific candidate IDs to try this call.
	 * @param  int|null $date_hint   Unix timestamp; if provided, already filtered by caller.
	 * @return array
	 */
	public function brute_force_decode( $html, array $post_ids ) {
		$result = array(
			'confirmed'       => false,
			'unconfirmed'     => false,
			'post_id'         => null,
			'timestamp'       => null,
			'payload_version' => null,
			'channels_matched'=> array(),
			'candidates_tried'=> 0,
			'message'         => '',
		);

		// Pre-parse the HTML once; all channel decoders receive the same segs
		// We do a shallow check first: collect all three semantic slot lists
		// so we can skip candidates where coverage is insufficient to carry
		// even a single valid payload (slot count < needed_v1).
		$segs        = $this->split_html( $html );
		$ct_slots    = $this->collect_contraction_slots( $segs );
		$sy_slots    = $this->collect_synonym_slots( $segs );
		$pu_slots    = $this->collect_punctuation_slots( $segs );
		$sp_slots    = $this->collect_spelling_slots( $segs );
		$hy_slots    = $this->collect_hyphenation_slots( $segs );
		$nu_slots    = $this->collect_number_slots( $segs );
		$p2_slots    = $this->collect_punctuation2_slots( $segs );
		$ci_slots    = $this->collect_citation_slots( $html );
		$pa_slots    = $this->collect_parity_slots( $segs );
		$wc_slots    = $this->collect_wordcount_slots( $segs );

		$needed_v1   = self::PAYLOAD_BITS_V1 * self::REDUNDANCY; // 336
		$needed_v2   = self::PAYLOAD_BITS_V2 * self::REDUNDANCY; // 408

		// Channels with enough slots to carry a payload are the active probes.
		// We need at least one to proceed at all.
		$active = array();
		if ( count( $ct_slots ) >= $needed_v1 ) { $active['ch5'] = $ct_slots; }
		if ( count( $sy_slots ) >= $needed_v1 ) { $active['ch6'] = $sy_slots; }
		if ( count( $pu_slots ) >= $needed_v1 ) { $active['ch7'] = $pu_slots; }
		if ( count( $sp_slots ) >= $needed_v1 ) { $active['ch8'] = $sp_slots; }
		if ( count( $hy_slots ) >= $needed_v1 ) { $active['ch9'] = $hy_slots; }
		if ( count( $nu_slots ) >= $needed_v1 ) { $active['ch10'] = $nu_slots; }
		if ( count( $p2_slots ) >= $needed_v1 ) { $active['ch11'] = $p2_slots; }
		if ( count( $ci_slots ) >= $needed_v1 ) { $active['ch12'] = $ci_slots; }
		if ( count( $pa_slots ) >= $needed_v1 ) { $active['ch13'] = $pa_slots; }
		if ( count( $wc_slots ) >= $needed_v1 ) { $active['ch14'] = $wc_slots; }

		if ( empty( $active ) ) {
			$result['message'] = __( 'No semantic channels have sufficient coverage to attempt brute-force decode. The content may be too short or the semantic channels were not encoded.', 'archiviomd' );
			return $result;
		}

		// Map channel id → slot array and decode callable (for position derivation)
		$channel_meta = array(
			'ch5'  => array( 'label' => 'Contractions (Ch.5)',     'collect_fn' => array( $this, 'collect_contraction_slots' ) ),
			'ch6'  => array( 'label' => 'Synonyms (Ch.6)',          'collect_fn' => array( $this, 'collect_synonym_slots' ) ),
			'ch7'  => array( 'label' => 'Punctuation (Ch.7)',       'collect_fn' => array( $this, 'collect_punctuation_slots' ) ),
			'ch8'  => array( 'label' => 'Spelling (Ch.8)',          'collect_fn' => array( $this, 'collect_spelling_slots' ) ),
			'ch9'  => array( 'label' => 'Hyphenation (Ch.9)',      'collect_fn' => array( $this, 'collect_hyphenation_slots' ) ),
			'ch10' => array( 'label' => 'Numbers (Ch.10)',          'collect_fn' => array( $this, 'collect_number_slots' ) ),
			'ch11' => array( 'label' => 'Punct. style II (Ch.11)', 'collect_fn' => array( $this, 'collect_punctuation2_slots' ) ),
			'ch12' => array( 'label' => 'Citation style (Ch.12)',  'collect_fn' => array( $this, 'collect_citation_slots' ) ),
			'ch13' => array( 'label' => 'Sentence parity (Ch.13)', 'collect_fn' => array( $this, 'collect_parity_slots' ) ),
			'ch14' => array( 'label' => 'Word-count parity (Ch.14)', 'collect_fn' => array( $this, 'collect_wordcount_slots' ) ),
		);

		foreach ( $post_ids as $candidate_id ) {
			$candidate_id = (int) $candidate_id;
			$result['candidates_tried']++;

			$channel_hits = array(); // channels that passed HMAC for this candidate

			foreach ( $active as $ch_id => $slots ) {
				$meta = $channel_meta[ $ch_id ];
				$n    = count( $slots );

				// Try v2 payload size first, then v1
				foreach ( array( 2, 1 ) as $ver ) {
					$needed = ( 2 === $ver ) ? $needed_v2 : $needed_v1;
					$pbits  = ( 2 === $ver ) ? self::PAYLOAD_BITS_V2 : self::PAYLOAD_BITS_V1;
					if ( $n < $needed ) { continue; }

					// Reconstruct the bit stream using this candidate's positions
					$positions = $this->derive_positions( $candidate_id, $ch_id, $needed, $n );
					$stream    = array_fill( 0, $needed, 0 );
					foreach ( $positions as $rank => $slot_idx ) {
						if ( isset( $slots[ $slot_idx ] ) ) {
							$stream[ $rank ] = $slots[ $slot_idx ]['form'];
						}
					}

					$payload = $this->bits_to_payload(
						$this->collapse_bits( $stream, $pbits ),
						$pbits
					);
					$dec = $this->verify_payload( $payload );

					if ( ! $dec || ! $dec['valid'] ) { continue; }

					// HMAC passed. Now the second check: does the post_id
					// encoded in the payload match the candidate we used to
					// derive the positions? If not, this is a false positive
					// from the HMAC check — reject it.
					if ( (int) $dec['post_id'] !== $candidate_id ) { continue; }

					// Timestamp sanity: must be a plausible Unix timestamp
					// (after 2000-01-01, before 2100-01-01).
					if ( $dec['timestamp'] < 946684800 || $dec['timestamp'] > 4102444800 ) {
						continue;
					}

					// Both checks passed — record this channel as a hit
					$channel_hits[ $ch_id ] = array(
						'label'           => $meta['label'],
						'post_id'         => $dec['post_id'],
						'timestamp'       => $dec['timestamp'],
						'payload_version' => $dec['payload_version'],
					);
					break; // found a version that works for this channel; move to next channel
				}
			}

			if ( empty( $channel_hits ) ) { continue; }

			// Require all hits to agree on the same (post_id, timestamp) pair.
			// A single-channel hit where the values disagree across channels
			// would indicate a corrupt read; we don't promote it to confirmed.
			$ref     = reset( $channel_hits );
			$all_agree = true;
			foreach ( $channel_hits as $hit ) {
				if ( $hit['post_id'] !== $ref['post_id'] || $hit['timestamp'] !== $ref['timestamp'] ) {
					$all_agree = false;
					break;
				}
			}

			if ( ! $all_agree ) { continue; }

			// Populate result
			$result['post_id']          = $ref['post_id'];
			$result['timestamp']        = $ref['timestamp'];
			$result['payload_version']  = $ref['payload_version'];
			$result['channels_matched'] = array_keys( $channel_hits );
			$result['channel_details']  = $channel_hits;

			$match_count = count( $channel_hits );

			if ( $match_count >= 2 ) {
				// ≥2 channels agree: confirmed match
				$result['confirmed'] = true;
				$result['message']   = sprintf(
					/* translators: 1: number of channels 2: post ID */
					__( 'Confirmed match — %1$d independent channels verified post ID %2$d.', 'archiviomd' ),
					$match_count, $ref['post_id']
				);
			} else {
				// Exactly 1 channel passed — flagged as unconfirmed
				$result['unconfirmed'] = true;
				$result['message']     = sprintf(
					/* translators: 1: channel label 2: post ID */
					__( 'Unconfirmed match — only %1$s verified post ID %2$d. A second channel is required for evidentiary confidence.', 'archiviomd' ),
					$ref['label'] ?? 'one channel', $ref['post_id']
				);
			}

			return $result; // stop at first valid match
		}

		// No match found in this batch
		$result['message'] = __( 'No match found in this batch.', 'archiviomd' );
		return $result;
	}

	/**
	 * Build the candidate post_id list for a brute-force scan.
	 * Applies the date-hint window and the hard cap.
	 *
	 * @param  int|null $date_hint  Unix timestamp to centre the window on.
	 * @param  int      $window     Seconds either side of the hint (default 180 days).
	 * @return int[]  Post IDs, ascending.
	 */
	public static function brute_force_candidates( $date_hint = null, $window = 15552000 ) {
		$args = array(
			'post_type'   => 'any',
			'post_status' => 'publish',
			'fields'      => 'ids',
			'numberposts' => self::BRUTE_MAX_POSTS,
			'orderby'     => 'date',
			'order'       => 'DESC',
		);
		if ( $date_hint && $date_hint > 0 ) {
			$args['date_query'] = array( array(
				'after'     => gmdate( 'Y-m-d H:i:s', max( 0, $date_hint - $window ) ),
				'before'    => gmdate( 'Y-m-d H:i:s', $date_hint + $window ),
				'inclusive' => true,
			) );
		}
		$ids = get_posts( $args );
		return array_map( 'intval', $ids );
	}

	/**
	 * AJAX handler — one chunk of the brute-force scan.
	 *
	 * Expects POST fields:
	 *   nonce        string   archivio_canary_nonce
	 *   content      string   HTML/text content to scan
	 *   post_ids     string   JSON array of post IDs to try this chunk
	 *   chunk        int      Current chunk index (0-based, for progress display)
	 *   total_chunks int      Total number of chunks
	 *
	 * Returns:
	 *   done         bool     true if a match was found (stop iterating)
	 *   confirmed    bool
	 *   unconfirmed  bool
	 *   post_id      int|null
	 *   timestamp    int|null
	 *   ...          (full brute_force_decode result if match found)
	 *   progress_pct int      0-100
	 *   chunk        int
	 *   total_chunks int
	 */
	public function ajax_brute_force_decode() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}

		$raw = isset( $_POST['content'] ) ? wp_unslash( $_POST['content'] ) : '';
		if ( empty( trim( $raw ) ) ) {
			wp_send_json_error( array( 'message' => __( 'No content provided.', 'archiviomd' ) ) );
		}

		$post_ids_raw = isset( $_POST['post_ids'] ) ? sanitize_text_field( wp_unslash( $_POST['post_ids'] ) ) : '[]';
		$post_ids     = json_decode( $post_ids_raw, true );
		if ( ! is_array( $post_ids ) || empty( $post_ids ) ) {
			wp_send_json_error( array( 'message' => __( 'No candidate post IDs provided.', 'archiviomd' ) ) );
		}
		// Sanitise: integers only, no more than BRUTE_CHUNK per request
		$post_ids = array_slice(
			array_map( 'absint', $post_ids ),
			0,
			self::BRUTE_CHUNK
		);

		$chunk        = max( 0, (int) ( $_POST['chunk']        ?? 0 ) );
		$total_chunks = max( 1, (int) ( $_POST['total_chunks'] ?? 1 ) );

		$scan = $this->brute_force_decode( $raw, $post_ids );

		$done = $scan['confirmed'] || $scan['unconfirmed'];

		// Enrich with post metadata if a match was found
		if ( $done && $scan['post_id'] ) {
			$this->enrich_result( $scan );
			$log_row_id = $this->log_discovery( $scan, 'brute_force', '' );
			if ( $log_row_id ) { $scan['log_row_id'] = $log_row_id; }
		}

		$progress_pct = (int) round( ( ( $chunk + 1 ) / $total_chunks ) * 100 );

		wp_send_json_success( array_merge( $scan, array(
			'done'         => $done,
			'progress_pct' => $progress_pct,
			'chunk'        => $chunk,
			'total_chunks' => $total_chunks,
		) ) );
	}

	/**
	 * AJAX handler — return the candidate post_id list for a given date hint.
	 * Called once at the start of a deep scan to build the full list in JS
	 * before chunking begins.
	 *
	 * Expects POST fields:
	 *   nonce      string   archivio_canary_nonce
	 *   date_hint  int      Unix timestamp (optional; 0 = no date filter)
	 *
	 * Returns:
	 *   post_ids      int[]
	 *   total         int
	 *   chunks        int
	 *   capped        bool   true if total was capped at BRUTE_MAX_POSTS
	 */
	public function ajax_brute_force_candidates() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}

		$date_hint = isset( $_POST['date_hint'] ) ? absint( wp_unslash( $_POST['date_hint'] ) ) : 0;
		$all_ids   = self::brute_force_candidates( $date_hint > 0 ? $date_hint : null );
		$capped    = count( $all_ids ) >= self::BRUTE_MAX_POSTS;
		$chunks    = (int) ceil( count( $all_ids ) / self::BRUTE_CHUNK );

		wp_send_json_success( array(
			'post_ids' => $all_ids,
			'total'    => count( $all_ids ),
			'chunks'   => max( 1, $chunks ),
			'capped'   => $capped,
		) );
	}

	// =========================================================================
	// SIGNED EVIDENCE PACKAGE
	// =========================================================================

	/**
	 * Build a signed evidence receipt for a specific decode result.
	 *
	 * The receipt is a self-describing JSON document that packages the full
	 * decode result into a machine-readable evidence package. A SHA-256
	 * integrity hash is always included. If Ed25519 keys are configured the
	 * receipt is also cryptographically signed — making it self-verifiable
	 * without WordPress.
	 *
	 * Receipt schema
	 * ──────────────
	 * receipt_type          "canary_decode"
	 * generated_at          ISO 8601 UTC
	 * plugin_version        e.g. "1.10.0"
	 * site_url              site home URL
	 * decode_result         the full enriched decode result array
	 * verifier_user_id      current user ID
	 * log_row_id            discovery log row ID (if provided)
	 * sha256                SHA-256 over canonical JSON of the fields above
	 * signature             Ed25519 hex signature over the same canonical JSON
	 *                       (omitted when signing is not configured)
	 * pubkey_fingerprint    first 16 hex chars of SHA-256(pubkey hex)
	 *                       (omitted when signing is not configured)
	 * signing_status        "signed" | "unsigned" | "unavailable"
	 *
	 * @param  array    $decode_result  Enriched result array from decode() / enrich_result().
	 * @param  int|null $log_row_id     Discovery log row to mark as receipt-generated.
	 * @return array  The full receipt array, ready for JSON encoding.
	 */
	public function generate_evidence_receipt( array $decode_result, $log_row_id = null ) {
		$current_user = wp_get_current_user();
		$generated_at = gmdate( 'Y-m-d\\TH:i:s\\Z' );

		$envelope = array(
			'receipt_type'     => 'canary_decode',
			'generated_at'     => $generated_at,
			'plugin_version'   => defined( 'MDSM_VERSION' ) ? MDSM_VERSION : 'unknown',
			'site_url'         => get_site_url(),
			'decode_result'    => $decode_result,
			'verifier_user_id' => $current_user instanceof WP_User ? $current_user->ID : 0,
			'log_row_id'       => $log_row_id ? (int) $log_row_id : null,
		);

		// ── SHA-256 integrity hash over canonical JSON (sorted keys, no whitespace) ──
		$canonical = wp_json_encode( $envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$sha256    = hash( 'sha256', $canonical );

		$envelope['sha256'] = $sha256;

		// ── Ed25519 signing (optional, degrades gracefully) ───────────────────
		$signing_available = (
			class_exists( 'MDSM_Ed25519_Signing' )
			&& MDSM_Ed25519_Signing::is_sodium_available()
			&& MDSM_Ed25519_Signing::is_private_key_defined()
		);

		if ( $signing_available ) {
			$sig = MDSM_Ed25519_Signing::sign( $canonical );

			if ( ! is_wp_error( $sig ) ) {
				// Derive pubkey fingerprint: first 16 hex chars of SHA-256(pubkey_hex)
				$pubkey_hex         = defined( 'MDSM_ED25519_PUBLIC_KEY' ) ? MDSM_ED25519_PUBLIC_KEY : '';
				$pubkey_fingerprint = $pubkey_hex ? substr( hash( 'sha256', $pubkey_hex ), 0, 16 ) : null;

				$envelope['signature']          = $sig;
				$envelope['pubkey_fingerprint'] = $pubkey_fingerprint;
				$envelope['public_key_url']     = trailingslashit( get_site_url() ) . '.well-known/ed25519-pubkey.txt';
				$envelope['signing_status']     = 'signed';
			} else {
				$envelope['signing_status']        = 'error';
				$envelope['signing_status_detail'] = $sig->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_Ed25519_Signing' ) && MDSM_Ed25519_Signing::is_mode_enabled() ) {
			$envelope['signing_status']        = 'unavailable';
			$envelope['signing_status_detail'] = 'Ed25519 mode is enabled but ext-sodium or the private key constant is missing.';
		} else {
			$envelope['signing_status']        = 'unsigned';
			$envelope['signing_status_detail'] = 'Ed25519 signing is not configured. Visit Archivio Post → Settings to enable signed evidence packages.';
		}

		// ── Mark log row as having a receipt generated ────────────────────────
		if ( $log_row_id ) {
			global $wpdb;
			$table = self::log_table_name();
			$wpdb->update(
				$table,
				array( 'receipt_generated' => 1 ),
				array( 'id' => (int) $log_row_id ),
				array( '%d' ),
				array( '%d' )
			);
		}

		return $envelope;
	}

	/**
	 * AJAX handler — generate and serve a signed evidence receipt as a
	 * downloadable .sig.json file.
	 *
	 * Expects POST fields:
	 *   nonce        string   archivio_canary_nonce
	 *   result       string   JSON-encoded enriched decode result
	 *   log_row_id   int      (optional) Discovery log row ID to mark
	 *
	 * Returns the receipt JSON as a base64 data URI for client-side download.
	 * Using a data URI avoids temp files entirely — the browser triggers the
	 * download directly from the response.
	 */
	public function ajax_download_evidence() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}

		// ── Reconstruct decode result from the server-written log row ─────────
		// We never sign data supplied directly by POST — that would allow any
		// admin to fabricate an arbitrary JSON object and receive a genuine
		// cryptographic signature over it. Instead we read the authoritative
		// record that the server itself wrote at decode time and sign that.
		$log_row_id = isset( $_POST['log_row_id'] ) ? absint( $_POST['log_row_id'] ) : 0;
		if ( ! $log_row_id ) {
			wp_send_json_error( array( 'message' => __( 'A valid log_row_id is required to generate an evidence receipt.', 'archiviomd' ) ) );
		}

		global $wpdb;
		$table = self::log_table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) ) {
			wp_send_json_error( array( 'message' => __( 'Discovery log table not found.', 'archiviomd' ) ) );
		}
		$row = $wpdb->get_row( $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT * FROM {$table} WHERE id = %d",
			$log_row_id
		), ARRAY_A );
		if ( ! $row ) {
			wp_send_json_error( array( 'message' => __( 'Log entry not found.', 'archiviomd' ) ) );
		}

		// Rebuild a minimal but complete decode_result array from the log row.
		// Enrich it with live post metadata so the receipt is self-describing.
		$decode_result = array(
			'found'           => (bool) $row['valid'],
			'valid'           => (bool) $row['valid'],
			'post_id'         => $row['post_id'] ? (int) $row['post_id'] : null,
			'timestamp'       => $row['fingerprint_ts'] ? (int) $row['fingerprint_ts'] : null,
			'payload_version' => $row['payload_version'] ? (int) $row['payload_version'] : null,
			'source'          => $row['source'],
			'source_url'      => $row['source_url'],
			'discovered_at'   => $row['discovered_at'],
			'channels_found'  => (int) $row['channels_found'],
		);
		$this->enrich_result( $decode_result );

		$receipt      = $this->generate_evidence_receipt( $decode_result, $log_row_id );
		$json         = wp_json_encode( $receipt, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$data_uri     = 'data:application/json;base64,' . base64_encode( $json ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions

		// Build a descriptive filename: canary-evidence-{post_id}-{date}.sig.json
		$post_id_slug = ! empty( $decode_result['post_id'] ) ? (int) $decode_result['post_id'] : 'unknown';
		$date_slug    = gmdate( 'Y-m-d' );
		$filename     = "canary-evidence-{$post_id_slug}-{$date_slug}.sig.json";

		wp_send_json_success( array(
			'data_uri'        => $data_uri,
			'filename'        => $filename,
			'signing_status'  => $receipt['signing_status'],
			'sha256'          => $receipt['sha256'],
		) );
	}


	/**
	 * Return the fully-qualified discovery log table name.
	 */
	public static function log_table_name() {
		global $wpdb;
		return $wpdb->prefix . 'archivio_canary_log';
	}

	/**
	 * Create (or upgrade) the discovery log table via dbDelta.
	 * Safe to call on every activation and upgrade — dbDelta is idempotent.
	 */
	public static function create_log_table() {
		global $wpdb;
		$table           = self::log_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table} (
			id                bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			discovered_at     datetime            NOT NULL,
			source            varchar(20)         NOT NULL DEFAULT 'admin',
			source_url        varchar(2083)       NOT NULL DEFAULT '',
			post_id           bigint(20) unsigned          DEFAULT NULL,
			fingerprint_ts    int(10) unsigned             DEFAULT NULL,
			payload_version   tinyint(3) unsigned          DEFAULT NULL,
			valid             tinyint(1)          NOT NULL DEFAULT 0,
			verifier_id       bigint(20) unsigned          DEFAULT NULL,
			channels_found    tinyint(3) unsigned NOT NULL DEFAULT 0,
			note              varchar(255)        NOT NULL DEFAULT '',
			receipt_generated tinyint(1)          NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			KEY discovered_at (discovered_at),
			KEY post_id (post_id),
			KEY valid (valid),
			KEY source (source)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Drop the discovery log table (used only when metadata cleanup is enabled).
	 */
	public static function drop_log_table() {
		global $wpdb;
		$table = self::log_table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
	}

	// =========================================================================
	// DISCOVERY LOG — WRITE
	// =========================================================================

	/**
	 * Write one entry to the discovery log.
	 *
	 * Called automatically after every successful decode (admin AJAX, URL
	 * decoder, and both REST endpoints). Only writes when the table exists;
	 * silently skips if it does not (e.g. on a fresh install before activation).
	 *
	 * @param array  $result      The decoded result array from decode().
	 * @param string $source      'admin_paste' | 'admin_url' | 'rest_public' | 'rest_full'
	 * @param string $source_url  The URL checked (if any).
	 */
	private function log_discovery( array $result, $source = 'admin_paste', $source_url = '' ) {
		global $wpdb;
		$table = self::log_table_name();

		// Silently skip if table doesn't exist yet (activation not run)
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) ) {
			return;
		}

		// Count how many channels returned a positive result
		$channels_found = 0;
		if ( ! empty( $result['channels'] ) ) {
			foreach ( $result['channels'] as $ch ) {
				if ( ! empty( $ch['valid'] ) ) {
					$channels_found++;
				}
			}
		}

		$wpdb->insert(
			$table,
			array(
				'discovered_at'   => current_time( 'mysql', true ), // UTC
				'source'          => sanitize_text_field( $source ),
				'source_url'      => esc_url_raw( $source_url ),
				'post_id'         => $result['post_id'] ? (int) $result['post_id'] : null,
				'fingerprint_ts'  => $result['timestamp'] ? (int) $result['timestamp'] : null,
				'payload_version' => $result['payload_version'] ? (int) $result['payload_version'] : null,
				'valid'           => $result['valid'] ? 1 : 0,
				'verifier_id'     => get_current_user_id() ?: null,
				'channels_found'  => (int) $channels_found,
				'note'            => '',
			),
			array( '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%s' )
		);

		return $wpdb->insert_id ?: null;
	}

	// =========================================================================
	// SEMANTIC DICTIONARIES
	// =========================================================================

	private static function contraction_pairs() {
		return array(
			// ── Negations ───────────────────────────────────────────────────────
			"shouldn't"  => 'should not',  "couldn't"   => 'could not',
			"wouldn't"   => 'would not',   "doesn't"    => 'does not',
			"haven't"    => 'have not',    "hadn't"     => 'had not',
			"hasn't"     => 'has not',     "weren't"    => 'were not',
			"wasn't"     => 'was not',     "aren't"     => 'are not',
			"didn't"     => 'did not',     "don't"      => 'do not',
			"isn't"      => 'is not',      "won't"      => 'will not',
			"can't"      => 'cannot',      "mustn't"    => 'must not',
			"needn't"    => 'need not',    "daren't"    => 'dare not',
			"shan't"     => 'shall not',   "mightn't"   => 'might not',
			"oughtn't"   => 'ought not',   "wouldn't've" => 'would not have',
			"shouldn't've" => 'should not have', "couldn't've" => 'could not have',
			// ── they / you / we ─────────────────────────────────────────────────
			"they're"    => 'they are',    "you're"     => 'you are',
			"we're"      => 'we are',      "they've"    => 'they have',
			"you've"     => 'you have',    "we've"      => 'we have',
			"they'll"    => 'they will',   "you'll"     => 'you will',
			"we'll"      => 'we will',     "they'd"     => 'they would',
			"you'd"      => 'you would',   "we'd"       => 'we would',
			"they'll've" => 'they will have', "you'll've" => 'you will have',
			"we'll've"   => 'we will have',
			// ── there / that / here / what / where / who / how ──────────────────
			"there's"    => 'there is',    "that's"     => 'that is',
			"here's"     => 'here is',     "what's"     => 'what is',
			"where's"    => 'where is',    "who's"      => 'who is',
			"how's"      => 'how is',      "when's"     => 'when is',
			"why's"      => 'why is',      "that'd"     => 'that would',
			"there'd"    => 'there would', "that'll"    => 'that will',
			"there'll"   => 'there will',
			// ── he / she / it ────────────────────────────────────────────────────
			"it's"       => 'it is',       "he's"       => 'he is',
			"she's"      => 'she is',      "he'd"       => 'he would',
			"she'd"      => 'she would',   "he'll"      => 'he will',
			"she'll"     => 'she will',    "he've"      => 'he have',
			// ── I ────────────────────────────────────────────────────────────────
			"I'm"        => 'I am',        "I've"       => 'I have',
			"I'll"       => 'I will',      "I'd"        => 'I would',
			"I'll've"    => 'I will have',
			// ── modal + have ─────────────────────────────────────────────────────
			"could've"   => 'could have',  "would've"   => 'would have',
			"should've"  => 'should have', "might've"   => 'might have',
			"must've"    => 'must have',   "may've"     => 'may have',
			"will've"    => 'will have',
			// ── miscellaneous ────────────────────────────────────────────────────
			"let's"      => 'let us',      "ma'am"      => 'madam',
			"o'clock"    => 'of the clock',
		);
	}

	private static function synonym_pairs() {
		return array(
			// ── Adverbs / connectives ────────────────────────────────────────────
			'often'        => 'frequently',   'almost'       => 'nearly',
			'also'         => 'additionally', 'thus'         => 'therefore',
			'however'      => 'nevertheless', 'although'     => 'though',
			'currently'    => 'presently',    'generally'    => 'typically',
			'usually'      => 'normally',     'previously'   => 'formerly',
			'approximately' => 'roughly',     'entirely'     => 'completely',
			'primarily'    => 'mainly',       'initially'    => 'originally',
			'subsequently' => 'later',        'ultimately'   => 'finally',
			'additionally' => 'furthermore',  'consequently' => 'as a result',
			// ── Verbs ────────────────────────────────────────────────────────────
			'start'        => 'begin',        'finish'       => 'complete',
			'help'         => 'assist',       'show'         => 'demonstrate',
			'choose'       => 'select',       'require'      => 'need',
			'allow'        => 'enable',       'try'          => 'attempt',
			'keep'         => 'maintain',     'get'          => 'obtain',
			'make'         => 'create',       'use'          => 'employ',
			'find'         => 'discover',     'give'         => 'provide',
			'check'        => 'verify',       'change'       => 'modify',
			'increase'     => 'expand',       'decrease'     => 'reduce',
			'improve'      => 'enhance',      'remove'       => 'eliminate',
			'consider'     => 'examine',      'discuss'      => 'address',
			'ensure'       => 'guarantee',    'indicate'     => 'suggest',
			'involve'      => 'include',      'occur'        => 'happen',
			'receive'      => 'obtain',       'remain'       => 'stay',
			'represent'    => 'reflect',      'support'      => 'back',
			'believe'      => 'think',        'decide'       => 'determine',
			'explain'      => 'describe',     'expect'       => 'anticipate',
			'establish'    => 'set up',       'implement'    => 'apply',
			'investigate'  => 'examine',      'acknowledge'  => 'recognise',
			// ── Adjectives ───────────────────────────────────────────────────────
			'important'    => 'significant',  'large'        => 'substantial',
			'fast'         => 'quick',        'simple'       => 'straightforward',
			'different'    => 'distinct',     'common'       => 'frequent',
			'clear'        => 'evident',      'hard'         => 'difficult',
			'small'        => 'minor',        'new'          => 'recent',
			'specific'     => 'particular',   'available'    => 'accessible',
			'necessary'    => 'essential',    'possible'     => 'feasible',
			'various'      => 'several',      'additional'   => 'further',
			'effective'    => 'successful',   'accurate'     => 'precise',
			'relevant'     => 'applicable',   'existing'     => 'current',
			'similar'      => 'comparable',   'complex'      => 'complicated',
			'broad'        => 'wide',         'brief'        => 'short',
			'entire'       => 'whole',        'main'         => 'primary',
			'major'        => 'key',          'overall'      => 'general',
			// ── Nouns ────────────────────────────────────────────────────────────
			'method'       => 'approach',     'problem'      => 'issue',
			'result'       => 'outcome',      'purpose'      => 'goal',
			'requirement'  => 'need',         'challenge'    => 'difficulty',
			'opportunity'  => 'chance',       'benefit'      => 'advantage',
			'component'    => 'element',      'feature'      => 'characteristic',
			'aspect'       => 'element',      'factor'       => 'element',
			'area'         => 'field',        'example'      => 'instance',
			'task'         => 'activity',     'role'         => 'function',
			'impact'       => 'effect',       'capacity'     => 'ability',
			'concern'      => 'worry',        'difference'   => 'distinction',
			'information'  => 'data',         'knowledge'    => 'understanding',
			'decision'     => 'choice',       'evidence'     => 'proof',
			'situation'    => 'circumstance', 'structure'    => 'framework',
		);
	}

	// =========================================================================
	// CH.8 DATA — SPELLING VARIANTS (British ↔ American)
	// =========================================================================

	/**
	 * British/American spelling pairs.
	 * Key   = British form  (form 0)
	 * Value = American form (form 1)
	 *
	 * Selection criteria:
	 *   - Both forms are unambiguously correct English in their respective registers.
	 *   - Neither form shifts meaning, register, or connotation relative to the other.
	 *   - The word must occur frequently enough in analytical/editorial prose.
	 *   - Hyphenated variants are excluded (handled by Ch.9).
	 *
	 * A normaliser enforcing consistency across the entire document would
	 * produce visibly edited text; a naive scraper that leaves spelling alone
	 * preserves the fingerprint intact.
	 */
	private static function spelling_pairs() {
		return array(
			// ── -ise / -ize ──────────────────────────────────────────────────
			'organise'     => 'organize',     'analyse'      => 'analyze',
			'recognise'    => 'recognize',    'realise'      => 'realize',
			'emphasise'    => 'emphasize',    'criticise'    => 'criticize',
			'authorise'    => 'authorize',    'prioritise'   => 'prioritize',
			'summarise'    => 'summarize',    'utilise'      => 'utilize',
			'specialise'   => 'specialize',   'minimise'     => 'minimize',
			'maximise'     => 'maximize',     'standardise'  => 'standardize',
			'characterise' => 'characterize', 'categorise'   => 'categorize',
			'centralise'   => 'centralize',   'finalise'     => 'finalize',
			'mobilise'     => 'mobilize',     'stabilise'    => 'stabilize',
			// ── -our / -or ───────────────────────────────────────────────────
			'colour'       => 'color',        'behaviour'    => 'behavior',
			'favour'       => 'favor',        'honour'       => 'honor',
			'labour'       => 'labor',        'neighbour'    => 'neighbor',
			'humour'       => 'humor',        'flavour'      => 'flavor',
			'rumour'       => 'rumor',        'vigour'       => 'vigor',
			'valour'       => 'valor',        'glamour'      => 'glamor',
			// ── -re / -er ────────────────────────────────────────────────────
			'centre'       => 'center',       'fibre'        => 'fiber',
			'litre'        => 'liter',        'metre'        => 'meter',
			'theatre'      => 'theater',      'calibre'      => 'caliber',
			'spectre'      => 'specter',
			// ── -ll / -l (inflections) ───────────────────────────────────────
			'travelling'   => 'traveling',    'cancelling'   => 'canceling',
			'modelling'    => 'modeling',     'labelling'    => 'labeling',
			'counselling'  => 'counseling',   'fulfil'       => 'fulfill',
			// ── -ogue / -og ──────────────────────────────────────────────────
			'catalogue'    => 'catalog',      'dialogue'     => 'dialog',
			// ── -ence / -ense ────────────────────────────────────────────────
			'defence'      => 'defense',      'offence'      => 'offense',
			'licence'      => 'license',      'pretence'     => 'pretense',
			// ── Miscellaneous ────────────────────────────────────────────────
			'ageing'       => 'aging',        'programme'    => 'program',
			'judgement'    => 'judgment',     'grey'         => 'gray',
			'sceptical'    => 'skeptical',    'tyre'         => 'tire',
			'cheque'       => 'check',        'plough'       => 'plow',
		);
	}

	// =========================================================================
	// CH.9 DATA — HYPHENATION CHOICES
	// =========================================================================

	/**
	 * Hyphenation variant pairs — position-independent only.
	 *
	 * Only pairs that are acceptable with OR without the hyphen regardless of
	 * syntactic position are included here. This avoids the attributive/predicative
	 * problem (long-term plan vs the plan is long term) entirely. The encoder
	 * never needs a POS tagger; it simply finds the word/phrase and flips the form.
	 *
	 * Both forms appear in major style guides (AP vs Chicago, Guardian vs Times).
	 * A scraper normalising to one form would alter text in ways that look
	 * like heavy copy-editing on professional content.
	 *
	 * Key   = closed / solid form  (form 0)
	 * Value = hyphenated form      (form 1)
	 */
	private static function hyphenation_pairs() {
		return array(
			// ── Tech / digital ───────────────────────────────────────────────
			'email'          => 'e-mail',
			'online'         => 'on-line',
			'offline'        => 'off-line',
			'website'        => 'web-site',
			'database'       => 'data-base',
			'startup'        => 'start-up',
			'login'          => 'log-in',
			'logout'         => 'log-out',
			'setup'          => 'set-up',
			'takeaway'       => 'take-away',
			'followup'       => 'follow-up',
			'rollout'        => 'roll-out',
			'buildup'        => 'build-up',
			'breakout'       => 'break-out',
			'rundown'        => 'run-down',
			'roundup'        => 'round-up',
			// ── Compound adjectives / nouns used in both positions ────────────
			'cooperate'      => 'co-operate',
			'cooperation'    => 'co-operation',
			'coordinate'     => 'co-ordinate',
			'coordination'   => 'co-ordination',
			'reexamine'      => 're-examine',
			'reexamination'  => 're-examination',
			'reevaluate'     => 're-evaluate',
			'reestablish'    => 're-establish',
			// ── Hyphenated nouns that are also written open or solid ─────────
			'policymaker'    => 'policy-maker',
			'policymaking'   => 'policy-making',
			'decisionmaker'  => 'decision-maker',
			'decisionmaking' => 'decision-making',
			'fundraiser'     => 'fund-raiser',
			'fundraising'    => 'fund-raising',
			'caretaker'      => 'care-taker',
			'caregiver'      => 'care-giver',
			'healthcare'     => 'health-care',
			'workforce'      => 'work-force',
			'workplace'      => 'work-place',
			'worldwide'      => 'world-wide',
			'nationwide'     => 'nation-wide',
			'citywide'       => 'city-wide',
			'statewide'      => 'state-wide',
			'countywide'     => 'county-wide',
		);
	}

	// =========================================================================
	// CH.10 DATA — NUMBER AND DATE STYLE
	// =========================================================================

	/**
	 * Collect number/date style slots.
	 *
	 * Three sub-channels — each is a genuine house-style choice no normaliser
	 * can collapse without making editorial decisions:
	 *
	 *   A) Thousands separator:  "1,000" (form 1) ↔ "1000" (form 0)
	 *      Only integers 1000–999999 (4-6 digits). Avoids years (1990–2099)
	 *      to prevent false positives; avoids post-codes and phone fragments.
	 *
	 *   B) Percent style:  "10 percent" (form 0) ↔ "10%" (form 1)
	 *      Also handles "per cent" (two-word British form, form 0).
	 *      Integer percentages only.
	 *
	 *   C) Ordinal style:  "first" … "twelfth" (form 0) ↔ "1st" … "12th" (form 1)
	 *      Covers 1st–12th. Written ordinals in this range are common in prose;
	 *      swapping is invisible to a reader.
	 *
	 * @param  array $segs  Segments from split_html().
	 * @return array  Slot list compatible with encode_channel_punctuation's model.
	 */
	private function collect_number_slots( array $segs ) {
		$slots = array();

		// ── Ordinal map ───────────────────────────────────────────────────────
		$ordinal_map = array(
			'first'   => '1st',  'second'  => '2nd',  'third'   => '3rd',
			'fourth'  => '4th',  'fifth'   => '5th',  'sixth'   => '6th',
			'seventh' => '7th',  'eighth'  => '8th',  'ninth'   => '9th',
			'tenth'   => '10th', 'eleventh'=> '11th', 'twelfth' => '12th',
		);
		// Build reverse: "1st" => "first"
		$ordinal_reverse = array_flip( $ordinal_map );

		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] || $seg['skip'] ) { continue; }
			$text = $seg['content'];

			// ── Sub-channel A: thousands separator ───────────────────────────
			// Match 4–6 digit integers with comma separator — "1,234" / "12,345" / "123,456"
			if ( preg_match_all( '/\b(\d{1,3}),(\d{3})\b/', $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$full = $match[0][0]; $off = $match[0][1];
					$solid = $match[1][0] . $match[2][0]; // "1000"
					// Skip years and phone-like numbers
					$numeric = (int) str_replace( ',', '', $full );
					if ( $numeric >= 1900 && $numeric <= 2099 ) { continue; }
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'number_sep',
						'form'      => 1, // comma form is form 1
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $solid,
						'form1_txt' => $full,
					);
				}
			}
			// Match 4–6 digit integers WITHOUT comma — "1000" but not years
			if ( preg_match_all( '/\b(\d{4,6})\b/', $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$full = $match[0][0]; $off = $match[0][1];
					$n = (int) $full;
					if ( $n >= 1000 && $n <= 999999 ) {
						if ( $n >= 1900 && $n <= 2099 ) { continue; } // skip years
						// Format with comma
						$with_comma = number_format( $n );
						$slots[] = array(
							'seg'       => $si,
							'type'      => 'number_sep',
							'form'      => 0, // solid form is form 0
							'offset'    => $off,
							'old_len'   => strlen( $full ),
							'form0_txt' => $full,
							'form1_txt' => $with_comma,
						);
					}
				}
			}

			// ── Sub-channel B: percent style ─────────────────────────────────
			// "10 percent" / "10 per cent" → form 0;  "10%" → form 1
			if ( preg_match_all( '/\b(\d+)\s+(per\s+cent|percent)\b/i', $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$full = $match[0][0]; $off = $match[0][1];
					$num  = $match[1][0];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'percent',
						'form'      => 0,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $full,
						'form1_txt' => $num . '%',
					);
				}
			}
			if ( preg_match_all( '/\b(\d+)%/', $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$full = $match[0][0]; $off = $match[0][1];
					$num  = $match[1][0];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'percent',
						'form'      => 1,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $num . ' percent',
						'form1_txt' => $full,
					);
				}
			}

			// ── Sub-channel C: ordinal style ─────────────────────────────────
			// Written form → form 0;  Numeric form → form 1
			$written_pat = '/\b(' . implode( '|', array_keys( $ordinal_map ) ) . ')\b/i';
			if ( preg_match_all( $written_pat, $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$word = $match[0][0]; $off = $match[0][1]; $lc = strtolower( $word );
					if ( ! isset( $ordinal_map[ $lc ] ) ) { continue; }
					$numeric_form = $ordinal_map[ $lc ];
					// Preserve capitalisation
					$numeric_out = ( strtoupper( $word[0] ) === $word[0] )
						? strtoupper( $numeric_form[0] ) . substr( $numeric_form, 1 )
						: $numeric_form;
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'ordinal',
						'form'      => 0,
						'offset'    => $off,
						'old_len'   => strlen( $word ),
						'form0_txt' => $word,
						'form1_txt' => $numeric_form,
					);
				}
			}
			$numeric_ord_pat = '/\b(1st|2nd|3rd|4th|5th|6th|7th|8th|9th|10th|11th|12th)\b/i';
			if ( preg_match_all( $numeric_ord_pat, $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$full = $match[0][0]; $off = $match[0][1]; $lc = strtolower( $full );
					if ( ! isset( $ordinal_reverse[ $lc ] ) ) { continue; }
					$written = $ordinal_reverse[ $lc ];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'ordinal',
						'form'      => 1,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $written,
						'form1_txt' => $full,
					);
				}
			}
		}

		// Deterministic order: by segment then by offset descending within segment
		// (descending offset so apply_semantic_changes works correctly when we
		//  build the changes array)
		usort( $slots, function( $a, $b ) {
			return $a['seg'] !== $b['seg'] ? $a['seg'] - $b['seg'] : $a['offset'] - $b['offset'];
		} );

		return $slots;
	}

	// =========================================================================
	// CHANNEL 8: SPELLING VARIANTS
	// =========================================================================

	private function collect_spelling_slots( array $segs ) {
		return $this->collect_synonym_slots_for_pairs( $segs, $this->key_derived_pairs( self::spelling_pairs(), 'ch8' ) );
	}

	/**
	 * Generic synonym-style slot collector parameterised on an arbitrary pairs
	 * array, so Ch.8 and any future word-substitution channel can share the
	 * same regex machinery as Ch.6 without touching collect_synonym_slots().
	 */
	private function collect_synonym_slots_for_pairs( array $segs, array $pairs ) {
		$all_forms = array();
		foreach ( $pairs as $f0 => $f1 ) {
			$all_forms[] = preg_quote( $f0, '/' );
			$all_forms[] = preg_quote( $f1, '/' );
		}
		usort( $all_forms, function( $a, $b ) { return strlen( $b ) - strlen( $a ); } );
		$pattern  = '/\b(' . implode( '|', $all_forms ) . ')\b/iu';
		$form_map = array();
		foreach ( $pairs as $f0 => $f1 ) {
			$form_map[ strtolower( $f0 ) ] = array( 'key' => $f0, 'form' => 0 );
			$form_map[ strtolower( $f1 ) ] = array( 'key' => $f0, 'form' => 1 );
		}
		$slots = array();
		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] || $seg['skip'] ) { continue; }
			if ( ! preg_match_all( $pattern, $seg['content'], $m, PREG_OFFSET_CAPTURE ) ) { continue; }
			foreach ( $m[1] as $hit ) {
				$matched = $hit[0]; $lc = strtolower( $matched );
				if ( ! isset( $form_map[ $lc ] ) ) { continue; }
				$info    = $form_map[ $lc ];
				$slots[] = array( 'seg' => $si, 'offset' => $hit[1], 'matched' => $matched,
					'key' => $info['key'], 'form' => $info['form'] );
			}
		}
		return $slots;
	}

	private function encode_channel_spelling( $html, array $bits_r, $post_id ) {
		$pairs = $this->key_derived_pairs( self::spelling_pairs(), 'ch8' );
		$fn    = array( $this, 'collect_spelling_slots' );
		return $this->encode_semantic_channel( $html, $bits_r, $post_id, 'ch8', $fn, $pairs );
	}

	private function decode_channel_spelling( $html, $post_id ) {
		$fn = array( $this, 'collect_spelling_slots' );
		return $this->decode_semantic_channel( $html, $post_id, 'ch8', $fn );
	}

	// =========================================================================
	// CHANNEL 9: HYPHENATION CHOICES
	// =========================================================================

	private function collect_hyphenation_slots( array $segs ) {
		return $this->collect_synonym_slots_for_pairs( $segs, $this->key_derived_pairs( self::hyphenation_pairs(), 'ch9' ) );
	}

	private function encode_channel_hyphenation( $html, array $bits_r, $post_id ) {
		$pairs = $this->key_derived_pairs( self::hyphenation_pairs(), 'ch9' );
		$fn    = array( $this, 'collect_hyphenation_slots' );
		return $this->encode_semantic_channel( $html, $bits_r, $post_id, 'ch9', $fn, $pairs );
	}

	private function decode_channel_hyphenation( $html, $post_id ) {
		$fn = array( $this, 'collect_hyphenation_slots' );
		return $this->decode_semantic_channel( $html, $post_id, 'ch9', $fn );
	}

	// =========================================================================
	// CHANNEL 10: NUMBER / DATE STYLE
	// =========================================================================

	private function encode_channel_numbers( $html, array $bits_r, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_number_slots( $segs );
		$n     = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch10', $needed, $n );
		$changes   = array();
		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot     = $slots[ $slot_idx ];
			$target   = $bits_r[ $rank ];
			$new_text = ( 0 === $target ) ? $slot['form0_txt'] : $slot['form1_txt'];
			if ( $new_text !== substr( $segs[ $slot['seg'] ]['content'], $slot['offset'], $slot['old_len'] ) ) {
				$changes[ $slot['seg'] ][] = array(
					'offset'   => $slot['offset'],
					'old_len'  => $slot['old_len'],
					'new_text' => $new_text,
				);
			}
		}
		$this->apply_semantic_changes( $segs, $changes );
		return $this->join_segments( $segs );
	}

	private function decode_channel_numbers( $html, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_number_slots( $segs );
		$n     = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch10', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	// =========================================================================
	// CHANNEL 11: PUNCTUATION STYLE II
	// Sub-channel A: Em-dash spacing  "word—word" (form 0) ↔ "word — word" (form 1)
	// Sub-channel B: Comma before "too"  "…it too." (form 0) ↔ "…it, too." (form 1)
	// Sub-channel C: Introductory-clause comma  "In 2020 the" (form 0) ↔
	//                                            "In 2020, the" (form 1)
	// All three contribute to one unified flat slot list (same model as Ch.7).
	// =========================================================================

	/**
	 * Collect Ch.11 slots from text segments.
	 *
	 * Sub-channel A — em-dash spacing.
	 *   "word—word"   (no spaces, form 0)  ↔  "word — word"  (spaced, form 1)
	 *   Excludes the Ch.7 paired "— text —" pattern (which has whitespace on
	 *   *both* sides AND a matching closing dash) to prevent double-counting.
	 *   A single em-dash with different spacing is the target.
	 *
	 * Sub-channel B — comma before "too".
	 *   Detects "too" at a natural pause point (before sentence-ending punctuation
	 *   or at end of segment). "…as well too." and "…too" at line end are excluded
	 *   to avoid false positives on idiomatic constructions.
	 *
	 * Sub-channel C — introductory-clause comma.
	 *   Short prepositional/temporal/conditional openers (3–35 chars) followed
	 *   by an optional comma then a capital letter starting the main clause.
	 *   Only matches when the opener is at sentence start (preceded by nothing,
	 *   a full stop, or paragraph break in the segment).
	 */
	private function collect_punctuation2_slots( array $segs ) {
		$slots  = array();
		$emdash = self::EM_DASH;
		$em_q   = preg_quote( $emdash, '/' );

		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] || $seg['skip'] ) { continue; }
			$text = $seg['content'];

			// ── Sub-channel A: em-dash spacing ───────────────────────────────
			// Form 0: tight "word—word"  (letter immediately before AND after dash)
			// Form 1: spaced "word — word" (single space on each side)
			// Exclusion: do NOT match if the same dash is the opening of a Ch.7
			// paired aside "— text —" (i.e. a space+dash followed by text+space+dash).
			// We detect the Ch.7 pattern as: space+em+space...space+em.
			// Our A pattern therefore requires no space before the dash (tight left).

			// Tight form (form 0): \w—\w  — but not inside a paired aside
			if ( preg_match_all(
				'/(\w)' . $em_q . '(\w)/u',
				$text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER
			) ) {
				foreach ( $m as $match ) {
					$full   = $match[0][0]; // e.g. "a—b"
					$off    = $match[0][1];
					// The replaceable span is the dash alone (between the two word chars)
					// We replace just the dash+its-neighbours: offset points to start of full
					// but we want to replace "word—word" with "word — word"
					$left   = $match[1][0];
					$right  = $match[2][0];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'emdash_space',
						'form'      => 0,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $full,
						'form1_txt' => $left . ' ' . $emdash . ' ' . $right,
					);
				}
			}

			// Spaced form (form 1): \w + space + em + space + \w
			// Exclude dashes that are the *opening* of a Ch.7 paired aside
			// ("— inner text —").  Rather than a trailing-presence heuristic —
			// which causes false negatives when multiple standalone spaced dashes
			// appear in the same segment — we pre-scan for all Ch.7 aside ranges
			// and test each candidate's offset against those ranges directly.
			//
			// A Ch.7 aside has the exact form:  <space>—<space>…<space>—
			// (space on both sides of both dashes, 4–80 chars of inner content).
			// We record [start, end) byte ranges; any spaced-dash candidate whose
			// offset falls inside one of those ranges belongs to a Ch.7 aside and
			// must be excluded.

			// Build Ch.7 paired-aside byte ranges for this segment.
			$aside_ranges = array();
			$aside_pat = '/ ' . $em_q . ' ([^' . $em_q . '\n]{4,80}) ' . $em_q . '/u';
			if ( preg_match_all( $aside_pat, $text, $am, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $am as $am_match ) {
					$aside_ranges[] = array(
						'start' => $am_match[0][1],
						'end'   => $am_match[0][1] + strlen( $am_match[0][0] ),
					);
				}
			}

			if ( preg_match_all(
				'/(\w) ' . $em_q . ' (\w)/u',
				$text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER
			) ) {
				foreach ( $m as $match ) {
					$full = $match[0][0]; // "a — b"
					$off  = $match[0][1];
					// Skip if this offset falls inside a Ch.7 paired-aside range.
					$in_aside = false;
					foreach ( $aside_ranges as $range ) {
						if ( $off >= $range['start'] && $off < $range['end'] ) {
							$in_aside = true;
							break;
						}
					}
					if ( $in_aside ) { continue; }
					$left  = $match[1][0];
					$right = $match[2][0];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'emdash_space',
						'form'      => 1,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $left . $emdash . $right,
						'form1_txt' => $full,
					);
				}
			}

			// ── Sub-channel B: comma before "too" ────────────────────────────
			// Pattern: word + optional-comma + space + "too" + sentence-end punct
			// We detect both forms: "word too[,.]" and "word, too[,.]"
			// and allow "too" at end of text segment as well.
			if ( preg_match_all(
				'/(\w)(,?) (too)(?=[.,;!?\s]|$)/iu',
				$text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER
			) ) {
				foreach ( $m as $match ) {
					$pre_word  = $match[1][0];
					$comma     = $match[2][0]; // '' or ','
					$too       = $match[3][0];
					$off       = $match[1][1]; // start of pre_word
					$full      = $pre_word . $comma . ' ' . $too;
					$form      = ( ',' === $comma ) ? 1 : 0;
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'comma_too',
						'form'      => $form,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $pre_word . ' ' . $too,
						'form1_txt' => $pre_word . ', ' . $too,
					);
				}
			}

			// ── Sub-channel C: introductory-clause comma ──────────────────────
			// Detect short openers (prepositional / temporal / conditional) at
			// sentence start.  A sentence start is: beginning of segment, OR
			// immediately following ". " or ".\n".
			//
			// Pattern (applied with PREG_SET_ORDER so we can iterate matches):
			//   (^|(?<=\.\s))                         — sentence start anchor
			//   (In|On|At|By|After|Before|...)        — opener keyword
			//   \s+([^,.\n]{3,35})                    — opener body (3–35 chars)
			//   (,?)                                  — optional comma
			//   \s+([A-Z])                            — main clause capital
			//
			// The opener body deliberately excludes commas and full stops so the
			// match cannot swallow a complete clause.

			$intro_openers = 'In|On|At|By|For|After|Before|During|Since|Until|With|Without'
			               . '|As|Although|When|While|If|Though|Despite|Given|Following'
			               . '|Across|Around|Beyond|Throughout|Under|Over|Between';

			$intro_pat = '/(?:^|(?<=\.\s)|(?<=\.\n))'
			           . '((?:' . $intro_openers . ')\s+[^,.\n]{3,35})'
			           . '(,?)'
			           . '(\s+[A-Z])/u';

			if ( preg_match_all( $intro_pat, $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$opener    = $match[1][0];   // e.g. "In 2020"
					$comma     = $match[2][0];   // '' or ','
					$tail      = $match[3][0];   // e.g. " T"
					$off       = $match[1][1];
					$old_len   = strlen( $opener ) + strlen( $comma ) + strlen( $tail );
					$form      = ( ',' === $comma ) ? 1 : 0;
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'intro_comma',
						'form'      => $form,
						'offset'    => $off,
						'old_len'   => $old_len,
						'form0_txt' => $opener . $tail,             // no comma: "In 2020 T"
						'form1_txt' => $opener . ',' . $tail,      // comma: "In 2020, T"
					);
				}
			}
		}

		// Deterministic order: segment then byte offset
		usort( $slots, function( $a, $b ) {
			return $a['seg'] !== $b['seg'] ? $a['seg'] - $b['seg'] : $a['offset'] - $b['offset'];
		} );

		return $slots;
	}

	private function encode_channel_punctuation2( $html, array $bits_r, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_punctuation2_slots( $segs );
		$n     = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch11', $needed, $n );
		$changes   = array();
		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot     = $slots[ $slot_idx ];
			$target   = $bits_r[ $rank ];
			$new_text = ( 0 === $target ) ? $slot['form0_txt'] : $slot['form1_txt'];
			$current  = substr( $segs[ $slot['seg'] ]['content'], $slot['offset'], $slot['old_len'] );
			if ( $new_text !== $current ) {
				$changes[ $slot['seg'] ][] = array(
					'offset'   => $slot['offset'],
					'old_len'  => $slot['old_len'],
					'new_text' => $new_text,
				);
			}
		}
		$this->apply_semantic_changes( $segs, $changes );
		return $this->join_segments( $segs );
	}

	private function decode_channel_punctuation2( $html, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_punctuation2_slots( $segs );
		$n     = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch11', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	// =========================================================================
	// CHANNEL 12: CITATION AND TITLE STYLE
	// Sub-channel A: Attribution colon
	//   "Smith said:" (form 1) ↔ "Smith said" (form 0) before an opening quote.
	//   Matches attribution verbs from a curated list followed by optional colon
	//   then whitespace and a double-quote character (straight or curly).
	// Sub-channel B: Title italics vs. quotation marks
	//   <em>The Times</em> (form 1) ↔ "The Times" (form 0)
	//   Operates on the raw HTML string rather than segmented text, since the
	//   italic form spans tag boundaries. The result of encoding is a change to
	//   the raw HTML string.
	// =========================================================================

	/**
	 * Collect Ch.12 slots.
	 *
	 * @param  string $html  Raw post HTML (not pre-segmented).
	 * @return array  Slot list with 'html_offset' key instead of 'seg'/'offset',
	 *                since sub-channel B operates on the raw HTML string directly.
	 *                Sub-channel A slots carry 'source' => 'text'; B slots carry
	 *                'source' => 'html'. The encoder/decoder handle both.
	 */
	private function collect_citation_slots( $html ) {
		$slots = array();

		// ── Sub-channel A: attribution colon ─────────────────────────────────
		// Attribution verbs that conventionally appear before a direct quote.
		// Both "said:" and "said" are correct before a quoted passage; the colon
		// is a house-style choice, not a grammatical requirement.
		$attr_verbs = 'said|noted|wrote|stated|observed|added|explained|argued'
		            . '|claimed|warned|replied|continued|concluded|acknowledged'
		            . '|confirmed|declared|insisted|maintained|reported|suggested';

		// Match: <verb>(,?) followed by optional colon, then whitespace and a quote char.
		// We capture the whole span from the verb start to (but not including) the quote.
		$attr_pat = '/\b(' . $attr_verbs . ')(,?)\s*(:?)\s*(?=["“‘])/iu';

		// Run on segmented text (skip code/pre etc.) so we don't alter quoted code.
		$segs = $this->split_html( $html );
		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] || $seg['skip'] ) { continue; }
			$text = $seg['content'];
			if ( ! preg_match_all( $attr_pat, $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				continue;
			}
			foreach ( $m as $match ) {
				$verb    = $match[1][0];
				$comma   = $match[2][0]; // '' or ','
				$colon   = $match[3][0]; // '' or ':'
				$off     = $match[0][1];
				$old_len = strlen( $match[0][0] );
				$form    = ( ':' === $colon ) ? 1 : 0;
				// form0: "said" / "said," (no colon)
				// form1: "said:" / "said,:" (with colon)
				$slots[] = array(
					'source'    => 'seg',
					'seg'       => $si,
					'type'      => 'attr_colon',
					'form'      => $form,
					'offset'    => $off,
					'old_len'   => $old_len,
					'form0_txt' => $verb . $comma . ' ',
					'form1_txt' => $verb . $comma . ': ',
				);
			}
		}

		// ── Sub-channel B: title italics ↔ quotation marks ───────────────────
		// Detects title-like content in <em> or <i> tags and in straight double
		// quotes in prose context.
		//
		// Form 1 (italic): <em>Title Text</em> or <i>Title Text</i>
		//   where the inner text looks like a proper title (title-cased, 2–60 chars,
		//   no sentence-ending punctuation inside).
		//
		// Form 0 (quoted): "Title Text" (straight or curly open/close quotes)
		//   matched in a prose context (preceded by a space or punctuation).
		//
		// Both patterns operate on the raw $html string directly.

		// Form 1 — italic titles
		$italic_pat = '/<(em|i)>([^<]{2,60})<\/\1>/iu';
		if ( preg_match_all( $italic_pat, $html, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
			foreach ( $m as $match ) {
				$tag    = $match[1][0];       // 'em' or 'i'
				$inner  = $match[2][0];       // the title text
				$full   = $match[0][0];       // "<em>Title</em>"
				$off    = $match[0][1];

				// Require the inner text to look like a title:
				//  - at least one letter
				//  - no sentence-ending punctuation
				//  - not purely numeric
				if ( ! preg_match( '/[a-zA-Z]/', $inner ) ) { continue; }
				if ( preg_match( '/[.!?]$/', $inner ) ) { continue; }

				// Verify the match is in prose context (not inside a skip tag).
				// We do this by checking the segs: find which seg this raw offset falls in.
				// Cheaper approximation: check the 20 chars before the match in $html.
				$ctx = substr( $html, max( 0, $off - 20 ), 20 );
				if ( preg_match( '/<(?:code|pre|script|style)[^>]*>/i', $ctx ) ) { continue; }

				$slots[] = array(
					'source'    => 'html',
					'type'      => 'title_style',
					'form'      => 1,
					'html_off'  => $off,
					'old_len'   => strlen( $full ),
					'form0_txt' => '"' . $inner . '"',
					'form1_txt' => $full,
				);
			}
		}

		// Form 0 — quoted titles
		// Straight double-quote: "Title"  — must have a word char before the opening
		// quote and after the closing quote (prose context, not code).
		$quoted_pat = '/(?<=[\s,;:.(])"([A-Z\x{00C0}-\x{024F}][^"]{1,58}[^"\s])"/u';
		if ( preg_match_all( $quoted_pat, $html, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
			foreach ( $m as $match ) {
				$inner  = $match[1][0];
				$full   = $match[0][0]; // '"Title"'
				$off    = $match[0][1];

				// Skip if inside a skip-tag context (same quick heuristic)
				$ctx = substr( $html, max( 0, $off - 20 ), 20 );
				if ( preg_match( '/<(?:code|pre|script|style|a)[^>]*>/i', $ctx ) ) { continue; }

				$slots[] = array(
					'source'    => 'html',
					'type'      => 'title_style',
					'form'      => 0,
					'html_off'  => $off,
					'old_len'   => strlen( $full ),
					'form0_txt' => $full,
					'form1_txt' => '<em>' . $inner . '</em>',
				);
			}
		}

		// Sort all slots by their document position for deterministic ordering.
		// Seg-based slots use seg*1000000+offset as a proxy position; html-based
		// slots use html_off directly. Combine into a comparable key.
		usort( $slots, function( $a, $b ) {
			$pos_a = ( 'html' === $a['source'] ) ? $a['html_off'] : ( $a['seg'] * 1000000 + $a['offset'] );
			$pos_b = ( 'html' === $b['source'] ) ? $b['html_off'] : ( $b['seg'] * 1000000 + $b['offset'] );
			return $pos_a - $pos_b;
		} );

		return $slots;
	}

	/**
	 * Apply Ch.12 changes.  Slots with source='seg' go through apply_semantic_changes()
	 * on the segmented array; slots with source='html' are applied to the raw HTML
	 * string directly (in reverse offset order to preserve positions).
	 */
	private function encode_channel_citation( $html, array $bits_r, $post_id ) {
		$slots  = $this->collect_citation_slots( $html );
		$n      = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }

		$positions = $this->derive_positions( $post_id, 'ch12', $needed, $n );

		// Partition selected changes by source type
		$seg_changes  = array(); // seg_idx => [edits]
		$html_changes = array(); // flat list of {html_off, old_len, new_text}

		// We need the segs array for seg-source changes
		$segs = $this->split_html( $html );

		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot     = $slots[ $slot_idx ];
			$target   = $bits_r[ $rank ];
			$new_text = ( 0 === $target ) ? $slot['form0_txt'] : $slot['form1_txt'];

			if ( 'seg' === $slot['source'] ) {
				$current = substr( $segs[ $slot['seg'] ]['content'], $slot['offset'], $slot['old_len'] );
				if ( $new_text !== $current ) {
					$seg_changes[ $slot['seg'] ][] = array(
						'offset'   => $slot['offset'],
						'old_len'  => $slot['old_len'],
						'new_text' => $new_text,
					);
				}
			} else {
				// html-source: compare against current raw html at that offset
				$current = substr( $html, $slot['html_off'], $slot['old_len'] );
				if ( $new_text !== $current ) {
					$html_changes[] = array(
						'html_off' => $slot['html_off'],
						'old_len'  => $slot['old_len'],
						'new_text' => $new_text,
					);
				}
			}
		}

		// Apply seg-based changes
		if ( $seg_changes ) {
			$this->apply_semantic_changes( $segs, $seg_changes );
			$html = $this->join_segments( $segs );
		}

		// Apply html-based changes in reverse offset order (highest offset first
		// so earlier offsets remain valid as we shorten/lengthen the string)
		if ( $html_changes ) {
			usort( $html_changes, function( $a, $b ) { return $b['html_off'] - $a['html_off']; } );
			foreach ( $html_changes as $chg ) {
				$html = substr( $html, 0, $chg['html_off'] )
				      . $chg['new_text']
				      . substr( $html, $chg['html_off'] + $chg['old_len'] );
			}
		}

		return $html;
	}

	private function decode_channel_citation( $html, $post_id ) {
		$slots  = $this->collect_citation_slots( $html );
		$n      = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch12', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	// =========================================================================
	// CHANNEL 13: SENTENCE-COUNT PARITY
	//
	// Encodes one bit per qualifying paragraph by making the paragraph's
	// sentence count even (bit=0) or odd (bit=1).
	//
	// Adjustment mechanism: a one-clause phrase from a keyed pool is appended
	// to (or removed from) the final sentence of the paragraph.  The phrases
	// are chosen to be editorially natural continuations of almost any prose
	// sentence — connectives, qualifiers, and transitional fragments.
	//
	// Resilience: survives all Unicode normalisation, HTML minification, CDN
	// processing, and copy-paste through any rich-text editor.  Defeated only
	// by deliberate paraphrase or by adding/removing sentences from every
	// paragraph — a level of rewriting that defeats all steganographic
	// approaches.
	//
	// Slot: one per paragraph (<p> tag) containing at least 2 sentences and
	// at least 20 words.  Short paragraphs are skipped to keep edits natural.
	// =========================================================================

	/**
	 * Pool of short clauses that can be appended to any sentence to make the
	 * paragraph's sentence count odd.  Each is a natural continuation that
	 * reads as an editorial aside or qualifier.  They are selected by index
	 * derived from the HMAC key so the active set is site-specific.
	 *
	 * @return string[]
	 */
	private static function parity_clauses() {
		return array(
			', as noted above',
			', which is worth emphasising',
			', as discussed',
			', among other considerations',
			', it should be noted',
			', as the evidence suggests',
			', broadly speaking',
			', in most cases',
			', to varying degrees',
			', in this context',
			', on balance',
			', as a general rule',
			', for the most part',
			', at least in principle',
			', all things considered',
			', to some extent',
			', by most accounts',
			', in practical terms',
			', as one might expect',
			', in the broader sense',
			', under most circumstances',
			', from a practical standpoint',
			', taken as a whole',
			', in the final analysis',
			', when considered carefully',
			', with some caveats',
			', in general terms',
			', at a high level',
			', more often than not',
			', as a matter of course',
			', to put it simply',
			', broadly considered',
			', under normal conditions',
			', when viewed in context',
			', for most purposes',
			', to a significant degree',
			', all else being equal',
			', in the ordinary sense',
			', as commonly understood',
			', as a practical matter',
			', at the very least',
			', in most respects',
			', when taken together',
			', as is generally the case',
			', by and large',
			', in the long run',
			', in the short term',
			', across the board',
			', in many respects',
			', in real-world terms',
		);
	}

	/**
	 * Select a clause from the pool using a key-derived index.
	 * The selected clause is site-specific — an adversary cannot enumerate
	 * the active set without the HMAC key.
	 *
	 * @param  int    $post_id
	 * @param  int    $slot_rank  Position within the slot sequence.
	 * @return string
	 */
	private function select_parity_clause( $post_id, $slot_rank ) {
		$clauses = self::parity_clauses();
		$seed    = hash_hmac( 'sha256',
			'parity_clause:' . $post_id . ':' . $slot_rank,
			$this->get_key()
		);
		$idx = hexdec( substr( $seed, 0, 8 ) ) % count( $clauses );
		return $clauses[ $idx ];
	}

	/**
	 * Count sentences in a plain-text string.
	 * Uses a conservative heuristic: full-stop / exclamation / question mark
	 * followed by whitespace and a capital letter, or end of string.
	 *
	 * @param  string $text
	 * @return int
	 */
	private function count_sentences( $text ) {
		// Normalise: collapse whitespace, strip leading/trailing space
		$text = trim( preg_replace( '/\s+/', ' ', $text ) );
		if ( '' === $text ) { return 0; }
		// Split on sentence-ending punctuation followed by space+capital or end
		$n = preg_match_all( '/[.!?](?:\s+[A-Z]|$)/u', $text );
		// At least one sentence exists if the text is non-empty
		return max( 1, $n );
	}

	/**
	 * Collect Ch.13 slots.
	 * Each slot corresponds to one qualifying paragraph and records the current
	 * parity of its sentence count.
	 *
	 * @param  array $segs  HTML segments from split_html().
	 * @return array  Slot list.  Each entry:
	 *   seg         int    Segment index of the paragraph's closing </p> text node.
	 *   offset      int    Byte offset within that segment of the last sentence end.
	 *   old_len     int    0 (insertion point, not a replacement).
	 *   form        int    Current parity: 0=even, 1=odd.
	 *   clause      string The clause that would be appended to make count odd.
	 *   sentences   int    Current sentence count.
	 *   para_text   string Full paragraph text (for count verification on decode).
	 */
	private function collect_parity_slots( array $segs ) {
		$slots       = array();
		$in_para     = false;
		$para_start  = null;   // seg index where current <p> body begins
		$para_segs   = array(); // [seg_idx => text_content] accumulated for current <p>
		$slot_rank   = 0;

		// We need the post_id to select the clause — not available here.
		// We store the slot without the clause; the encode/decode methods
		// pass the post_id and call select_parity_clause() themselves.

		foreach ( $segs as $si => $seg ) {
			if ( 'tag' === $seg['type'] ) {
				$tag = strtolower( $seg['content'] );
				if ( preg_match( '/^<p(\s|>)/i', $tag ) ) {
					$in_para    = true;
					$para_segs  = array();
					$para_start = $si;
				} elseif ( '</p>' === strtolower( trim( $tag ) ) && $in_para ) {
					// End of paragraph — evaluate
					$in_para = false;
					// Concatenate all text segments in this paragraph
					$para_text = '';
					foreach ( $para_segs as $pidx => $ptxt ) {
						$para_text .= $ptxt;
					}
					$plain = wp_strip_all_tags( $para_text );
					$words = str_word_count( $plain );
					if ( $words < 20 ) { continue; } // too short
					$n_sentences = $this->count_sentences( $plain );
					if ( $n_sentences < 2 ) { continue; } // single sentence — skip
					// Find the last text segment in this paragraph for insertion
					$last_text_si = null;
					foreach ( $para_segs as $pidx => $ptxt ) {
						if ( '' !== trim( $ptxt ) ) { $last_text_si = $pidx; }
					}
					if ( null === $last_text_si ) { continue; }
					// Find the insertion point: after the last sentence-ending punct
					$last_text    = $segs[ $last_text_si ]['content'];
					$insert_offset = $this->find_last_sentence_end( $last_text );
					if ( false === $insert_offset ) { continue; }
					$slots[] = array(
						'seg'        => $last_text_si,
						'offset'     => $insert_offset,
						'old_len'    => 0,
						'form'       => $n_sentences % 2, // 0=even, 1=odd
						'sentences'  => $n_sentences,
						'slot_rank'  => $slot_rank,
					);
					$slot_rank++;
				}
			} elseif ( $in_para && 'text' === $seg['type'] && ! $seg['skip'] ) {
				$para_segs[ $si ] = $seg['content'];
			}
		}
		return $slots;
	}

	/**
	 * Find the byte offset just after the last sentence-ending punctuation
	 * in $text.  Returns false if none found.
	 *
	 * @param  string $text
	 * @return int|false
	 */
	private function find_last_sentence_end( $text ) {
		// Find the last occurrence of . ! ? before optional closing punctuation
		if ( ! preg_match_all( '/[.!?]["\')]?\s*/u', $text, $m, PREG_OFFSET_CAPTURE ) ) {
			return false;
		}
		$last = end( $m[0] );
		// Return offset just before the trailing whitespace
		$punct_end = $last[1] + strlen( rtrim( $last[0] ) );
		return $punct_end;
	}

	private function encode_channel_parity( $html, array $bits_r, $post_id ) {
		$segs   = $this->split_html( $html );
		$slots  = $this->collect_parity_slots( $segs );
		$n      = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch13', $needed, $n );
		$changes   = array();
		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot        = $slots[ $slot_idx ];
			$target_bit  = $bits_r[ $rank ];
			$current_par = $slot['form']; // 0=even, 1=odd
			if ( $target_bit === $current_par ) { continue; } // already correct
			// Need to flip parity: append a clause to make even→odd or odd→even.
			// For odd→even: we'd need to add a second sentence, which is more
			// intrusive.  Simpler: when current=odd and target=even, we check
			// whether the slot already has a clause appended and remove it.
			// For current=even and target=odd: append clause.
			$clause = $this->select_parity_clause( $post_id, $slot['slot_rank'] );
			if ( 0 === $current_par && 1 === $target_bit ) {
				// even → odd: append clause before the sentence-ending punctuation
				$text    = $segs[ $slot['seg'] ]['content'];
				$off     = $slot['offset'];
				// Insert clause just before the punctuation mark at $off
				$punct   = substr( $text, $off, 1 );
				$new_txt = substr( $text, 0, $off ) . $clause . substr( $text, $off );
				$changes[ $slot['seg'] ][] = array(
					'offset'   => $off,
					'old_len'  => 0,
					'new_text' => $clause,
				);
			} else {
				// odd → even: check if the clause we'd have appended is present
				// and remove it.  If it's not present, we can't flip — skip.
				$text    = $segs[ $slot['seg'] ]['content'];
				$off     = $slot['offset'];
				if ( false !== ($cp = strpos( $text, $clause, max( 0, $off - strlen( $clause ) - 5 ) ) ) ) {
					$changes[ $slot['seg'] ][] = array(
						'offset'   => $cp,
						'old_len'  => strlen( $clause ),
						'new_text' => '',
					);
				}
			}
		}
		$this->apply_semantic_changes( $segs, $changes );
		return $this->join_segments( $segs );
	}

	private function decode_channel_parity( $html, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_parity_slots( $segs );
		$n     = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch13', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	// =========================================================================
	// CHANNEL 14: WORD-COUNT PARITY
	//
	// Encodes one bit per qualifying sentence by making the sentence's word
	// count even (bit=0) or odd (bit=1).
	//
	// Adjustment mechanism: a single filler word from a keyed pool ("also",
	// "still", "then", "now", "thus", "indeed", "clearly" etc.) is inserted
	// at or removed from a natural position within the sentence.  The words
	// are selected to blend into analytical/editorial prose without changing
	// meaning.  Position within the sentence is also key-derived.
	//
	// Resilience: identical to Ch.13 — survives everything except deliberate
	// rewriting of individual sentences.
	//
	// Slot: one per sentence of 10+ words in a qualifying prose paragraph.
	// =========================================================================

	/**
	 * Pool of single-word fillers that can be inserted into most prose
	 * sentences without changing meaning.  Selected by key-derived index.
	 *
	 * @return string[]
	 */
	private static function filler_words() {
		return array(
			'also', 'still', 'then', 'now', 'thus', 'indeed', 'clearly',
			'certainly', 'notably', 'largely', 'broadly', 'generally',
			'typically', 'often', 'usually', 'primarily', 'mainly',
			'simply', 'merely', 'effectively', 'essentially', 'fundamentally',
			'specifically', 'particularly', 'especially', 'precisely',
			'naturally', 'obviously', 'evidently', 'accordingly', 'therefore',
			'consequently', 'subsequently', 'ultimately', 'eventually',
			'arguably', 'admittedly', 'importantly', 'significantly',
			'remarkably', 'notably', 'plainly', 'practically', 'critically',
		);
	}

	/**
	 * Select a filler word using a key-derived index.
	 *
	 * @param  int $post_id
	 * @param  int $slot_rank
	 * @return string
	 */
	private function select_filler_word( $post_id, $slot_rank ) {
		$words = self::filler_words();
		$seed  = hash_hmac( 'sha256',
			'filler_word:' . $post_id . ':' . $slot_rank,
			$this->get_key()
		);
		$idx = hexdec( substr( $seed, 0, 8 ) ) % count( $words );
		return $words[ $idx ];
	}

	/**
	 * Select an insertion position (word index) within a sentence using a
	 * key-derived index, biased toward the middle of the sentence to look
	 * most natural.
	 *
	 * @param  int $post_id
	 * @param  int $slot_rank
	 * @param  int $word_count
	 * @return int  Word index (0-based) after which to insert.
	 */
	private function select_insert_position( $post_id, $slot_rank, $word_count ) {
		$seed = hash_hmac( 'sha256',
			'filler_pos:' . $post_id . ':' . $slot_rank,
			$this->get_key()
		);
		// Bias toward middle third of the sentence
		$lo  = (int) floor( $word_count / 3 );
		$hi  = (int) ceil( $word_count * 2 / 3 );
		$range = max( 1, $hi - $lo );
		return $lo + ( hexdec( substr( $seed, 0, 8 ) ) % $range );
	}

	/**
	 * Collect Ch.14 slots — one per qualifying sentence.
	 *
	 * @param  array $segs
	 * @return array
	 */
	private function collect_wordcount_slots( array $segs ) {
		$slots     = array();
		$slot_rank = 0;

		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] || $seg['skip'] ) { continue; }
			$text = $seg['content'];
			// Split into sentences
			if ( ! preg_match_all(
				'/[^.!?]*[.!?]+/u',
				$text, $m, PREG_OFFSET_CAPTURE
			) ) { continue; }

			foreach ( $m[0] as $sent_match ) {
				$sent     = $sent_match[0];
				$sent_off = $sent_match[1];
				$wc       = str_word_count( wp_strip_all_tags( $sent ) );
				if ( $wc < 10 ) { continue; } // too short to insert naturally
				$slots[] = array(
					'seg'       => $si,
					'sent_off'  => $sent_off,
					'sent_len'  => strlen( $sent ),
					'sent_text' => $sent,
					'form'      => $wc % 2, // 0=even, 1=odd
					'word_count'=> $wc,
					'slot_rank' => $slot_rank,
				);
				$slot_rank++;
			}
		}
		return $slots;
	}

	/**
	 * Find the byte offset within $sent after which to insert the filler word,
	 * targeting the $insert_after-th word boundary (0-based).
	 *
	 * @param  string $sent
	 * @param  int    $insert_after  Word index after which to insert.
	 * @return int|false  Byte offset, or false if not found.
	 */
	private function find_word_boundary( $sent, $insert_after ) {
		$count = 0;
		if ( ! preg_match_all( '/\S+/u', $sent, $m, PREG_OFFSET_CAPTURE ) ) {
			return false;
		}
		$words = $m[0];
		if ( $insert_after >= count( $words ) ) {
			$insert_after = count( $words ) - 1;
		}
		$word   = $words[ $insert_after ];
		$offset = $word[1] + strlen( $word[0] ); // end of the target word
		return $offset;
	}

	private function encode_channel_wordcount( $html, array $bits_r, $post_id ) {
		$segs   = $this->split_html( $html );
		$slots  = $this->collect_wordcount_slots( $segs );
		$n      = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch14', $needed, $n );
		$changes   = array();
		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot       = $slots[ $slot_idx ];
			$target_bit = $bits_r[ $rank ];
			if ( $target_bit === $slot['form'] ) { continue; }
			$filler     = $this->select_filler_word( $post_id, $slot['slot_rank'] );
			$ins_after  = $this->select_insert_position( $post_id, $slot['slot_rank'], $slot['word_count'] );
			$sent       = $segs[ $slot['seg'] ]['content'];
			// Absolute offset of insertion point within segment
			$seg_off    = $slot['sent_off'];
			$rel_off    = $this->find_word_boundary( $slot['sent_text'], $ins_after );
			if ( false === $rel_off ) { continue; }
			$abs_off    = $seg_off + $rel_off;
			if ( 0 === $slot['form'] && 1 === $target_bit ) {
				// even → odd: insert filler word after boundary (with spaces)
				$changes[ $slot['seg'] ][] = array(
					'offset'   => $abs_off,
					'old_len'  => 0,
					'new_text' => ' ' . $filler,
				);
			} else {
				// odd → even: remove the filler word if present
				$search = ' ' . $filler;
				$seg_content = $segs[ $slot['seg'] ]['content'];
				$find_from   = max( 0, $abs_off - strlen( $filler ) - 5 );
				$found = strpos( $seg_content, $search, $find_from );
				if ( false !== $found ) {
					$changes[ $slot['seg'] ][] = array(
						'offset'   => $found,
						'old_len'  => strlen( $search ),
						'new_text' => '',
					);
				}
			}
		}
		$this->apply_semantic_changes( $segs, $changes );
		return $this->join_segments( $segs );
	}

	private function decode_channel_wordcount( $html, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_wordcount_slots( $segs );
		$n     = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch14', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	// =========================================================================
	// PAYLOAD
	// =========================================================================

	// =========================================================================
	// VERSION HELPERS  (runtime, not compile-time constants)
	// =========================================================================

	/**
	 * Returns the payload version that should be used for NEW injections.
	 * Reads the wp_options flag set in the admin settings card.
	 *
	 * @return int  1 or 2
	 */
	private function active_payload_version() {
		return ( 2 === (int) self::cget( 'payload_version', 1  ) ) ? 2 : 1;
	}

	/**
	 * Byte count for the active (encode) version.
	 */
	private function payload_bytes() {
		return ( 2 === $this->active_payload_version() )
			? self::PAYLOAD_BYTES_V2
			: self::PAYLOAD_BYTES_V1;
	}

	/**
	 * Bit count for the active (encode) version.
	 */
	private function payload_bits() {
		return ( 2 === $this->active_payload_version() )
			? self::PAYLOAD_BITS_V2
			: self::PAYLOAD_BITS_V1;
	}

	// =========================================================================
	// PAYLOAD BUILD / VERIFY  (version-aware)
	// =========================================================================

	/**
	 * Build a payload binary string for encoding.
	 * Uses the version configured in settings.
	 *
	 * @param  int      $post_id
	 * @param  int|null $timestamp  Unix timestamp; defaults to now.
	 * @return string   Raw binary payload.
	 */
	public function build_payload( $post_id, $timestamp = null ) {
		if ( null === $timestamp ) {
			// Honour a stored stamp so that re-fingerprint bulk actions can
			// bind a fresh timestamp to the current key without touching content.
			$stamp = (int) get_post_meta( (int) $post_id, '_archivio_canary_stamp', true );
			$timestamp = $stamp > 0 ? $stamp : time();
		}
		$post_id   = (int) $post_id   & 0xFFFFFFFF;
		$timestamp = (int) $timestamp & 0xFFFFFFFF;

		if ( 2 === $this->active_payload_version() ) {
			// v2: [version 1B][post_id 4B][timestamp 4B][HMAC-SHA256[0:8] 8B] = 17 bytes
			$ver    = chr( self::PAYLOAD_VERSION_2 );
			$header = $ver . pack( 'NN', $post_id, $timestamp );
			$mac    = substr( hash_hmac( 'sha256', $header, $this->get_key(), true ), 0, 8 );
			return $header . $mac;
		}

		// v1 (default): [post_id 4B][timestamp 4B][HMAC-SHA256[0:6] 6B] = 14 bytes
		$header = pack( 'NN', $post_id, $timestamp );
		$mac    = substr( hash_hmac( 'sha256', $header, $this->get_key(), true ), 0, 6 );
		return $header . $mac;
	}

	/**
	 * Attempt to verify a raw binary payload.
	 * Auto-detects v1 vs v2 by length and version byte; tries both if ambiguous.
	 *
	 * Returns an array with keys: post_id, timestamp, valid, payload_version
	 * or false if the payload cannot be interpreted at all.
	 *
	 * @param  string $payload  Raw binary.
	 * @return array|false
	 */
	public function verify_payload( $payload ) {
		$len = strlen( $payload );

		// ── Try v2 first ─────────────────────────────────────────────────────
		if ( self::PAYLOAD_BYTES_V2 === $len && ord( $payload[0] ) === self::PAYLOAD_VERSION_2 ) {
			$header       = substr( $payload, 0, 9 ); // ver + post_id + timestamp
			$parts        = unpack( 'Npost_id/Ntimestamp', substr( $payload, 1, 8 ) );
			$mac_found    = substr( $payload, 9, 8 );
			$mac_expected = substr( hash_hmac( 'sha256', $header, $this->get_key(), true ), 0, 8 );
			return array(
				'post_id'         => (int) $parts['post_id'],
				'timestamp'       => (int) $parts['timestamp'],
				'valid'           => hash_equals( $mac_expected, $mac_found ),
				'payload_version' => 2,
			);
		}

		// ── Try v1 ───────────────────────────────────────────────────────────
		if ( self::PAYLOAD_BYTES_V1 === $len ) {
			$parts        = unpack( 'Npost_id/Ntimestamp', substr( $payload, 0, 8 ) );
			$mac_found    = substr( $payload, 8, 6 );
			$mac_expected = substr( hash_hmac( 'sha256', substr( $payload, 0, 8 ), $this->get_key(), true ), 0, 6 );
			return array(
				'post_id'         => (int) $parts['post_id'],
				'timestamp'       => (int) $parts['timestamp'],
				'valid'           => hash_equals( $mac_expected, $mac_found ),
				'payload_version' => 1,
			);
		}

		return false;
	}

	// =========================================================================
	// BIT HELPERS
	// =========================================================================

	private function payload_to_bits( $payload ) {
		$bits = array();
		for ( $i = 0, $n = strlen( $payload ); $i < $n; $i++ ) {
			$byte = ord( $payload[ $i ] );
			for ( $b = 7; $b >= 0; $b-- ) { $bits[] = ( $byte >> $b ) & 1; }
		}
		return $bits;
	}

	private function bits_to_payload( array $bits, $payload_bits = null ) {
		if ( null === $payload_bits ) { $payload_bits = $this->payload_bits(); }
		$p = '';
		for ( $i = 0; $i < $payload_bits; $i += 8 ) {
			$byte = 0;
			for ( $b = 0; $b < 8; $b++ ) {
				$byte = ( $byte << 1 ) | ( isset( $bits[ $i + $b ] ) ? (int) $bits[ $i + $b ] : 0 );
			}
			$p .= chr( $byte );
		}
		return $p;
	}

	private function expand_bits( array $bits ) {
		$out = array();
		foreach ( $bits as $bit ) {
			for ( $r = 0; $r < self::REDUNDANCY; $r++ ) { $out[] = $bit; }
		}
		return $out;
	}

	private function collapse_bits( array $stream, $payload_bits = null ) {
		if ( null === $payload_bits ) { $payload_bits = $this->payload_bits(); }
		$bits = array();
		for ( $i = 0; $i < $payload_bits; $i++ ) {
			$ones = 0;
			for ( $r = 0; $r < self::REDUNDANCY; $r++ ) {
				$idx = $i * self::REDUNDANCY + $r;
				if ( isset( $stream[ $idx ] ) && $stream[ $idx ] ) { $ones++; }
			}
			$bits[] = ( $ones > self::REDUNDANCY / 2 ) ? 1 : 0;
		}
		return $bits;
	}

	// =========================================================================
	// POSITION DERIVATION
	// =========================================================================

	private function derive_positions( $post_id, $channel_id, $count, $max ) {
		if ( $count <= 0 || $max <= 0 ) { return array(); }
		$count    = min( $count, $max );
		$seed     = hash_hmac( 'sha256', (string) $post_id . ':' . $channel_id, $this->get_key(), true );
		$selected = array();
		$state    = $seed;
		for ( $a = 0; count( $selected ) < $count && $a < $count * 30; $a++ ) {
			$state = hash( 'sha256', $state, true );
			$pos   = unpack( 'N', substr( $state, 0, 4 ) )[1] % $max;
			if ( ! in_array( $pos, $selected, true ) ) { $selected[] = $pos; }
		}

		// Deterministic fallback: when $count approaches $max the rejection sampler
		// can exhaust its iteration budget before filling every slot (e.g. a post
		// with exactly as many slots as bits needed).  Rather than silently returning
		// fewer positions — which causes the encoder to embed fewer bits than the
		// decoder expects, producing an HMAC failure on a post that appeared to have
		// sufficient coverage — we fill the shortfall from the lowest-numbered
		// positions not already chosen.
		//
		// Critically, both encoder and decoder call this function with identical
		// arguments, so they reach the same fallback positions deterministically.
		// Existing fingerprints are unaffected: the fallback only fires in cases
		// where the old code would have returned an incomplete array.
		if ( count( $selected ) < $count ) {
			$selected_set = array_flip( $selected ); // O(1) membership test
			for ( $i = 0; $i < $max && count( $selected ) < $count; $i++ ) {
				if ( ! isset( $selected_set[ $i ] ) ) {
					$selected[]         = $i;
					$selected_set[ $i ] = true;
				}
			}
		}

		sort( $selected );
		return $selected;
	}

	// =========================================================================
	// HTML SEGMENT HELPERS
	// =========================================================================

	private function split_html( $html ) {
		$parts = preg_split( '/(<[^>]*>)/s', $html, -1, PREG_SPLIT_DELIM_CAPTURE );
		$segs  = array();
		$depth = array();
		foreach ( $parts as $p ) {
			if ( '' === $p ) { continue; }
			if ( preg_match( '/^<[^>]*>$/s', $p ) ) {
				if ( preg_match( '/^<\/(\w+)/i', $p, $m ) ) {
					$tag = strtolower( $m[1] );
					if ( isset( $depth[ $tag ] ) && $depth[ $tag ] > 0 ) { $depth[ $tag ]--; }
				} elseif ( preg_match( '/^<(\w+)/i', $p, $m ) && substr( $p, -2 ) !== '/>' ) {
					$tag = strtolower( $m[1] );
					$depth[ $tag ] = ( $depth[ $tag ] ?? 0 ) + 1;
				}
				$segs[] = array( 'type' => 'tag', 'content' => $p, 'skip' => false );
			} else {
				$in_skip = false;
				foreach ( self::$SEMANTIC_SKIP_TAGS as $st ) {
					if ( ! empty( $depth[ $st ] ) ) { $in_skip = true; break; }
				}
				$segs[] = array( 'type' => 'text', 'content' => $p, 'skip' => $in_skip );
			}
		}
		return $segs;
	}

	private function join_segments( array $segs ) {
		return implode( '', array_column( $segs, 'content' ) );
	}

	// =========================================================================
	// CHANNEL 1: ZERO-WIDTH CHARACTERS
	// =========================================================================

	private function encode_channel_zw( $html, array $bits_r ) {
		$segs  = $this->split_html( $html );
		$bi    = 0;
		$total = count( $bits_r );
		foreach ( $segs as &$seg ) {
			if ( 'text' !== $seg['type'] || $bi >= $total ) { continue; }
			$chars  = preg_split( '//u', $seg['content'], -1, PREG_SPLIT_NO_EMPTY );
			$result = '';
			$prev   = '';
			foreach ( $chars as $char ) {
				$word_start = preg_match( '/[\p{L}\p{N}]/u', $char )
				              && ( '' === $prev || preg_match( '/\s/u', $prev ) );
				if ( $word_start && $bi < $total ) {
					$result .= ( 0 === $bits_r[ $bi++ ] ) ? self::ZW_ZERO : self::ZW_ONE;
				}
				$result .= $char;
				$prev    = $char;
			}
			$seg['content'] = $result;
		}
		unset( $seg );
		return $this->join_segments( $segs );
	}

	private function decode_channel_zw( $html ) {
		$text = wp_strip_all_tags( $html );
		$bits = array();
		$len  = mb_strlen( $text, 'UTF-8' );
		for ( $i = 0; $i < $len; $i++ ) {
			$c = mb_substr( $text, $i, 1, 'UTF-8' );
			if ( self::ZW_ZERO === $c ) { $bits[] = 0; }
			elseif ( self::ZW_ONE === $c ) { $bits[] = 1; }
		}
		return $bits;
	}

	// =========================================================================
	// CHANNEL 2: SPACE VARIANTS
	// =========================================================================

	private function encode_channel_spaces( $html, array $bits_r, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = array();
		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] ) { continue; }
			$chars = preg_split( '//u', $seg['content'], -1, PREG_SPLIT_NO_EMPTY );
			foreach ( $chars as $ci => $c ) {
				if ( self::SP_REGULAR === $c ) { $slots[] = array( 's' => $si, 'c' => $ci ); }
			}
		}
		$n = count( $slots ); $needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch2', $needed, $n );
		foreach ( $positions as $rank => $si ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $si ] ) ) { break; }
			if ( 1 === $bits_r[ $rank ] ) {
				$loc   = $slots[ $si ];
				$chars = preg_split( '//u', $segs[ $loc['s'] ]['content'], -1, PREG_SPLIT_NO_EMPTY );
				$chars[ $loc['c'] ] = self::SP_THIN;
				$segs[ $loc['s'] ]['content'] = implode( '', $chars );
			}
		}
		return $this->join_segments( $segs );
	}

	private function decode_channel_spaces( $html, $post_id ) {
		$segs = $this->split_html( $html ); $slots = array();
		foreach ( $segs as $seg ) {
			if ( 'text' !== $seg['type'] ) { continue; }
			$chars = preg_split( '//u', $seg['content'], -1, PREG_SPLIT_NO_EMPTY );
			foreach ( $chars as $c ) {
				if ( self::SP_REGULAR === $c || self::SP_THIN === $c ) {
					$slots[] = ( self::SP_THIN === $c ) ? 1 : 0;
				}
			}
		}
		$n = count( $slots ); $needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch2', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $si ) {
			if ( isset( $slots[ $si ] ) ) { $out[ $r ] = $slots[ $si ]; }
		}
		return $out;
	}

	// =========================================================================
	// CHANNEL 3: APOSTROPHE VARIANTS
	// =========================================================================

	private function encode_channel_apostrophes( $html, array $bits_r, $post_id ) {
		$segs  = $this->split_html( $html ); $slots = array();
		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] ) { continue; }
			$chars = preg_split( '//u', $seg['content'], -1, PREG_SPLIT_NO_EMPTY );
			foreach ( $chars as $ci => $c ) {
				if ( self::APOS_STRAIGHT === $c ) { $slots[] = array( 's' => $si, 'c' => $ci ); }
			}
		}
		$n = count( $slots ); $needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch3', $needed, $n );
		foreach ( $positions as $rank => $si ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $si ] ) ) { break; }
			if ( 1 === $bits_r[ $rank ] ) {
				$loc   = $slots[ $si ];
				$chars = preg_split( '//u', $segs[ $loc['s'] ]['content'], -1, PREG_SPLIT_NO_EMPTY );
				$chars[ $loc['c'] ] = self::APOS_CURLY;
				$segs[ $loc['s'] ]['content'] = implode( '', $chars );
			}
		}
		return $this->join_segments( $segs );
	}

	private function decode_channel_apostrophes( $html, $post_id ) {
		$segs = $this->split_html( $html ); $slots = array();
		foreach ( $segs as $seg ) {
			if ( 'text' !== $seg['type'] ) { continue; }
			$chars = preg_split( '//u', $seg['content'], -1, PREG_SPLIT_NO_EMPTY );
			foreach ( $chars as $c ) {
				if ( self::APOS_STRAIGHT === $c || self::APOS_CURLY === $c ) {
					$slots[] = ( self::APOS_CURLY === $c ) ? 1 : 0;
				}
			}
		}
		$n = count( $slots ); $needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch3', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $si ) {
			if ( isset( $slots[ $si ] ) ) { $out[ $r ] = $slots[ $si ]; }
		}
		return $out;
	}

	// =========================================================================
	// CHANNEL 4: SOFT HYPHENS
	// =========================================================================

	private function collect_intraword_slots( array $segs ) {
		$slots = array();
		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] ) { continue; }
			preg_match_all( '/\p{L}{' . self::MIN_WORD_LENGTH . ',}/u', $seg['content'], $m );
			foreach ( $m[0] as $word ) {
				$wl = mb_strlen( $word, 'UTF-8' );
				for ( $i = 1; $i < $wl - 1; $i++ ) {
					$slots[] = array( 'seg_idx' => $si, 'word' => $word, 'char_pos' => $i );
				}
			}
		}
		return $slots;
	}

	private function encode_channel_soft_hyphens( $html, array $bits_r, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_intraword_slots( $segs );
		$n     = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch4', $needed, $n );
		$ins = array();
		foreach ( $positions as $rank => $si ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $si ] ) ) { break; }
			if ( 1 === $bits_r[ $rank ] ) {
				$slot  = $slots[ $si ];
				$s_idx = $slot['seg_idx'];
				if ( ! isset( $ins[ $s_idx ] ) ) { $ins[ $s_idx ] = array(); }
				$ins[ $s_idx ][] = array( 'word' => $slot['word'], 'char_pos' => $slot['char_pos'] );
			}
		}
		foreach ( $ins as $s_idx => $list ) {
			$text = $segs[ $s_idx ]['content'];
			foreach ( array_reverse( $list ) as $item ) {
				$w = $item['word']; $cp = $item['char_pos'];
				$before = mb_substr( $w, 0, $cp, 'UTF-8' );
				$after  = mb_substr( $w, $cp, null, 'UTF-8' );
				$marked = $before . self::SOFT_HYPHEN . $after;
				$pos = mb_strpos( $text, $w, 0, 'UTF-8' );
				if ( false !== $pos ) {
					$text = mb_substr( $text, 0, $pos, 'UTF-8' )
					      . $marked
					      . mb_substr( $text, $pos + mb_strlen( $w, 'UTF-8' ), null, 'UTF-8' );
				}
			}
			$segs[ $s_idx ]['content'] = $text;
		}
		return $this->join_segments( $segs );
	}

	private function decode_channel_soft_hyphens( $html, $post_id ) {
		$clean      = str_replace( self::SOFT_HYPHEN, '', $html );
		$segs_clean = $this->split_html( $clean );
		$segs_stego = $this->split_html( $html );
		$slots      = $this->collect_intraword_slots( $segs_clean );
		$slot_bits  = array();
		foreach ( $slots as $slot ) {
			$si     = $slot['seg_idx'];
			$target = mb_substr( $slot['word'], 0, $slot['char_pos'], 'UTF-8' ) . self::SOFT_HYPHEN;
			$slot_bits[] = ( false !== mb_strpos( $segs_stego[ $si ]['content'] ?? '', $target, 0, 'UTF-8' ) ) ? 1 : 0;
		}
		$n = count( $slot_bits ); $needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch4', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $si ) {
			if ( isset( $slot_bits[ $si ] ) ) { $out[ $r ] = $slot_bits[ $si ]; }
		}
		return $out;
	}

	// =========================================================================
	// CHANNEL 5: CONTRACTION ENCODING
	// =========================================================================

	private function collect_contraction_slots( array $segs ) {
		return $this->collect_synonym_slots_for_pairs(
			$segs,
			$this->key_derived_pairs( self::contraction_pairs(), 'ch5' )
		);
	}

	private function apply_semantic_changes( array &$segs, array $changes ) {
		foreach ( $changes as $si => $edits ) {
			usort( $edits, function( $a, $b ) { return $b['offset'] - $a['offset']; } );
			$text = $segs[ $si ]['content'];
			foreach ( $edits as $edit ) {
				$text = substr( $text, 0, $edit['offset'] )
				      . $edit['new_text']
				      . substr( $text, $edit['offset'] + $edit['old_len'] );
			}
			$segs[ $si ]['content'] = $text;
		}
	}

	private function encode_semantic_channel( $html, array $bits_r, $post_id, $channel_id,
											  callable $collect_fn, array $pairs ) {
		$segs  = $this->split_html( $html );
		$slots = $collect_fn( $segs );
		$n     = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, $channel_id, $needed, $n );
		$changes   = array();
		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot      = $slots[ $slot_idx ];
			$key       = $slot['key'];
			$new_form  = ( 0 === $bits_r[ $rank ] ) ? $key : $pairs[ $key ];
			$new_form  = $this->match_case( $slot['matched'], $new_form );
			if ( $new_form !== $slot['matched'] ) {
				$changes[ $slot['seg'] ][] = array(
					'offset'   => $slot['offset'],
					'old_len'  => strlen( $slot['matched'] ),
					'new_text' => $new_form,
				);
			}
		}
		$this->apply_semantic_changes( $segs, $changes );
		return $this->join_segments( $segs );
	}

	private function decode_semantic_channel( $html, $post_id, $channel_id, callable $collect_fn ) {
		$segs  = $this->split_html( $html );
		$slots = $collect_fn( $segs );
		$n     = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, $channel_id, $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	private function encode_channel_contractions( $html, array $bits_r, $post_id ) {
		$pairs = $this->key_derived_pairs( self::contraction_pairs(), 'ch5' );
		$fn    = array( $this, 'collect_contraction_slots' );
		return $this->encode_semantic_channel( $html, $bits_r, $post_id, 'ch5', $fn, $pairs );
	}

	private function decode_channel_contractions( $html, $post_id ) {
		$fn = array( $this, 'collect_contraction_slots' );
		return $this->decode_semantic_channel( $html, $post_id, 'ch5', $fn );
	}

	// =========================================================================
	// CHANNEL 6: SYNONYM SUBSTITUTION
	// =========================================================================

	private function collect_synonym_slots( array $segs ) {
		return $this->collect_synonym_slots_for_pairs(
			$segs,
			$this->key_derived_pairs( self::synonym_pairs(), 'ch6' )
		);
	}

	private function encode_channel_synonyms( $html, array $bits_r, $post_id ) {
		$pairs = $this->key_derived_pairs( self::synonym_pairs(), 'ch6' );
		$fn    = array( $this, 'collect_synonym_slots' );
		return $this->encode_semantic_channel( $html, $bits_r, $post_id, 'ch6', $fn, $pairs );
	}

	private function decode_channel_synonyms( $html, $post_id ) {
		$fn = array( $this, 'collect_synonym_slots' );
		return $this->decode_semantic_channel( $html, $post_id, 'ch6', $fn );
	}

	// =========================================================================
	// CHANNEL 7: PUNCTUATION CHOICE
	// Sub-channel A: Oxford comma  — "X, Y[,] and Z"  (bit0=no comma, bit1=comma)
	// Sub-channel B: Em-dash vs Parentheses — " (text)" ↔ " — text —"
	// Both sub-channels contribute slots to a single unified list, position-
	// selected by HMAC-PRNG so the decoder can reconstruct the same ordering.
	// =========================================================================

	/**
	 * Collect all punctuation-swappable slots from text segments.
	 * Returns a flat list sorted by (seg_index, byte_offset).
	 */
	private function collect_punctuation_slots( array $segs ) {
		$slots  = array();
		$emdash = self::EM_DASH;

		foreach ( $segs as $si => $seg ) {
			if ( 'text' !== $seg['type'] || $seg['skip'] ) { continue; }
			$text = $seg['content'];

			// ── Sub-channel A: Oxford comma ───────────────────────────────────
			// Requires a preceding comma (list context): ", item[,] and word"
			// Negative lookahead prevents matching ", and word" directly.
			if ( preg_match_all(
				'/,\\s+(?!and\\b)(\\w[^,\n.!?;]{1,40}?)(,?)\\s+(and)\\s+(\\w)/iu',
				$text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER
			) ) {
				foreach ( $m as $match ) {
					$item_text   = $match[1][0]; // the penultimate list item
					$oxford_comma = $match[2][0]; // '' or ','
					$and_word    = $match[3][0]; // 'and'
					$last_char   = $match[4][0]; // first char of last item
					$replace_start = $match[1][1]; // byte offset of item_text within $text
					$replace_len   = strlen( $item_text ) + strlen( $oxford_comma )
					                + strlen( $match[3][-1] ?? '' ) // surrounding whitespace
					                + strlen( $and_word ) + strlen( $match[4][-1] ?? '' );
					// Build the two replacement strings (item_text + [comma] + " and " + last_char)
					$spacer       = preg_replace( '/[^\\s]/', '', $match[3][0] ); // whitespace around 'and'
					$between      = $spacer . $and_word . substr( $match[0][0], -1 - strlen( $last_char ) + 1 );
					// Calculate exact offsets for the replaceable portion
					$full_match = $match[0][0]; // everything matched
					$full_off   = $match[0][1];
					// The replaceable portion begins AFTER the leading comma (which is not ours to change)
					// i.e. item_text + oxford_comma + spaces + "and " + first-char-of-last
					$rep_start = $match[1][1];
					$rep_len   = strlen( $full_match ) - ( $rep_start - $full_off );
					$f0 = $item_text . ltrim( preg_replace( '/^,/', '', $oxford_comma ) ) . substr( $full_match, strlen( $item_text ) + strlen( $oxford_comma ), $rep_len - strlen( $item_text ) - strlen( $oxford_comma ) );
					$f1 = $item_text . ',' . ltrim( $oxford_comma ) . substr( $full_match, strlen( $item_text ) + strlen( $oxford_comma ), $rep_len - strlen( $item_text ) - strlen( $oxford_comma ) );
					if ( '' !== $oxford_comma ) { // already Oxford
						$f0 = $item_text . substr( $full_match, strlen($item_text)+1 ); // without comma
						$f1 = $item_text . substr( $full_match, strlen($item_text) );   // with comma
					} else {
						$f0 = $item_text . substr( $full_match, strlen($item_text) );     // without comma
						$f1 = $item_text . ',' . substr( $full_match, strlen($item_text) ); // with comma
					}
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'oxford',
						'form'      => ( '' !== $oxford_comma ) ? 1 : 0,
						'offset'    => $rep_start,
						'old_len'   => $rep_len,
						'form0_txt' => $f0,
						'form1_txt' => $f1,
					);
				}
			}

			// ── Sub-channel B: Parentheses (form 0) ──────────────────────────
			$paren_pat = '/(?<=\\s|[,.:;!?])\\(([^()\n]{4,80})\\)/u';
			if ( preg_match_all( $paren_pat, $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$inner   = $match[1][0];
					if ( preg_match( '/^[\\d\\s%$+-]+$/', $inner ) ) { continue; } // skip maths/data
					$full    = $match[0][0]; // "(inner)"
					$off     = $match[0][1];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'emdash',
						'form'      => 0,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => $full,
						'form1_txt' => $emdash . " " . $inner . " " . $emdash,
					);
				}
			}

			// ── Sub-channel B: Em-dash aside (form 1) ────────────────────────
			$em_pat = '/' . preg_quote( $emdash, '/' ) . '\\s([^'
			        . preg_quote( $emdash, '/' ) . '\n]{4,80})\\s'
			        . preg_quote( $emdash, '/' ) . '/u';
			if ( preg_match_all( $em_pat, $text, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
				foreach ( $m as $match ) {
					$inner   = $match[1][0];
					$full    = $match[0][0];
					$off     = $match[0][1];
					$slots[] = array(
						'seg'       => $si,
						'type'      => 'emdash',
						'form'      => 1,
						'offset'    => $off,
						'old_len'   => strlen( $full ),
						'form0_txt' => '(' . trim( $inner ) . ')',
						'form1_txt' => $full,
					);
				}
			}
		}

		// Sort by seg then offset for deterministic ordering
		usort( $slots, function( $a, $b ) {
			return $a['seg'] !== $b['seg'] ? $a['seg'] - $b['seg'] : $a['offset'] - $b['offset'];
		} );

		return $slots;
	}

	private function encode_channel_punctuation( $html, array $bits_r, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_punctuation_slots( $segs );
		$n     = count( $slots );
		$needed = min( count( $bits_r ), $n );
		if ( ! $needed ) { return $html; }
		$positions = $this->derive_positions( $post_id, 'ch7', $needed, $n );
		$changes   = array();
		foreach ( $positions as $rank => $slot_idx ) {
			if ( ! isset( $bits_r[ $rank ], $slots[ $slot_idx ] ) ) { break; }
			$slot      = $slots[ $slot_idx ];
			$target    = $bits_r[ $rank ];
			$new_text  = ( 0 === $target ) ? $slot['form0_txt'] : $slot['form1_txt'];
			if ( $new_text !== substr( $segs[ $slot['seg'] ]['content'], $slot['offset'], $slot['old_len'] ) ) {
				$changes[ $slot['seg'] ][] = array(
					'offset'  => $slot['offset'],
					'old_len' => $slot['old_len'],
					'new_text'=> $new_text,
				);
			}
		}
		$this->apply_semantic_changes( $segs, $changes );
		return $this->join_segments( $segs );
	}

	private function decode_channel_punctuation( $html, $post_id ) {
		$segs  = $this->split_html( $html );
		$slots = $this->collect_punctuation_slots( $segs );
		$n     = count( $slots );
		$needed = min( self::PAYLOAD_BITS * self::REDUNDANCY, $n );
		$positions = $this->derive_positions( $post_id, 'ch7', $needed, $n );
		$out = array_fill( 0, $needed, 0 );
		foreach ( $positions as $r => $slot_idx ) {
			if ( isset( $slots[ $slot_idx ] ) ) { $out[ $r ] = $slots[ $slot_idx ]['form']; }
		}
		return array( 'stream' => $out, 'coverage' => $n );
	}

	// =========================================================================
	// CAPITALISATION HELPER
	// =========================================================================

	private function match_case( $original, $new_text ) {
		if ( '' === $original || '' === $new_text ) { return $new_text; }
		if ( strtoupper( $original ) === $original ) { return strtoupper( $new_text ); }
		if ( ucfirst( strtolower( $original ) ) === $original ) { return ucfirst( $new_text ); }
		return $new_text;
	}

	// =========================================================================
	// PUBLIC ENCODE
	// =========================================================================

	public function encode( $html, $post_id ) {
		$bits_r = $this->expand_bits( $this->payload_to_bits( $this->build_payload( $post_id ) ) );
		// Unicode layer — always on
		$html = $this->encode_channel_zw( $html, $bits_r );
		$html = $this->encode_channel_spaces( $html, $bits_r, $post_id );
		$html = $this->encode_channel_apostrophes( $html, $bits_r, $post_id );
		$html = $this->encode_channel_soft_hyphens( $html, $bits_r, $post_id );
		// Semantic layer — opt-in
		if ( self::cget( 'contractions', false  ) ) {
			$html = $this->encode_channel_contractions( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'synonyms', false  ) ) {
			$html = $this->encode_channel_synonyms( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'punctuation', false  ) ) {
			$html = $this->encode_channel_punctuation( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'spelling', false  ) ) {
			$html = $this->encode_channel_spelling( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'hyphenation', false  ) ) {
			$html = $this->encode_channel_hyphenation( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'numbers', false  ) ) {
			$html = $this->encode_channel_numbers( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'punctuation2', false  ) ) {
			$html = $this->encode_channel_punctuation2( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'citation', false  ) ) {
			$html = $this->encode_channel_citation( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'parity', false  ) ) {
			$html = $this->encode_channel_parity( $html, $bits_r, $post_id );
		}
		if ( self::cget( 'wordcount', false  ) ) {
			$html = $this->encode_channel_wordcount( $html, $bits_r, $post_id );
		}
		return $html;
	}

	// =========================================================================
	// PUBLIC DECODE  (auto-detects v1 and v2 payloads)
	// =========================================================================

	public function decode( $html, $post_id = null ) {
		$result = array(
			'found'           => false,
			'post_id'         => null,
			'timestamp'       => null,
			'valid'           => false,
			'payload_version' => null,
			'channels'        => array(),
			'message'         => '',
		);

		// ── Ch.1: zero-width bootstrap — try v2 then v1 ─────────────────────
		// We must try the larger payload first; if only 112 bits are present a
		// v2 attempt will simply fail HMAC and fall through to the v1 attempt.
		$zw      = $this->decode_channel_zw( $html );
		$zw_count = count( $zw );
		$needed_v2 = self::PAYLOAD_BITS_V2 * self::REDUNDANCY; // 408
		$needed_v1 = self::PAYLOAD_BITS_V1 * self::REDUNDANCY; // 336

		$zw_dec = false;
		$zw_needed = $needed_v1; // used for coverage display; updated on success

		if ( $zw_count >= $needed_v2 ) {
			$candidate = $this->verify_payload(
				$this->bits_to_payload(
					$this->collapse_bits( array_slice( $zw, 0, $needed_v2 ), self::PAYLOAD_BITS_V2 ),
					self::PAYLOAD_BITS_V2
				)
			);
			if ( $candidate && $candidate['valid'] ) {
				$zw_dec    = $candidate;
				$zw_needed = $needed_v2;
			}
		}
		if ( ! $zw_dec && $zw_count >= $needed_v1 ) {
			$candidate = $this->verify_payload(
				$this->bits_to_payload(
					$this->collapse_bits( array_slice( $zw, 0, $needed_v1 ), self::PAYLOAD_BITS_V1 ),
					self::PAYLOAD_BITS_V1
				)
			);
			if ( $candidate ) {
				$zw_dec    = $candidate;
				$zw_needed = $needed_v1;
			}
		}

		$result['channels']['zw'] = array(
			'label'       => 'Zero-width chars (Ch.1)',
			'layer'       => 'unicode',
			'bits_found'  => $zw_count,
			'bits_needed' => $zw_needed,
			'coverage'    => $zw_needed > 0 ? min( 100, (int) ( $zw_count / $zw_needed * 100 ) ) : 0,
		);

		if ( $zw_dec ) {
			$result['found']           = true;
			$result['post_id']         = $zw_dec['post_id'];
			$result['timestamp']       = $zw_dec['timestamp'];
			$result['valid']           = $zw_dec['valid'];
			$result['payload_version'] = $zw_dec['payload_version'];
			$result['channels']['zw'] += $zw_dec;
			if ( null === $post_id ) { $post_id = $zw_dec['post_id']; }
		}

		if ( null !== $post_id ) {
			// Determine which payload sizes to attempt for keyed channels.
			// If we already know the version from Ch.1, only try that size.
			// Otherwise attempt both, preferring v2.
			$known_version  = $result['payload_version'];
			$try_versions   = ( null !== $known_version )
				? array( $known_version )
				: array( 2, 1 );

			// ── Ch.2-4: Unicode keyed channels ──────────────────────────────
			$unicode_keyed = array(
				'sp' => array( 'label' => 'Thin spaces (Ch.2)',  'stream' => $this->decode_channel_spaces( $html, $post_id ) ),
				'ap' => array( 'label' => 'Apostrophes (Ch.3)',  'stream' => $this->decode_channel_apostrophes( $html, $post_id ) ),
				'sh' => array( 'label' => 'Soft hyphens (Ch.4)', 'stream' => $this->decode_channel_soft_hyphens( $html, $post_id ) ),
			);
			foreach ( $unicode_keyed as $name => $ch ) {
				$s    = $ch['stream'];
				$n    = count( $s );
				$info = array(
					'label'  => $ch['label'],
					'layer'  => 'unicode',
				);
				$dec_result = false;
				foreach ( $try_versions as $ver ) {
					$needed = ( 2 === $ver ) ? $needed_v2 : $needed_v1;
					$pbits  = ( 2 === $ver ) ? self::PAYLOAD_BITS_V2 : self::PAYLOAD_BITS_V1;
					if ( $n >= $needed ) {
						$candidate = $this->verify_payload(
							$this->bits_to_payload(
								$this->collapse_bits( array_slice( $s, 0, $needed ), $pbits ),
								$pbits
							)
						);
						if ( $candidate && $candidate['valid'] ) {
							$dec_result = $candidate;
							$info['bits_found']  = $n;
							$info['bits_needed'] = $needed;
							$info['coverage']    = min( 100, (int) ( $n / $needed * 100 ) );
							break;
						} elseif ( $candidate && ! $dec_result ) {
							$dec_result = $candidate; // keep first attempt even if MAC fails
							$info['bits_found']  = $n;
							$info['bits_needed'] = $needed;
							$info['coverage']    = min( 100, (int) ( $n / $needed * 100 ) );
						}
					}
				}
				if ( ! isset( $info['bits_found'] ) ) {
					$fallback_needed     = ( null !== $known_version && 2 === $known_version ) ? $needed_v2 : $needed_v1;
					$info['bits_found']  = $n;
					$info['bits_needed'] = $fallback_needed;
					$info['coverage']    = $fallback_needed > 0 ? min( 100, (int) ( $n / $fallback_needed * 100 ) ) : 0;
				}
				if ( $dec_result ) {
					$info += $dec_result;
					$info['matches_ch1'] = (
						$result['post_id'] === $dec_result['post_id'] &&
						$result['timestamp'] === $dec_result['timestamp']
					);
				}
				$result['channels'][ $name ] = $info;
			}

			// ── Ch.5-12: Semantic channels ───────────────────────────────────
			$semantic = array(
				'ct' => array( 'label' => 'Contractions (Ch.5)',      'layer' => 'semantic',    'data' => $this->decode_channel_contractions( $html, $post_id ) ),
				'sy' => array( 'label' => 'Synonyms (Ch.6)',           'layer' => 'semantic',    'data' => $this->decode_channel_synonyms( $html, $post_id ) ),
				'pu' => array( 'label' => 'Punctuation (Ch.7)',        'layer' => 'semantic',    'data' => $this->decode_channel_punctuation( $html, $post_id ) ),
				'sl' => array( 'label' => 'Spelling (Ch.8)',           'layer' => 'semantic',    'data' => $this->decode_channel_spelling( $html, $post_id ) ),
				'hy' => array( 'label' => 'Hyphenation (Ch.9)',        'layer' => 'semantic',    'data' => $this->decode_channel_hyphenation( $html, $post_id ) ),
				'nu' => array( 'label' => 'Numbers (Ch.10)',           'layer' => 'semantic',    'data' => $this->decode_channel_numbers( $html, $post_id ) ),
				'p2' => array( 'label' => 'Punct. style II (Ch.11)',   'layer' => 'semantic',    'data' => $this->decode_channel_punctuation2( $html, $post_id ) ),
				'ci' => array( 'label' => 'Citation style (Ch.12)',    'layer' => 'semantic',    'data' => $this->decode_channel_citation( $html, $post_id ) ),
				'pa' => array( 'label' => 'Sentence parity (Ch.13)',   'layer' => 'structural',  'data' => $this->decode_channel_parity( $html, $post_id ) ),
				'wc' => array( 'label' => 'Word-count parity (Ch.14)', 'layer' => 'structural',  'data' => $this->decode_channel_wordcount( $html, $post_id ) ),
			);
			foreach ( $semantic as $name => $ch ) {
				$stream  = $ch['data']['stream'];
				$n_slots = $ch['data']['coverage'];
				$n       = count( $stream );
				$info    = array(
					'label'        => $ch['label'],
					'layer'        => $ch['layer'],
					'slots_in_text'=> $n_slots,
					'not_encoded'  => ( 0 === $n_slots ),
				);
				$dec_result = false;
				foreach ( $try_versions as $ver ) {
					$needed = ( 2 === $ver ) ? $needed_v2 : $needed_v1;
					$pbits  = ( 2 === $ver ) ? self::PAYLOAD_BITS_V2 : self::PAYLOAD_BITS_V1;
					if ( $n >= $needed ) {
						$candidate = $this->verify_payload(
							$this->bits_to_payload(
								$this->collapse_bits( array_slice( $stream, 0, $needed ), $pbits ),
								$pbits
							)
						);
						if ( $candidate && $candidate['valid'] ) {
							$dec_result = $candidate;
							$info['bits_found']  = $n;
							$info['bits_needed'] = $needed;
							$info['coverage']    = min( 100, (int) ( $n / $needed * 100 ) );
							break;
						} elseif ( $candidate && ! $dec_result ) {
							$dec_result = $candidate;
							$info['bits_found']  = $n;
							$info['bits_needed'] = $needed;
							$info['coverage']    = min( 100, (int) ( $n / $needed * 100 ) );
						}
					}
				}
				if ( ! isset( $info['bits_found'] ) ) {
					$fallback_needed     = ( null !== $known_version && 2 === $known_version ) ? $needed_v2 : $needed_v1;
					$info['bits_found']  = $n;
					$info['bits_needed'] = $fallback_needed;
					$info['coverage']    = $fallback_needed > 0 ? min( 100, (int) ( $n / $fallback_needed * 100 ) ) : 0;
				}
				if ( $dec_result ) {
					$info += $dec_result;
					$info['matches_ch1'] = (
						$result['post_id'] === $dec_result['post_id'] &&
						$result['timestamp'] === $dec_result['timestamp']
					);
				}
				$result['channels'][ $name ] = $info;
			}
		}

		$result['message'] = $result['found'] && $result['valid']
			? __( 'Canary verified. Payload is authentic.', 'archiviomd' )
			: ( $result['found']
				? __( 'Canary found but HMAC verification failed. Payload may be partially stripped or key changed.', 'archiviomd' )
				: __( 'No canary detected. Injection may not be enabled, or all channels have been stripped.', 'archiviomd' )
			);
		return $result;
	}

	// =========================================================================
	// REST API INJECTION
	// =========================================================================

	/**
	 * Inject canary into WP REST API post/page/attachment responses.
	 *
	 * Hooks: rest_prepare_post, rest_prepare_page, rest_prepare_attachment
	 * Fires only when fingerprinting is enabled and the post is published.
	 * Only touches content.rendered — leaves content.raw untouched so the
	 * Gutenberg editor never sees injected characters.
	 *
	 * @param  WP_REST_Response $response
	 * @param  WP_Post          $post
	 * @param  WP_REST_Request  $request
	 * @return WP_REST_Response
	 */
	public function inject_canary_rest( $response, $post, $request ) {
		// Skip if the request asks for the raw block-editor context
		if ( 'edit' === $request->get_param( 'context' ) ) {
			return $response;
		}
		if ( 'publish' !== $post->post_status ) {
			return $response;
		}
		if ( get_post_meta( $post->ID, '_archivio_canary_disabled', true ) ) {
			return $response;
		}
		$data = $response->get_data();
		if ( isset( $data['content']['rendered'] ) && '' !== $data['content']['rendered'] ) {
			$data['content']['rendered'] = $this->encode( $data['content']['rendered'], $post->ID );
			$response->set_data( $data );
		}
		// Also fingerprint excerpt if present
		if ( isset( $data['excerpt']['rendered'] ) && '' !== $data['excerpt']['rendered'] ) {
			$data['excerpt']['rendered'] = $this->encode( $data['excerpt']['rendered'], $post->ID );
			$response->set_data( $data );
		}
		return $response;
	}

	// =========================================================================
	// KEY HEALTH MONITOR
	// =========================================================================

	/**
	 * Compute a short, stable fingerprint of the active HMAC key.
	 * First 16 hex chars of SHA-256(key) — enough to detect rotation,
	 * not enough to help an attacker reconstruct the key.
	 *
	 * @return string  16-char hex string.
	 */
	private function key_fingerprint() {
		return substr( hash( 'sha256', $this->get_key() ), 0, 16 );
	}

	/**
	 * On every request, compare the current key fingerprint to the stored one.
	 * - First run: store it, nothing else.
	 * - Key unchanged: do nothing.
	 * - Key rotated: set a flag so the admin notice fires; update the stored
	 *   fingerprint so the warning shows once per rotation, not forever.
	 *
	 * Called from init_hooks() so it runs on every page load (admin and front).
	 */
	private function maybe_check_key_health() {
		$current  = $this->key_fingerprint();
		$stored   = self::cget( 'key_fingerprint', ''  );
		$dismissed = self::cget( 'key_warn_dismissed', '' );

		if ( '' === $stored ) {
			// First ever run — record and move on
			self::cset( 'key_fingerprint', $current, false );
			return;
		}

		if ( hash_equals( $stored, $current ) ) {
			return; // Key unchanged, nothing to do
		}

		// Key has rotated since last seen.
		// Update stored fingerprint so next load is clean.
		self::cset( 'key_fingerprint', $current, false );

		// Only set the warning flag if the admin hasn't already dismissed
		// this specific rotation (dismissed value is the old fingerprint).
		if ( $dismissed !== $stored ) {
			self::cset( 'key_rotated', '1', false );
			// Store the old fingerprint so dismiss can be tied to this event
			self::cset( 'key_rotated_from', $stored, false );
		}
	}

	/**
	 * Render a persistent admin notice when key rotation is detected.
	 * Shown on all admin pages, not just the Canary Tokens page, because
	 * the admin needs to know regardless of where they are.
	 */
	public function key_health_admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// ── Fallback key warning ──────────────────────────────────────────────
		// Only shown on the Canary Tokens admin page — this is an opt-in feature
		// so there is no reason to surface the warning on every admin screen.
		// The notice is dismissible; the dismiss is stored per-user so it
		// re-appears after a key rotation but not on every page load.
		if ( self::is_using_fallback_key() ) {
			$screen = get_current_screen();
			$on_canary_page = $screen && 'archiviomd_page_archivio-canary' === $screen->id;
			if ( ! $on_canary_page ) {
				// Not on the Canary Tokens page — skip entirely.
			} else {
				$dismissed_ver = get_user_meta( get_current_user_id(), 'archivio_fallback_key_dismissed', true );
				$current_ver   = MDSM_VERSION; // re-show after each plugin update
				if ( $dismissed_ver !== $current_ver ) {
					$dismiss_nonce = wp_create_nonce( 'archivio_fallback_key_dismiss' );
					?>
					<div class="notice notice-warning is-dismissible" id="archivio-fallback-key-notice">
						<p>
							<strong><?php esc_html_e( 'ArchivioMD — Canary Token key not configured', 'archiviomd' ); ?></strong>
						</p>
						<p>
							<?php esc_html_e( 'The HMAC key used for Canary Token fingerprinting is currently derived from WordPress\'s wp_salt(\'auth\') value. This key can change without warning — for example, when you regenerate WordPress secret keys or when a hosting provider migrates your site. If the key changes, all previously embedded fingerprints will fail HMAC verification and become worthless as evidence.', 'archiviomd' ); ?>
						</p>
						<p>
							<?php
							printf(
								/* translators: %s: wp-config.php define() line formatted as code */
								esc_html__( 'To prevent this, add a stable, random key to your wp-config.php: %s', 'archiviomd' ),
								'<code>define( \'ARCHIVIOMD_HMAC_KEY\', \'your-random-32-char-string-here\' );</code>'
							);
							?>
						</p>
					</div>
					<script>
					(function() {
						var el = document.getElementById('archivio-fallback-key-notice');
						if ( ! el ) { return; }
						// Hook into WP core's dismissible-notice close button
						el.addEventListener('click', function(e) {
							if ( ! e.target.classList.contains('notice-dismiss') ) { return; }
							fetch(ajaxurl, {
								method: 'POST',
								headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
								body: 'action=archivio_fallback_key_dismiss&nonce=<?php echo esc_js( $dismiss_nonce ); ?>'
							});
						});
					}());
					</script>
					<?php
				}
			}
		}

		// ── Key rotation warning ──────────────────────────────────────────────
		if ( ! self::cget( 'key_rotated', false ) ) {
			return;
		}
		$old_fp = esc_html( self::cget( 'key_rotated_from', '?' ) );
		$new_fp = esc_html( $this->key_fingerprint() );
		$nonce  = wp_create_nonce( 'archivio_canary_key_warn_dismiss' );
		?>
		<div class="notice notice-warning is-dismissible" id="archivio-key-rotated-notice">
			<p>
				<strong><?php esc_html_e( 'ArchivioMD — Canary Token key rotation detected', 'archiviomd' ); ?></strong>
			</p>
			<p>
				<?php
				printf(
					/* translators: 1: old fingerprint hex, 2: new fingerprint hex */
					esc_html__( 'The HMAC key used for Canary Token fingerprinting has changed (previous key fingerprint: %1$s → new: %2$s). All fingerprints embedded before this change will fail HMAC verification. Fingerprints injected from this point onward will use the new key and verify correctly.', 'archiviomd' ),
					'<code>' . $old_fp . '</code>',
					'<code>' . $new_fp . '</code>'
				);
				?>
			</p>
			<p>
				<?php esc_html_e( 'If you have active infringement matters relying on fingerprints from before the key change, do not use the new key to attempt verification of old copies — they will show as invalid. Keep a record of the old key separately.', 'archiviomd' ); ?>
			</p>
			<p>
				<button type="button" class="button button-secondary" id="archivio-dismiss-key-warn"
					data-nonce="<?php echo esc_attr( $nonce ); ?>">
					<?php esc_html_e( 'I understand — dismiss this warning', 'archiviomd' ); ?>
				</button>
			</p>
		</div>
		<script>
		document.getElementById('archivio-dismiss-key-warn')?.addEventListener('click', function() {
			var btn = this;
			btn.disabled = true;
			fetch(ajaxurl, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: 'action=archivio_canary_dismiss_key_warn&nonce=' + encodeURIComponent(btn.dataset.nonce)
			}).then(function() {
				document.getElementById('archivio-key-rotated-notice')?.remove();
			});
		});
		</script>
		<?php
	}

	/**
	 * AJAX handler — dismiss the key rotation warning.
	 * Clears the rotation flag so the notice stops appearing.
	 */
	public function ajax_dismiss_key_warning() {
		check_ajax_referer( 'archivio_canary_key_warn_dismiss', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error();
		}
		// Record which rotation was dismissed so we don't re-show it
		self::cset( 'key_warn_dismissed',
			self::cget( 'key_rotated_from', '' ), false );
		// Use the obfuscated option keys (via opt()) — raw legacy key names
		// were never written by cset(), so delete_option() on them is a no-op
		// that leaves the flags set and the warning re-appearing forever.
		delete_option( self::opt( 'key_rotated' ) );
		delete_option( self::opt( 'key_rotated_from' ) );
		wp_send_json_success();
	}

	/**
	 * AJAX handler — dismiss the fallback-key notice for the current user.
	 * Stored per-user so each admin can dismiss independently.
	 */
	public function ajax_dismiss_fallback_key_notice() {
		check_ajax_referer( 'archivio_fallback_key_dismiss', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error();
		}
		update_user_meta( get_current_user_id(), 'archivio_fallback_key_dismissed', MDSM_VERSION );
		wp_send_json_success();
	}

	// =========================================================================
	// FILTER HOOK  (HTML layer)
	// =========================================================================

	public function inject_canary( $content ) {
		if ( ! is_feed() && ! is_singular() ) { return $content; }
		$post_id = get_the_ID();
		if ( ! $post_id ) { return $content; }
		$post = get_post( $post_id );
		if ( ! $post || 'publish' !== $post->post_status ) { return $content; }
		if ( get_post_meta( $post_id, '_archivio_canary_disabled', true ) ) { return $content; }
		// Instruct proxies and CDNs not to modify the response body.
		// RFC 7230 §5.7.2: no-transform prohibits modification of content-coding,
		// media-type, or entity-body — this covers HTML minification at the edge.
		// Does not prevent caching; only prohibits body transformation.
		if ( ! headers_sent() && ! is_feed() ) {
			header( 'Cache-Control: no-transform', false );
		}
		return $this->encode( $content, $post_id );
	}

	// =========================================================================
	// AJAX HANDLERS
	// =========================================================================

	public function ajax_save_settings() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}
		$tf = function( $key ) {
			return isset( $_POST[ $key ] ) && 'true' === sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
		};
		self::cset( 'enabled', $tf( 'enabled'  ) );
		self::cset( 'contractions', $tf( 'contractions'  ) );
		self::cset( 'synonyms', $tf( 'synonyms'  ) );
		self::cset( 'punctuation', $tf( 'punctuation'  ) );
		self::cset( 'spelling', $tf( 'spelling'  ) );
		self::cset( 'hyphenation', $tf( 'hyphenation'  ) );
		self::cset( 'numbers', $tf( 'numbers'  ) );
		self::cset( 'punctuation2', $tf( 'punctuation2'  ) );
		self::cset( 'citation', $tf( 'citation'  ) );
		self::cset( 'parity', $tf( 'parity'  ) );
		self::cset( 'wordcount', $tf( 'wordcount'  ) );

		// Payload version: accept only 1 or 2; default to 1 for safety.
		$raw_ver = isset( $_POST['payload_version'] ) ? absint( wp_unslash( $_POST['payload_version'] ) ) : 1;
		self::cset( 'payload_version', in_array( $raw_ver, array( 1, 2 ), true ) ? $raw_ver : 1 );

		wp_send_json_success( array( 'message' => __( 'Settings saved.', 'archiviomd' ) ) );
	}

	private function enrich_result( array &$result ) {
		if ( $result['found'] && $result['valid'] && $result['post_id'] ) {
			$post = get_post( $result['post_id'] );
			if ( $post ) {
				$result['post_title']  = get_the_title( $post );
				$result['post_url']    = get_permalink( $post );
				$result['post_date']   = get_the_date( '', $post );
				$result['post_author'] = get_the_author_meta( 'display_name', $post->post_author );
				$result['post_status'] = $post->post_status;
			}
		}
		if ( $result['timestamp'] ) {
			$result['timestamp_human'] = wp_date(
				get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
				$result['timestamp']
			);
		}
	}

	public function ajax_decode() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}
		$raw = isset( $_POST['content'] ) ? wp_unslash( $_POST['content'] ) : '';
		if ( empty( trim( $raw ) ) ) {
			wp_send_json_error( array( 'message' => __( 'No content provided.', 'archiviomd' ) ) );
		}
		$result = $this->decode( $raw );
		$this->enrich_result( $result );
		$log_row_id = $this->log_discovery( $result, 'admin_paste', '' );
		if ( $log_row_id ) { $result['log_row_id'] = $log_row_id; }
		wp_send_json_success( $result );
	}

	/**
	 * Fetch a remote URL, extract main content, and run the canary decoder.
	 */
	public function ajax_decode_url() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}
		$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';
		if ( empty( $url ) || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			wp_send_json_error( array( 'message' => __( 'Please enter a valid URL.', 'archiviomd' ) ) );
		}

		// ── SSRF prevention ───────────────────────────────────────────────────
		// FILTER_VALIDATE_URL only checks syntax; it does not block private
		// addresses. We resolve the hostname and reject any IP that falls in a
		// private, loopback, or reserved range before making the outbound request.
		$parsed = wp_parse_url( $url );
		$scheme = isset( $parsed['scheme'] ) ? strtolower( $parsed['scheme'] ) : '';
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Only http:// and https:// URLs are supported.', 'archiviomd' ) ) );
		}
		$host = $parsed['host'] ?? '';
		if ( '' === $host ) {
			wp_send_json_error( array( 'message' => __( 'Could not parse hostname from URL.', 'archiviomd' ) ) );
		}
		// Resolve to IP(s) and check each one.
		// dns_get_record returns all A/AAAA records so we catch multi-homed hosts.
		$dns_records = dns_get_record( $host, DNS_A | DNS_AAAA );
		if ( empty( $dns_records ) ) {
			// gethostbyname() as fallback (returns hostname unchanged on failure)
			$resolved_ip = gethostbyname( $host );
			$dns_records = ( $resolved_ip !== $host ) ? array( array( 'ip' => $resolved_ip ) ) : array();
		}
		if ( empty( $dns_records ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not resolve hostname.', 'archiviomd' ) ) );
		}
		$validated_ips = array();
		foreach ( $dns_records as $record ) {
			$ip = $record['ip'] ?? ( $record['ipv6'] ?? '' );
			if ( '' === $ip ) { continue; }
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP,
					FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				wp_send_json_error( array(
					'message' => __( 'URL resolves to a private or reserved address and cannot be fetched.', 'archiviomd' ),
				) );
			}
			$validated_ips[] = $ip;
		}
		// ── Pin DNS to close the rebinding window ─────────────────────────────
		// wp_remote_get() triggers a second independent DNS resolution inside
		// cURL. A low-TTL attacker-controlled domain can rebind between our
		// check above and that second lookup (e.g. to 169.254.169.254/AWS IMDS).
		// CURLOPT_RESOLVE injects our already-validated IPs directly into cURL's
		// resolver cache, so no second DNS query is ever issued. TLS certificate
		// validation still runs against the original hostname — no security
		// tradeoff. We pin every validated IP for every port cURL may connect on:
		// the explicit port from the URL (if non-standard) plus the scheme default.
		$default_port    = ( 'https' === $scheme ) ? 443 : 80;
		$explicit_port   = isset( $parsed['port'] ) ? (int) $parsed['port'] : null;
		$ports_to_pin    = array_unique( array_filter( array( $default_port, $explicit_port ) ) );
		$resolve_entries = array();
		foreach ( $validated_ips as $validated_ip ) {
			foreach ( $ports_to_pin as $pin_port ) {
				$resolve_entries[] = "{$host}:{$pin_port}:{$validated_ip}";
			}
		}
		$curl_pin_cb = function( $handle ) use ( $resolve_entries ) {
			curl_setopt( $handle, CURLOPT_RESOLVE, $resolve_entries );
		};
		add_action( 'http_api_curl', $curl_pin_cb );
		// ── End SSRF prevention ───────────────────────────────────────────────
		$response = wp_remote_get( $url, array(
			'timeout'    => 20,
			'user-agent' => 'Mozilla/5.0 (compatible; ArchivioMD Canary Checker/1.10)',
			'headers'    => array( 'Accept' => 'text/html,application/xhtml+xml' ),
		) );
		remove_action( 'http_api_curl', $curl_pin_cb );
		if ( is_wp_error( $response ) ) {
			wp_send_json_error( array( 'message' => sprintf(
				/* translators: %s error message */
				__( 'Could not fetch URL: %s', 'archiviomd' ), $response->get_error_message()
			) ) );
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 400 ) {
			wp_send_json_error( array( 'message' => sprintf(
				__( 'Remote server returned HTTP %d.', 'archiviomd' ), $code
			) ) );
		}
		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			wp_send_json_error( array( 'message' => __( 'Empty response from URL.', 'archiviomd' ) ) );
		}
		$extracted = $this->extract_main_content( $body );
		$result    = $this->decode( $extracted );
		$this->enrich_result( $result );
		$result['fetched_url']      = $url;
		$result['content_preview']  = mb_substr( wp_strip_all_tags( $extracted ), 0, 300, 'UTF-8' );
		$result['full_content']     = $extracted; // used by Deep Scan brute-force pass
		$log_row_id = $this->log_discovery( $result, 'admin_url', $url );
		if ( $log_row_id ) { $result['log_row_id'] = $log_row_id; }
		wp_send_json_success( $result );
	}

	/**
	 * Extract likely-article text from raw HTML.
	 * Tries <article>, <main>, .entry-content, .post-content, then <body>.
	 *
	 * The input is capped before any regex pass to prevent catastrophic
	 * backtracking (ReDoS) against attacker-controlled HTML that has no
	 * closing tags — e.g. a large body with no </article>.
	 */
	private function extract_main_content( $html ) {
		// Cap at 2 MB — sufficient for any realistic article page.
		// Anything larger is almost certainly not prose content and would
		// cause multi-second regex backtracking on certain inputs.
		$html = substr( $html, 0, 2 * 1024 * 1024 );

		// ── Attempt DOMDocument-based extraction first ────────────────────
		// DOMDocument is not vulnerable to ReDoS and handles malformed HTML
		// gracefully. We prefer it over regex when available.
		if ( class_exists( 'DOMDocument' ) ) {
			$dom = new DOMDocument();
			// Suppress warnings on malformed HTML; use UTF-8 meta hint.
			$wrapped = '<?xml encoding="UTF-8">' . $html;
			$loaded  = @$dom->loadHTML( $wrapped, LIBXML_NOERROR | LIBXML_NOWARNING ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $loaded ) {
				$xpath   = new DOMXPath( $dom );

				// Priority order: <article>, <main>, class-based divs
				$queries = array(
					'//article',
					'//main',
					'//*[contains(concat(" ",normalize-space(@class)," ")," entry-content ")]',
					'//*[contains(concat(" ",normalize-space(@class)," ")," post-content ")]',
					'//*[contains(concat(" ",normalize-space(@class)," ")," article-content ")]',
					'//*[contains(concat(" ",normalize-space(@class)," ")," td-post-content ")]',
					'//*[contains(concat(" ",normalize-space(@class)," ")," post-body ")]',
				);
				foreach ( $queries as $q ) {
					$nodes = $xpath->query( $q );
					if ( $nodes && $nodes->length > 0 ) {
						$inner = '';
						foreach ( $nodes->item(0)->childNodes as $child ) {
							$inner .= $dom->saveHTML( $child );
						}
						return $inner;
					}
				}

				// Fall back to <body> minus nav/header/footer/aside
				$skip = array( 'nav', 'header', 'footer', 'aside', 'script', 'style' );
				foreach ( $skip as $tag ) {
					$nodes = $dom->getElementsByTagName( $tag );
					// Iterate in reverse — removing nodes shifts the live NodeList
					$to_remove = array();
					foreach ( $nodes as $n ) { $to_remove[] = $n; }
					foreach ( $to_remove as $n ) {
						if ( $n->parentNode ) { $n->parentNode->removeChild( $n ); }
					}
				}
				$body = $dom->getElementsByTagName( 'body' );
				if ( $body->length > 0 ) {
					$inner = '';
					foreach ( $body->item(0)->childNodes as $child ) {
						$inner .= $dom->saveHTML( $child );
					}
					return $inner;
				}
			}
		}

		// ── Regex fallback (DOMDocument unavailable) ──────────────────────
		// We already capped $html above. Use non-greedy patterns with a
		// possessive-style workaround: require the closing tag to exist
		// within a hard character limit by replacing .*? with [^§]{0,50000}
		// where § is a sentinel character not expected in HTML.
		// For simplicity we use a character-class exclusion of the tag name
		// start character, which prevents the catastrophic backtrack path.
		$tags = array( 'article', 'main' );
		foreach ( $tags as $tag ) {
			// Use a stricter pattern: inner content must be at most 100 000 chars
			if ( preg_match( '/<' . $tag . '[^>]*>(.{0,100000}?)<\/' . $tag . '>/is', $html, $m ) ) {
				return $m[1];
			}
		}
		$classes = array( 'entry-content', 'post-content', 'article-content', 'td-post-content', 'post-body' );
		foreach ( $classes as $cls ) {
			if ( preg_match( '/class="[^"]*' . preg_quote( $cls, '/' ) . '[^"]*"[^>]*>(.{0,100000}?)<\/(?:div|section|article)/is', $html, $m ) ) {
				return $m[1];
			}
		}
		// Last resort: strip head and navigation blocks, return rest
		$body = preg_replace( '/<head[^>]*>.{0,100000}?<\/head>/is', '', $html );
		$body = preg_replace( '/<(?:nav|header|footer|aside)[^>]*>.{0,50000}?<\/(?:nav|header|footer|aside)>/is', '', $body ?? $html );
		return $body ?: $html;
	}

	/**
	 * Save DMCA contact details to wp_options for re-use.
	 */
	public function ajax_save_dmca_contact() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}
		$fields = array( 'dmca_name', 'dmca_title', 'dmca_company', 'dmca_email',
							'dmca_phone', 'dmca_address', 'dmca_website' );
		foreach ( $fields as $field ) {
			if ( isset( $_POST[ $field ] ) ) {
				update_option( 'archivio_' . $field,
					sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) );
			}
		}
		wp_send_json_success( array( 'message' => __( 'Contact details saved.', 'archiviomd' ) ) );
	}

	// =========================================================================
	// REST API  (verification endpoint)
	// =========================================================================

	public function register_rest_route() {
		// Public endpoint — basic decode, rate-limited.
		// Namespace and route are deliberately generic to avoid advertising
		// that steganographic fingerprinting is in use.
		register_rest_route( 'content/v1', '/verify', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'rest_canary_check' ),
			'permission_callback' => '__return_true',
			'args'                => array(
				'content' => array(
					'required'  => true,
					'type'      => 'string',
					// Cap at 500 KB — sufficient for any realistic article.
					// Without this, an unauthenticated caller could POST
					// megabytes per request at the full rate-limit quota.
					'maxLength' => 512000,
				),
			),
		) );

		// Authenticated endpoint — full channel breakdown, no rate limit.
		register_rest_route( 'content/v1', '/verify/full', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'rest_canary_check_full' ),
			'permission_callback' => function() { return current_user_can( 'manage_options' ); },
			'args'                => array(
				'content' => array(
					'required'  => true,
					'type'      => 'string',
					'maxLength' => 512000,
				),
			),
		) );
	}

	/**
	 * Rate-limit helper for the public REST endpoint.
	 * Uses transients keyed to a hashed IP; allows $limit requests per minute.
	 * Returns true if the request should be blocked.
	 *
	 * @param  int $limit  Requests allowed per 60-second window. Default 60.
	 * @return bool
	 */
	private function rest_is_rate_limited( $limit = 60 ) {
		// Build a key from the client IP — hashed so no raw IP is stored.
		// X-Forwarded-For is attacker-controlled; we take the LAST (rightmost)
		// IP added by a trusted proxy rather than the first, and we validate it
		// is a public routable address before trusting it for rate-limiting.
		// If it resolves to a private/loopback range we fall back to REMOTE_ADDR.
		$remote = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: 'unknown';

		$ip = $remote; // default: direct connection IP (always trustworthy)

		if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			// Take the rightmost IP (added by the closest trusted proxy)
			$parts     = array_map( 'trim', explode( ',', $forwarded ) );
			$candidate = end( $parts );
			// Only use it if it is a syntactically valid, publicly routable IP.
			// FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE rejects
			// 10.x, 172.16–31.x, 192.168.x, 127.x, 169.254.x, and ::1.
			if ( filter_var( $candidate, FILTER_VALIDATE_IP,
					FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				$ip = $candidate;
			}
			// Otherwise fall back to $remote (REMOTE_ADDR) — an attacker
			// cannot spoof that value at the network layer.
		}

		$key  = 'archivio_rl_' . md5( $ip );
		$hits = (int) get_transient( $key );
		if ( $hits >= $limit ) {
			return true;
		}
		// Increment; set a 60-second window on first hit
		set_transient( $key, $hits + 1, MINUTE_IN_SECONDS );
		return false;
	}

	/**
	 * Public REST endpoint callback.
	 * Returns: found, valid, post_id, timestamp_human, post_title, post_url,
	 *          payload_version, message.
	 * Rate-limited to 60 requests/minute per IP.
	 */
	public function rest_canary_check( WP_REST_Request $request ) {
		if ( $this->rest_is_rate_limited( 60 ) ) {
			return new WP_Error(
				'rate_limited',
				__( 'Too many requests. Please wait a moment and try again.', 'archiviomd' ),
				array( 'status' => 429 )
			);
		}
		$result = $this->decode( sanitize_textarea_field( $request->get_param( 'content' ) ) );
		$this->log_discovery( $result, 'rest_public', '' );
		$resp   = array(
			'found'           => $result['found'],
			'valid'           => $result['valid'],
			'timestamp'       => $result['timestamp'],
			'payload_version' => $result['payload_version'],
			'message'         => $result['message'],
		);
		// Only disclose post_id and post metadata for published posts.
		// A fingerprint may decode a valid payload for a draft, private, or
		// trashed post whose existence should not be confirmed to anonymous callers.
		if ( $result['found'] && $result['valid'] && $result['post_id'] ) {
			$post = get_post( $result['post_id'] );
			if ( $post && 'publish' === $post->post_status ) {
				$resp['post_id']    = $result['post_id'];
				$resp['post_title'] = get_the_title( $post );
				$resp['post_url']   = get_permalink( $post );
			}
		}
		if ( $result['timestamp'] ) {
			$resp['timestamp_human'] = gmdate( 'Y-m-d H:i:s', $result['timestamp'] ) . ' UTC';
		}
		return rest_ensure_response( $resp );
	}

	/**
	 * Authenticated REST endpoint — full channel breakdown.
	 * Same as the admin AJAX decoder but available over REST for tooling.
	 * Requires manage_options capability; no rate limit.
	 */
	public function rest_canary_check_full( WP_REST_Request $request ) {
		$result = $this->decode( sanitize_textarea_field( $request->get_param( 'content' ) ) );
		$this->enrich_result( $result );
		$this->log_discovery( $result, 'rest_full', '' );
		return rest_ensure_response( $result );
	}

	// =========================================================================
	// DISCOVERY LOG — AJAX HANDLERS
	// =========================================================================

	/**
	 * Return paginated log entries as JSON for the admin log tab.
	 * Accepts optional GET params: page (int), per_page (int, max 100).
	 */
	public function ajax_fetch_log() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}

		global $wpdb;
		$table    = self::log_table_name();
		$per_page = min( 50, max( 1, (int) ( $_POST['per_page'] ?? 25 ) ) );
		$page     = max( 1, (int) ( $_POST['page'] ?? 1 ) );
		$offset   = ( $page - 1 ) * $per_page;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) ) {
			wp_send_json_success( array( 'rows' => array(), 'total' => 0, 'pages' => 0 ) );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT id, discovered_at, source, source_url, post_id, fingerprint_ts,
			        payload_version, valid, verifier_id, channels_found, note,
			        receipt_generated
			 FROM {$table}
			 ORDER BY id DESC
			 LIMIT %d OFFSET %d",
			$per_page,
			$offset
		), ARRAY_A );

		// Enrich with post titles and verifier display names for readability
		foreach ( $rows as &$row ) {
			$row['post_title']     = '';
			$row['verifier_name']  = '';
			$row['fingerprint_human'] = '';
			if ( $row['post_id'] ) {
				$post = get_post( (int) $row['post_id'] );
				if ( $post ) {
					$row['post_title'] = get_the_title( $post );
					$row['post_url']   = get_permalink( $post );
				}
			}
			if ( $row['verifier_id'] ) {
				$u = get_userdata( (int) $row['verifier_id'] );
				if ( $u ) { $row['verifier_name'] = $u->display_name; }
			}
			if ( $row['fingerprint_ts'] ) {
				$row['fingerprint_human'] = gmdate( 'Y-m-d H:i:s', (int) $row['fingerprint_ts'] ) . ' UTC';
			}
		}
		unset( $row );

		wp_send_json_success( array(
			'rows'  => $rows,
			'total' => $total,
			'pages' => (int) ceil( $total / $per_page ),
			'page'  => $page,
		) );
	}

	/**
	 * Clear all rows from the discovery log.
	 * Requires manage_options and a separate nonce so it can't be triggered
	 * accidentally from the same form that saves settings.
	 */
	public function ajax_clear_log() {
		check_ajax_referer( 'archivio_canary_clear_log', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}
		global $wpdb;
		$table = self::log_table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "TRUNCATE TABLE {$table}" );
		wp_send_json_success( array( 'message' => __( 'Discovery log cleared.', 'archiviomd' ) ) );
	}

	// =========================================================================
	// RE-FINGERPRINT (BULK RESTAMP)
	// =========================================================================

	/**
	 * AJAX handler — re-stamp all published posts with the current time, in batches.
	 *
	 * Accepts POST fields:
	 *   nonce     string   archivio_canary_nonce
	 *   offset    int      (optional) 0-based row offset to start from; default 0
	 *   batch     int      (optional) posts per call; capped at 200; default 200
	 *
	 * Returns JSON:
	 *   done      bool     true when no more rows remain
	 *   processed int      posts stamped in this batch
	 *   total     int      total published posts (returned on first call only)
	 *   message   string   human-readable status
	 *
	 * The JS caller should loop: send offset=0, receive processed+done; if !done
	 * send offset += processed and repeat until done=true.
	 */
	public function ajax_restamp_all() {
		check_ajax_referer( 'archivio_canary_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'archiviomd' ) ) );
		}

		global $wpdb;

		$batch  = min( 200, max( 1, absint( wp_unslash( $_POST['batch'] ?? 200 ) ) ) );
		$offset = max( 0, absint( wp_unslash( $_POST['offset'] ?? 0 ) ) );

		// On the first call (offset=0) also return the total count so the UI
		// can show a progress bar without a separate query.
		$total = null;
		if ( 0 === $offset ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$total = (int) $wpdb->get_var(
				$wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = %s", 'publish' )
			);
		}

		$post_ids = $wpdb->get_col(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT ID FROM {$wpdb->posts} WHERE post_status = %s ORDER BY ID ASC LIMIT %d OFFSET %d",
				'publish',
				$batch,
				$offset
			)
		);

		$stamp     = time();
		$processed = 0;
		foreach ( $post_ids as $pid ) {
			$pid = (int) $pid;
			if ( false === update_post_meta( $pid, '_archivio_canary_stamp', $stamp ) ) {
				add_post_meta( $pid, '_archivio_canary_stamp', $stamp, true );
			}
			$processed++;
		}

		$done = count( $post_ids ) < $batch;

		$response = array(
			'done'      => $done,
			'processed' => $processed,
			/* translators: %d number of posts stamped in this batch */
			'message'   => $done
				? __( 'All posts re-stamped. New fingerprints will be embedded on the next page load.', 'archiviomd' )
				/* translators: %d: posts stamped so far */
				: sprintf( __( 'Stamped %d post(s) so far…', 'archiviomd' ), $offset + $processed ),
		);
		if ( null !== $total ) {
			$response['total'] = $total;
		}

		wp_send_json_success( $response );
	}

	// =========================================================================
	// COVERAGE ESTIMATE  (used by meta box on post edit screen)
	// =========================================================================

	/**
	 * Estimate per-channel slot availability for a block of HTML.
	 *
	 * Runs all fourteen channel slot collectors in read-only mode and returns
	 * a structured array so the meta box — or any caller — can display
	 * coverage without encoding anything.
	 *
	 * The word-count guard skips the expensive semantic regex passes on very
	 * long posts (> 10 000 words) and reports them as sufficient rather than
	 * potentially timing out.
	 *
	 * @param  string $html  Post content HTML.
	 * @return array  Keyed by channel id (ch1–ch12). Each entry:
	 *                  label   string
	 *                  layer   'unicode'|'semantic'
	 *                  slots   int   available slot count
	 *                  needed  int   slots required for a full payload
	 *                  pct     int   0-100
	 *                  ok      bool
	 */
	public function coverage_estimate( $html ) {
		$needed_v1 = self::PAYLOAD_BITS_V1 * self::REDUNDANCY; // 336
		$needed_v2 = self::PAYLOAD_BITS_V2 * self::REDUNDANCY; // 408
		$needed    = ( 2 === $this->active_payload_version() ) ? $needed_v2 : $needed_v1;
		$plain     = wp_strip_all_tags( $html );
		$wc        = str_word_count( $plain );
		$segs      = $this->split_html( $html );

		// ── Ch.1 zero-width — one slot per word-start (approximation) ────────
		$ch1_slots = $wc;

		// ── Ch.2 thin spaces — one slot per space ────────────────────────────
		$ch2_slots = substr_count( $html, ' ' );

		// ── Ch.3 apostrophes — one slot per apostrophe ───────────────────────
		$ch3_slots = substr_count( $html, "'" ) + substr_count( $html, self::APOS_CURLY );

		// ── Ch.4 soft hyphens — intraword positions in long words ────────────
		$ch4_slots = count( $this->collect_intraword_slots( $segs ) );

		// ── Ch.5–14 semantic — skip on very long posts to avoid timeout ──────
		$skip_semantic = $wc > 10000;

		if ( $skip_semantic ) {
			$ch5_slots  = $needed;
			$ch6_slots  = $needed;
			$ch7_slots  = $needed;
			$ch8_slots  = $needed;
			$ch9_slots  = $needed;
			$ch10_slots = $needed;
			$ch11_slots = $needed;
			$ch12_slots = $needed;
			$ch13_slots = $needed;
			$ch14_slots = $needed;
		} else {
			$ch5_slots  = count( $this->collect_contraction_slots( $segs ) );
			$ch6_slots  = count( $this->collect_synonym_slots( $segs ) );
			$ch7_slots  = count( $this->collect_punctuation_slots( $segs ) );
			$ch8_slots  = count( $this->collect_spelling_slots( $segs ) );
			$ch9_slots  = count( $this->collect_hyphenation_slots( $segs ) );
			$ch10_slots = count( $this->collect_number_slots( $segs ) );
			$ch11_slots = count( $this->collect_punctuation2_slots( $segs ) );
			$ch12_slots = count( $this->collect_citation_slots( $html ) );
			$ch13_slots = count( $this->collect_parity_slots( $segs ) );
			$ch14_slots = count( $this->collect_wordcount_slots( $segs ) );
		}

		$channels = array(
			'ch1'  => array( 'label' => 'Ch.1 Zero-width',        'layer' => 'unicode',   'slots' => $ch1_slots ),
			'ch2'  => array( 'label' => 'Ch.2 Thin spaces',       'layer' => 'unicode',   'slots' => $ch2_slots ),
			'ch3'  => array( 'label' => 'Ch.3 Apostrophes',       'layer' => 'unicode',   'slots' => $ch3_slots ),
			'ch4'  => array( 'label' => 'Ch.4 Soft hyphens',      'layer' => 'unicode',   'slots' => $ch4_slots ),
			'ch5'  => array( 'label' => 'Ch.5 Contractions',      'layer' => 'semantic',  'slots' => $ch5_slots ),
			'ch6'  => array( 'label' => 'Ch.6 Synonyms',          'layer' => 'semantic',  'slots' => $ch6_slots ),
			'ch7'  => array( 'label' => 'Ch.7 Punctuation',       'layer' => 'semantic',  'slots' => $ch7_slots ),
			'ch8'  => array( 'label' => 'Ch.8 Spelling',          'layer' => 'semantic',  'slots' => $ch8_slots ),
			'ch9'  => array( 'label' => 'Ch.9 Hyphenation',       'layer' => 'semantic',  'slots' => $ch9_slots ),
			'ch10' => array( 'label' => 'Ch.10 Numbers',          'layer' => 'semantic',  'slots' => $ch10_slots ),
			'ch11' => array( 'label' => 'Ch.11 Punct. style II',  'layer' => 'semantic',  'slots' => $ch11_slots ),
			'ch12' => array( 'label' => 'Ch.12 Citation style',   'layer' => 'semantic',  'slots' => $ch12_slots ),
			'ch13' => array( 'label' => 'Ch.13 Sentence parity',  'layer' => 'structural', 'slots' => $ch13_slots ),
			'ch14' => array( 'label' => 'Ch.14 Word-count parity','layer' => 'structural', 'slots' => $ch14_slots ),
		);

		foreach ( $channels as &$ch ) {
			$ch['needed'] = $needed;
			$ch['pct']    = $needed > 0 ? min( 100, (int) round( $ch['slots'] / $needed * 100 ) ) : 0;
			$ch['ok']     = $ch['slots'] >= $needed;
		}
		unset( $ch );

		if ( $skip_semantic ) {
			foreach ( array( 'ch5', 'ch6', 'ch7', 'ch8', 'ch9', 'ch10', 'ch11', 'ch12', 'ch13', 'ch14' ) as $k ) {
				$channels[ $k ]['note'] = __( 'Post exceeds 10 000 words — coverage assumed sufficient.', 'archiviomd' );
			}
		}

		return $channels;
	}

	// =========================================================================
	// COVERAGE META BOX
	// =========================================================================

	/**
	 * Register the Canary Coverage meta box on all public post type edit screens.
	 * Only shown when Canary Token injection is enabled.
	 */
	public function register_coverage_meta_box() {
		if ( ! self::cget( 'enabled', false  ) ) {
			return;
		}
		$post_types = get_post_types( array( 'public' => true ) );
		foreach ( $post_types as $pt ) {
			add_meta_box(
				'archivio_canary_coverage',
				__( 'Canary Coverage', 'archiviomd' ),
				array( $this, 'render_coverage_meta_box' ),
				$pt,
				'side',
				'low'
			);
		}
	}

	/**
	 * Render the Canary Coverage meta box on the post edit screen.
	 *
	 * Runs coverage_estimate() against the current saved post content.
	 * Deliberately uses get_post_field( 'post_content' ) — the stored HTML —
	 * so the estimate reflects what will actually be encoded at render time.
	 * Safe to run on every edit-screen page load; collect_* methods are
	 * read-only and do not modify content.
	 */
	public function render_coverage_meta_box( $post ) {
		$content = get_post_field( 'post_content', $post->ID, 'raw' );

		if ( empty( trim( $content ) ) ) {
			echo '<p style="font-size:.82rem;color:#646970;margin:0">'
				. esc_html__( 'No content yet. Save a draft to see coverage.', 'archiviomd' )
				. '</p>';
			return;
		}

		$channels = $this->coverage_estimate( apply_filters( 'the_content', $content ) );
		$all_ok   = ! in_array( false, array_column( $channels, 'ok' ), true );
		$version  = $this->active_payload_version();

		// ── Overall status badge ─────────────────────────────────────────────
		$badge_style = $all_ok
			? 'background:#d1fae5;color:#065f46'
			: 'background:#fef3c7;color:#92400e';
		$badge_text  = $all_ok
			? __( 'Full coverage', 'archiviomd' )
			: __( 'Partial coverage', 'archiviomd' );
		?>
		<div style="font-size:.79rem;line-height:1.5">
		  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
		    <span style="<?php echo esc_attr( $badge_style ); ?>;padding:2px 8px;border-radius:3px;font-weight:600;font-size:.78rem">
		      <?php echo esc_html( $badge_text ); ?>
		    </span>
		    <span style="color:#646970;font-size:.75rem">v<?php echo esc_html( $version ); ?> payload</span>
		  </div>
		  <table style="width:100%;border-collapse:collapse">
		    <thead>
		      <tr style="border-bottom:1px solid #dcdcde">
		        <th style="text-align:left;padding:3px 4px;font-size:.75rem;color:#50575e;font-weight:600"><?php esc_html_e( 'Channel', 'archiviomd' ); ?></th>
		        <th style="text-align:right;padding:3px 4px;font-size:.75rem;color:#50575e;font-weight:600"><?php esc_html_e( 'Coverage', 'archiviomd' ); ?></th>
		      </tr>
		    </thead>
		    <tbody>
		    <?php foreach ( $channels as $id => $ch ) :
		      $bar_color = 'unicode' === $ch['layer'] ? '#38bdf8' : '#f472b6';
		      $bar_w     = max( 2, min( 60, (int) round( $ch['pct'] * 0.6 ) ) );
		      $tick      = $ch['ok'] ? '✓' : '✗';
		      $tick_col  = $ch['ok'] ? '#00a32a' : '#d63638';
		      $row_style = $ch['ok'] ? '' : 'background:#fefce8';
		    ?>
		      <tr style="border-bottom:1px solid #f0f0f1;<?php echo esc_attr( $row_style ); ?>">
		        <td style="padding:4px 4px;vertical-align:middle">
		          <span style="color:<?php echo esc_attr( $tick_col ); ?>;font-weight:700;margin-right:3px"><?php echo esc_html( $tick ); ?></span>
		          <?php echo esc_html( $ch['label'] ); ?>
		          <?php if ( ! empty( $ch['note'] ) ) : ?>
		            <span style="color:#646970;font-size:.7rem;display:block;margin-left:14px"><?php echo esc_html( $ch['note'] ); ?></span>
		          <?php endif; ?>
		        </td>
		        <td style="padding:4px 4px;text-align:right;white-space:nowrap;vertical-align:middle">
		          <span style="display:inline-block;width:<?php echo esc_attr( $bar_w ); ?>px;height:6px;background:<?php echo esc_attr( $bar_color ); ?>;border-radius:3px;vertical-align:middle;margin-right:4px;opacity:<?php echo $ch['ok'] ? '1' : '.45'; ?>"></span>
		          <span style="font-size:.75rem;color:#50575e"><?php echo esc_html( $ch['pct'] ); ?>%</span>
		        </td>
		      </tr>
		    <?php endforeach; ?>
		    </tbody>
		  </table>
		  <p style="margin:8px 0 0;font-size:.72rem;color:#646970">
		    <?php
		    printf(
		      /* translators: 1: needed slots, 2: redundancy factor */
		      esc_html__( 'Needs ≥%1$d slots/channel (%2$d bits × %3$dx redundancy). Estimates are approximate.', 'archiviomd' ),
		      (int) $channels['ch1']['needed'],
		      ( 2 === $version ) ? self::PAYLOAD_BITS_V2 : self::PAYLOAD_BITS_V1,
		      self::REDUNDANCY
		    );
		    ?>
		  </p>
		</div>
		<?php
	}


	// =========================================================================
	// CACHE HEALTH CHECK (Unicode stripping detection)
	// =========================================================================

	const CACHE_CHECK_CRON_HOOK = 'archivio_canary_cache_check';

	/**
	 * Schedule the cache health check cron when the plugin activates
	 * or when canary injection is first enabled.
	 * Safe to call multiple times — wp_next_scheduled() guards against doubles.
	 */
	public static function schedule_cache_check() {
		if ( ! wp_next_scheduled( self::CACHE_CHECK_CRON_HOOK ) ) {
			wp_schedule_event( time() + 300, 'daily', self::CACHE_CHECK_CRON_HOOK );
		}
	}

	/**
	 * Remove the scheduled cache health check on deactivation.
	 */
	public static function unschedule_cache_check() {
		$ts = wp_next_scheduled( self::CACHE_CHECK_CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CACHE_CHECK_CRON_HOOK );
		}
	}

	/**
	 * WP-Cron callback — fetch the site's most recently published post,
	 * run the canary decoder against the raw HTTP response, and record
	 * the result in wp_options so the admin notice can surface it.
	 *
	 * We use the most recently published post because it is most likely
	 * to be in the page cache. We fetch via wp_remote_get() with a
	 * cache-busting query string so the request bypasses object cache
	 * but still hits any full-page cache (which is exactly what we want
	 * to probe).
	 *
	 * The check is skipped when:
	 *   - Canary injection is not enabled (nothing to detect)
	 *   - No published posts exist
	 *   - The remote fetch fails (transient network error — try again tomorrow)
	 *
	 * Result stored in archivio_canary_cache_health:
	 *   'ok'      — Unicode Ch.1 characters found in the fetched HTML
	 *   'stripped' — Canary enabled but Ch.1 characters absent from response
	 *   'unknown' — Check could not run (no posts, fetch failed, etc.)
	 */
	public function run_cache_health_check() {
		if ( ! self::cget( 'enabled', false  ) ) {
			// Nothing to check — clear any stale warning
			self::cset( 'cache_health', 'ok', false );
			return;
		}

		// Find the most recently published post of any public type
		$posts = get_posts( array(
			'post_type'      => array_values( get_post_types( array( 'public' => true ) ) ),
			'post_status'    => 'publish',
			'numberposts'    => 1,
			'orderby'        => 'date',
			'order'          => 'DESC',
			'fields'         => 'ids',
		) );

		if ( empty( $posts ) ) {
			self::cset( 'cache_health', 'unknown', false );
			return;
		}

		$post_id  = (int) $posts[0];
		$post_url = get_permalink( $post_id );
		if ( ! $post_url ) {
			self::cset( 'cache_health', 'unknown', false );
			return;
		}

		// Append a cache-buster that caching plugins should pass through
		// (we want to hit the cached layer, not force a miss)
		$check_url = add_query_arg( 'archivio_cc', '1', $post_url );

		$response = wp_remote_get( $check_url, array(
			'timeout'    => 15,
			'user-agent' => 'ArchivioMD-CacheCheck/1.0 (internal; +' . get_site_url() . ')',
			'headers'    => array(
				'Accept'          => 'text/html',
				'Cache-Control'   => 'no-cache',
				'X-Forwarded-For' => '127.0.0.1',
			),
		) );

		if ( is_wp_error( $response ) ) {
			self::cset( 'cache_health', 'unknown', false );
			return;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code >= 400 ) {
			self::cset( 'cache_health', 'unknown', false );
			return;
		}

		$body = wp_remote_retrieve_body( $response );

		// Check for the presence of Ch.1 zero-width characters in the response.
		// If injection is working, every word boundary should have one.
		// We look for either ZW_ZERO or ZW_ONE — either confirms injection survived.
		$has_zw = (
			strpos( $body, self::ZW_ZERO ) !== false ||
			strpos( $body, self::ZW_ONE  ) !== false
		);

		$health = $has_zw ? 'ok' : 'stripped';
		self::cset( 'cache_health', $health, false );
		// If the check passes, clear the dismissed flag so a future stripping
		// event will surface the notice again (fix confirmed — reset state)
		if ( $has_zw ) {
			// Clear the dismissed flag through the obfuscated key so that a
			// future stripping event will surface the notice again.
			delete_option( self::opt( 'cache_notice_dismissed' ) );
		}

		// Store the checked URL and time for the admin notice
		self::cset( 'cache_check_url', $post_url, false );
		self::cset( 'cache_check_time', time(), false );
	}

	/**
	 * Admin notice — fires when the cache health check found that Ch.1
	 * zero-width characters were absent from the fetched response.
	 *
	 * Only shown to manage_options users. Dismissible via a separate nonce-
	 * protected AJAX action so it doesn't reappear on the next page load.
	 */
	public function cache_health_admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( 'stripped' !== self::cget( 'cache_health', 'ok'  ) ) {
			return;
		}
		if ( self::cget( 'cache_notice_dismissed', false  ) ) {
			return;
		}

		$checked_url  = esc_url( self::cget( 'cache_check_url', ''  ) );
		$checked_time = (int) self::cget( 'cache_check_time', 0  );
		$time_str     = $checked_time ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $checked_time ) : '';
		$nonce        = wp_create_nonce( 'archivio_canary_cache_notice_dismiss' );
		?>
		<div class="notice notice-warning is-dismissible" id="archivio-cache-health-notice">
			<p>
				<strong><?php esc_html_e( 'ArchivioMD — Canary Token cache warning', 'archiviomd' ); ?></strong>
			</p>
			<p>
				<?php
				printf(
					/* translators: 1: post URL, 2: time string */
					esc_html__( 'A cache health check fetched %1$s%2$s and found no zero-width fingerprint characters in the response. This usually means a caching plugin is stripping Unicode characters from cached pages, silently removing the canary fingerprint before it is served to visitors.', 'archiviomd' ),
					$checked_url ? '<a href="' . $checked_url . '" target="_blank">' . $checked_url . '</a>' : esc_html__( 'a recent post', 'archiviomd' ),
					$time_str ? ' ' . esc_html( sprintf( '(%s)', $time_str ) ) : ''
				);
				?>
			</p>
			<p>
				<?php esc_html_e( 'The cache compatibility layer (class-cache-compat.php) is compensating automatically — fingerprints are being re-injected into the output after minification, so cached copies will still carry the fingerprint. However, this adds a small CPU overhead on every cache-miss render. To eliminate it, check your caching plugin settings for options that clean or normalise HTML output, such as "minify HTML", "remove special characters", or "strip invisible characters". WP Super Cache, W3 Total Cache, LiteSpeed Cache, and WP Rocket may all have relevant settings. Unicode-layer channels (Ch.1–4) will be fully efficient again once the root cause is resolved. Semantic and structural channels (Ch.5–14) are not affected by caching.', 'archiviomd' ); ?>
			</p>
			<p>
				<button class="button button-small" id="archivio-dismiss-cache-notice" data-nonce="<?php echo esc_attr( $nonce ); ?>">
					<?php esc_html_e( 'Dismiss', 'archiviomd' ); ?>
				</button>
				<span style="font-size:.82rem;color:#646970;margin-left:10px"><?php esc_html_e( 'The check runs daily. If you fix the caching issue the warning will clear automatically on the next check.', 'archiviomd' ); ?></span>
			</p>
		</div>
		<script>
		document.getElementById('archivio-dismiss-cache-notice') &&
		document.getElementById('archivio-dismiss-cache-notice').addEventListener('click', function() {
			var btn = this;
			btn.disabled = true;
			var fd = new FormData();
			fd.append('action', 'archivio_canary_dismiss_cache_notice');
			fd.append('nonce', btn.dataset.nonce);
			fetch(<?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>, { method: 'POST', body: fd })
				.then(function() {
					var el = document.getElementById('archivio-cache-health-notice');
					if (el) { el.style.display = 'none'; }
				});
		});
		</script>
		<?php
	}

	/**
	 * AJAX handler — dismiss the cache health admin notice.
	 */
	public function ajax_dismiss_cache_notice() {
		check_ajax_referer( 'archivio_canary_cache_notice_dismiss', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error();
		}
		self::cset( 'cache_notice_dismissed', '1', false );
		wp_send_json_success();
	}


	// =========================================================================
	// OPT-OUT AUDIT TRAIL
	// =========================================================================

	/**
	 * Write an audit entry to the discovery log whenever the per-post opt-out
	 * meta key (_archivio_canary_disabled) is added, updated, or deleted.
	 *
	 * Called from added_post_meta, updated_post_meta, and deleted_post_meta hooks.
	 * The action name (added/updated/deleted) is stored in the `note` column so
	 * the log provides a full history of who changed opt-out status and when.
	 *
	 * @param int    $meta_id   ID of the meta row (unused).
	 * @param int    $post_id   Post ID.
	 * @param string $meta_key  Meta key being written.
	 * @param mixed  $value     New meta value (empty string on delete).
	 */
	public function audit_canary_disabled_meta( $meta_id, $post_id, $meta_key, $value ) {
		if ( '_archivio_canary_disabled' !== $meta_key ) {
			return;
		}

		global $wpdb;
		$table = self::log_table_name();

		// Silently skip if table doesn't exist yet
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) ) {
			return;
		}

		// Determine action from the current hook name
		$hook   = current_action();
		$action = 'updated';
		if ( strpos( $hook, 'added' ) !== false ) {
			$action = 'added';
		} elseif ( strpos( $hook, 'deleted' ) !== false ) {
			$action = 'deleted';
		}

		$enabled = ! empty( $value ) && 'deleted' !== $action;
		/* translators: 1: action word (added/updated/deleted), 2: new value */
		$note = sprintf(
			__( 'opt-out %1$s; value: %2$s', 'archiviomd' ),
			$action,
			$enabled ? '1 (disabled)' : '0 (re-enabled)'
		);

		$wpdb->insert(
			$table,
			array(
				'discovered_at'   => current_time( 'mysql', true ),
				'source'          => 'opt_out_change',
				'source_url'      => '',
				'post_id'         => (int) $post_id,
				'fingerprint_ts'  => null,
				'payload_version' => null,
				'valid'           => 0,
				'verifier_id'     => get_current_user_id() ?: null,
				'channels_found'  => 0,
				'note'            => substr( $note, 0, 255 ),
			),
			array( '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%s' )
		);
	}


	// =========================================================================
	// UTILITY
	// =========================================================================

	public static function strip_canary( $html ) {
		$html = str_replace( array( self::ZW_ZERO, self::ZW_ONE ), '', $html );
		$html = str_replace( self::SP_THIN,    self::SP_REGULAR, $html );
		$html = str_replace( self::APOS_CURLY, self::APOS_STRAIGHT, $html );
		$html = str_replace( self::SOFT_HYPHEN, '', $html );
		return $html;
	}
}
