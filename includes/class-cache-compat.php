<?php
/**
 * Canary Token — Cache Compatibility Layer
 *
 * Problem
 * -------
 * Ch.1–4 inject invisible Unicode characters (zero-width chars, thin spaces,
 * soft hyphens, typographic apostrophes) via the WordPress `the_content`
 * filter at render time (priority 99).  Caching plugins capture the rendered
 * HTML *after* the filter chain runs, so in theory the characters should be
 * present in the cached copy.
 *
 * In practice two things go wrong:
 *
 * 1. HTML minifiers embedded in caching plugins strip "special" or
 *    "invisible" characters as part of whitespace normalisation, running
 *    on the output *before* it is written to the cache store.  The cached
 *    copy never contains the fingerprint.
 *
 * 2. The caching plugin uses its own output-buffer callback that wraps the
 *    entire WordPress execution, bypassing `the_content` entirely and serving
 *    its cached copy directly.  The fingerprint was in the first render but
 *    the minifier stripped it; every subsequent request gets the stripped copy.
 *
 * Solution
 * --------
 * This class registers a single `ob_start` callback on `template_redirect`
 * (priority 1, before any caching plugin has a chance to wrap its own buffer).
 * When the callback fires — after WordPress has fully rendered the page and
 * all caching-plugin minifiers have run — it checks whether Ch.1 zero-width
 * characters are present in the output.
 *
 * If they are present: no action — the pipeline is healthy.
 * If they are absent:  the minifier stripped them.  The callback re-encodes
 *                      the article body portion of the HTML and splices the
 *                      fingerprinted content back in before the caching plugin
 *                      writes its copy.
 *
 * Because our `ob_start` wraps the caching plugin's buffer, our callback sees
 * the final HTML the caching plugin is about to store.  We fingerprint that
 * HTML, so both the cache store and the current response carry the fingerprint.
 *
 * Additionally, direct output-filter hooks are registered for the four major
 * caching plugins as a belt-and-suspenders measure for plugins that install
 * their own top-level ob outside `template_redirect`.
 *
 * Supported caching plugins (direct filter hooks)
 * ------------------------------------------------
 *   WP Super Cache    — wp_cache_ob_callback (string filter on full HTML)
 *   W3 Total Cache    — w3tc_process_content  (string filter on full HTML)
 *   LiteSpeed Cache   — litespeed_buffer_output (string filter on full HTML)
 *   WP Rocket         — rocket_buffer          (string filter on full HTML)
 *
 * All five paths (ob_start + four plugin filters) call the same
 * `maybe_reinject()` method so the logic is never duplicated.
 *
 * Scope
 * -----
 * Only runs on singular post/page views (`is_singular()`) where the canary
 * is enabled and the post is published.  All other requests are passed through
 * unchanged.
 *
 * @package ArchivioMD
 * @since   1.12.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_Canary_Cache_Compat {

	/**
	 * Post ID captured at template_redirect, used inside the ob callback
	 * where get_the_ID() may no longer be reliable.
	 *
	 * @var int|null
	 */
	private $current_post_id = null;

	/**
	 * Singleton.
	 */
	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Only register when canary injection is enabled.
		if ( ! get_option( 'archivio_canary_enabled', false ) ) {
			return;
		}

		// Capture the post ID before any output starts, so it is available
		// inside the ob callback where the loop may already be over.
		add_action( 'template_redirect', array( $this, 'capture_post_id' ), 1 );

		// Register our output buffer at priority 1 so it wraps the caching
		// plugin's own buffer (which typically registers at priority 2–10).
		// Our callback therefore sees the fully-rendered, possibly-minified HTML.
		add_action( 'template_redirect', array( $this, 'start_output_buffer' ), 1 );

		// Belt-and-suspenders: direct hooks into each major caching plugin's
		// pre-write output filter.  These fire even if the caching plugin
		// bypasses template_redirect with its own top-level ob.
		add_filter( 'wp_cache_ob_callback',     array( $this, 'maybe_reinject' ), 999 );
		add_filter( 'w3tc_process_content',     array( $this, 'maybe_reinject' ), 999 );
		add_filter( 'litespeed_buffer_output',  array( $this, 'maybe_reinject' ), 999 );
		add_filter( 'rocket_buffer',            array( $this, 'maybe_reinject' ), 999 );
	}

	// =========================================================================
	// POST ID CAPTURE
	// =========================================================================

	/**
	 * Store the current post ID at template_redirect so it is available
	 * inside the output-buffer callback.
	 */
	public function capture_post_id() {
		if ( ! is_singular() ) {
			return;
		}
		$post_id = get_queried_object_id();
		if ( ! $post_id ) {
			return;
		}
		$post = get_post( $post_id );
		if ( ! $post || 'publish' !== $post->post_status ) {
			return;
		}
		if ( get_post_meta( $post_id, '_archivio_canary_disabled', true ) ) {
			return;
		}
		$this->current_post_id = $post_id;
	}

	// =========================================================================
	// OUTPUT BUFFER
	// =========================================================================

	/**
	 * Start an output buffer that wraps the entire page render.
	 * The callback fires after WordPress (and any caching-plugin minifiers)
	 * have produced the final HTML but before it is written to the cache store.
	 */
	public function start_output_buffer() {
		if ( null === $this->current_post_id ) {
			return; // not a fingerprint-eligible request
		}
		ob_start( array( $this, 'ob_callback' ) );
	}

	/**
	 * Output-buffer callback.  Receives the fully-rendered (and possibly
	 * minified) HTML for the page.  Re-injects Ch.1–4 if they were stripped.
	 *
	 * @param  string $html  Full page HTML.
	 * @return string        HTML with Ch.1–4 present.
	 */
	public function ob_callback( $html ) {
		if ( null === $this->current_post_id ) {
			return $html;
		}
		return $this->maybe_reinject( $html );
	}

	// =========================================================================
	// CORE RE-INJECTION LOGIC
	// =========================================================================

	/**
	 * Check whether Ch.1 zero-width characters are present in $html.
	 * If they are, the Unicode layer survived the pipeline and no action is
	 * needed.  If they are absent, extract the article body, re-encode it,
	 * and splice it back in.
	 *
	 * This method is intentionally idempotent: calling it on already-
	 * fingerprinted HTML is a no-op (the ZW check passes immediately).
	 *
	 * @param  string $html  Full page or article HTML.
	 * @return string        HTML guaranteed to contain the Ch.1 fingerprint
	 *                       (provided the article body has enough word-starts
	 *                       to carry the payload).
	 */
	public function maybe_reinject( $html ) {
		if ( empty( $html ) || null === $this->current_post_id ) {
			return $html;
		}

		// Fast path: ZW chars already present — pipeline is healthy.
		if ( $this->has_zero_width_chars( $html ) ) {
			return $html;
		}

		// ZW chars are absent — the minifier stripped them.
		// Re-encode the article body and splice it back into the full page HTML.
		return $this->reinject_into_page( $html, $this->current_post_id );
	}

	// =========================================================================
	// DETECTION
	// =========================================================================

	/**
	 * Return true if the HTML contains at least one Ch.1 zero-width character.
	 * ZW_ZERO = U+200B, ZW_ONE = U+200C.
	 *
	 * @param  string $html
	 * @return bool
	 */
	private function has_zero_width_chars( $html ) {
		return (
			false !== strpos( $html, MDSM_Canary_Token::ZW_ZERO ) ||
			false !== strpos( $html, MDSM_Canary_Token::ZW_ONE )
		);
	}

	// =========================================================================
	// EXTRACTION AND RE-INJECTION
	// =========================================================================

	/**
	 * Extract the article body from the full page HTML, run encode() on it,
	 * and splice the result back into the page at the same position.
	 *
	 * Article body extraction uses the same heuristics as the URL decoder:
	 * look for the innermost <article>, <main>, or role="main" element.
	 * If none is found, fall back to encoding the entire <body> content.
	 * If that also fails, encode the whole HTML string (last resort).
	 *
	 * The splice is done by byte-offset replacement so no HTML is re-parsed.
	 *
	 * @param  string $html     Full page HTML.
	 * @param  int    $post_id  Post ID.
	 * @return string           Full page HTML with fingerprint re-injected.
	 */
	private function reinject_into_page( $html, $post_id ) {
		$canary = MDSM_Canary_Token::get_instance();

		// ── Attempt 1: <article> element ─────────────────────────────────────
		$result = $this->extract_and_encode( $html, $post_id, $canary,
			'/<article\b[^>]*>(.*?)<\/article>/is' );
		if ( null !== $result ) {
			return $result;
		}

		// ── Attempt 2: <main> element ─────────────────────────────────────────
		$result = $this->extract_and_encode( $html, $post_id, $canary,
			'/<main\b[^>]*>(.*?)<\/main>/is' );
		if ( null !== $result ) {
			return $result;
		}

		// ── Attempt 3: role="main" ────────────────────────────────────────────
		$result = $this->extract_and_encode( $html, $post_id, $canary,
			'/<[a-z][a-z0-9]*\b[^>]*\brole=["\']main["\'][^>]*>(.*?)<\/[a-z][a-z0-9]*>/is' );
		if ( null !== $result ) {
			return $result;
		}

		// ── Attempt 4: <body> ─────────────────────────────────────────────────
		$result = $this->extract_and_encode( $html, $post_id, $canary,
			'/<body\b[^>]*>(.*?)<\/body>/is' );
		if ( null !== $result ) {
			return $result;
		}

		// ── Fallback: encode the whole string ─────────────────────────────────
		// This is unlikely to produce a clean result but guarantees a return value.
		return $canary->encode( $html, $post_id );
	}

	/**
	 * Run a single extraction regex against $html, encode the captured body,
	 * and return the full HTML with the encoded body spliced back in.
	 * Returns null if the regex does not match.
	 *
	 * @param  string             $html
	 * @param  int                $post_id
	 * @param  MDSM_Canary_Token  $canary
	 * @param  string             $pattern  PCRE pattern with one capture group for the body.
	 * @return string|null
	 */
	private function extract_and_encode( $html, $post_id, $canary, $pattern ) {
		if ( ! preg_match( $pattern, $html, $m, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}

		$full_match   = $m[0][0]; // the entire matched element, e.g. "<article>...</article>"
		$full_offset  = $m[0][1]; // byte offset of the full match in $html
		$inner        = $m[1][0]; // the captured inner content
		$inner_offset = $m[1][1]; // byte offset of the inner content

		// Encode only the inner content so we do not corrupt the wrapping tags.
		$encoded_inner = $canary->encode( $inner, $post_id );

		if ( $encoded_inner === $inner ) {
			// encode() made no changes (insufficient slots, or post opt-out).
			return null;
		}

		// Splice: replace the inner content within the full match, then replace
		// the full match within $html, all by byte offset to avoid re-parsing.
		$inner_start_in_full = $inner_offset - $full_offset;
		$new_full_match = substr( $full_match, 0, $inner_start_in_full )
		                . $encoded_inner
		                . substr( $full_match, $inner_start_in_full + strlen( $inner ) );

		return substr( $html, 0, $full_offset )
		     . $new_full_match
		     . substr( $html, $full_offset + strlen( $full_match ) );
	}
}
