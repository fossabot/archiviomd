<?php
/**
 * Canary Token Admin Page — tabbed interface
 * Tabs: Settings | Decoder (paste + URL) | DMCA Notice
 *
 * @package ArchivioMD
 * @since 1.10.0
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

$enabled      = (bool) MDSM_Canary_Token::cget( 'enabled', false );
$contractions = (bool) MDSM_Canary_Token::cget( 'contractions', false );
$synonyms     = (bool) MDSM_Canary_Token::cget( 'synonyms', false );
$punctuation  = (bool) MDSM_Canary_Token::cget( 'punctuation', false );
$spelling     = (bool) MDSM_Canary_Token::cget( 'spelling', false );
$hyphenation  = (bool) MDSM_Canary_Token::cget( 'hyphenation', false );
$numbers      = (bool) MDSM_Canary_Token::cget( 'numbers', false );
$punctuation2 = (bool) MDSM_Canary_Token::cget( 'punctuation2', false );
$citation     = (bool) MDSM_Canary_Token::cget( 'citation', false );
$parity       = (bool) MDSM_Canary_Token::cget( 'parity', false );
$wordcount    = (bool) MDSM_Canary_Token::cget( 'wordcount', false );
$payload_ver  = (int)  MDSM_Canary_Token::cget( 'payload_version', 1 );
$hmac_ok      = defined( 'ARCHIVIOMD_HMAC_KEY' ) && strlen( ARCHIVIOMD_HMAC_KEY ) >= 16;
$rest_url     = rest_url( 'content/v1/verify' );
$nonce        = wp_create_nonce( 'archivio_canary_nonce' );
$ajax_url     = admin_url( 'admin-ajax.php' );

// Load saved DMCA contact
$dmca = array();
foreach ( array( 'name','title','company','email','phone','address','website' ) as $f ) {
    $dmca[ $f ] = get_option( 'archivio_dmca_' . $f, '' );
}
?>
<style>
/* ── Base ─────────────────────────────────────────────────────────────────── */
.ct-wrap{max-width:900px}
.ct-panel{background:#fff;border:1px solid #dcdcde;border-radius:4px;padding:24px 28px;margin-bottom:20px}
.ct-panel h2{margin-top:0;font-size:1.1rem;display:flex;align-items:center;gap:8px}
.ct-panel h3{margin:0 0 8px;font-size:.93rem}
.ct-hr{border:none;border-top:1px solid #dcdcde;margin:20px 0}
.ct-muted{font-size:.84rem;color:#646970;margin:0 0 12px}
/* ── Tabs ─────────────────────────────────────────────────────────────────── */
.ct-tabs{display:flex;gap:0;border-bottom:2px solid #dcdcde;margin-bottom:22px}
.ct-tab{padding:9px 20px;cursor:pointer;font-size:.93rem;font-weight:600;color:#646970;border:2px solid transparent;border-bottom:none;border-radius:4px 4px 0 0;margin-bottom:-2px;background:transparent;transition:color .15s}
.ct-tab:hover{color:#1d2327}
.ct-tab.active{color:#1d2327;background:#fff;border-color:#dcdcde;border-bottom-color:#fff}
.ct-pane{display:none}.ct-pane.active{display:block}
/* ── Badges / labels ──────────────────────────────────────────────────────── */
.ct-badge{padding:3px 10px;border-radius:3px;font-size:.82rem;font-weight:600}
.ct-badge-ok{background:#d1fae5;color:#065f46}.ct-badge-warn{background:#fef3c7;color:#92400e}
.ct-layer{display:inline-block;padding:1px 7px;border-radius:2px;font-size:.75rem;font-weight:600;margin-left:6px;vertical-align:middle}
.ct-layer-u{background:#e0f2fe;color:#0c4a6e}.ct-layer-s{background:#fce7f3;color:#831843}.ct-layer-t{background:#dcfce7;color:#14532d}
/* ── Toggles ──────────────────────────────────────────────────────────────── */
.ct-toggle{display:flex;align-items:flex-start;gap:12px;margin:10px 0 4px}
.ct-toggle input[type=checkbox]{margin-top:3px;flex-shrink:0}
.ct-toggle-label strong{display:block;font-size:.92rem;margin-bottom:2px}
.ct-toggle-label .ct-muted{margin:0}
/* ── Monospace box ────────────────────────────────────────────────────────── */
.ct-mono{font-family:monospace;font-size:.79rem;background:#f6f7f7;padding:7px 10px;border-radius:3px;border:1px solid #dcdcde;display:block;word-break:break-all;margin-top:6px}
/* ── Info boxes ───────────────────────────────────────────────────────────── */
.ct-info{padding:10px 14px;border-left:4px solid #72aee6;background:#f0f6fc;border-radius:2px;font-size:.87rem;margin-top:12px}
.ct-info.warn{border-color:#dba617;background:#fefce8}
/* ── Decoder sub-tabs ─────────────────────────────────────────────────────── */
.ct-subtabs{display:flex;gap:6px;margin-bottom:16px}
.ct-subtab{padding:5px 14px;border-radius:14px;cursor:pointer;font-size:.84rem;font-weight:600;color:#646970;background:#f6f7f7;border:1px solid #dcdcde;transition:all .15s}
.ct-subtab.active{background:#2271b1;color:#fff;border-color:#2271b1}
.ct-subpane{display:none}.ct-subpane.active{display:block}
/* ── Textarea / inputs ────────────────────────────────────────────────────── */
.ct-textarea{width:100%;min-height:130px;font-family:monospace;font-size:.82rem;border:1px solid #8c8f94;border-radius:3px;padding:10px;resize:vertical;box-sizing:border-box}
.ct-input-row{display:flex;gap:8px;align-items:center;margin-bottom:10px}
.ct-input-row input[type=url]{flex:1;padding:8px 10px;border:1px solid #8c8f94;border-radius:3px;font-size:.9rem}
.ct-decode-row{display:flex;align-items:center;gap:10px;margin-top:10px}
/* ── Result card ──────────────────────────────────────────────────────────── */
.ct-result{display:none;margin-top:18px;padding:16px 20px;border-radius:4px;border:1px solid #dcdcde}
.ct-result.ok{border-color:#00a32a;background:#f0fdf4}
.ct-result.warn{border-color:#dba617;background:#fefce8}
.ct-result.miss{border-color:#8c8f94;background:#f6f7f7}
.ct-result h3{margin:0 0 12px;font-size:1rem}
.ct-prov{display:grid;grid-template-columns:165px 1fr;gap:5px 12px;font-size:.87rem}
.ct-prov .k{font-weight:600;color:#50575e}.ct-prov .v{color:#1d2327;word-break:break-all}
/* ── Channel table ────────────────────────────────────────────────────────── */
.ct-ch-wrap{margin-top:14px}
.ct-ch-wrap summary{cursor:pointer;font-size:.82rem;color:#646970;user-select:none}
.ct-ch-tbl{width:100%;border-collapse:collapse;font-size:.79rem;margin-top:8px}
.ct-ch-tbl th,.ct-ch-tbl td{padding:5px 8px;border:1px solid #dcdcde;vertical-align:middle}
.ct-ch-tbl th{background:#f6f7f7;font-weight:600;text-align:left}
.ct-ch-tbl tr.sem-row td:first-child{border-left:3px solid #f472b6}
.ct-ch-tbl tr.uni-row td:first-child{border-left:3px solid #38bdf8}
.ct-bar{display:inline-block;height:7px;border-radius:4px;background:#2271b1;vertical-align:middle;margin-right:4px}
/* ── Preview box ──────────────────────────────────────────────────────────── */
.ct-preview{font-size:.8rem;color:#50575e;font-style:italic;background:#f6f7f7;padding:8px 12px;border-radius:3px;margin-top:10px;white-space:pre-wrap;word-break:break-all}
/* ── DMCA form ────────────────────────────────────────────────────────────── */
.ct-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 20px;margin-bottom:14px}
.ct-form-grid label{display:flex;flex-direction:column;gap:4px;font-size:.87rem;font-weight:600;color:#1d2327}
.ct-form-grid input,.ct-form-grid textarea{padding:7px 9px;border:1px solid #8c8f94;border-radius:3px;font-size:.88rem;font-family:inherit}
.ct-form-grid .span2{grid-column:1/-1}
.ct-form-grid textarea{min-height:60px;resize:vertical}
/* ── DMCA output ──────────────────────────────────────────────────────────── */
.ct-notice-wrap{display:none;margin-top:18px}
.ct-notice-box{font-family:monospace;font-size:.8rem;white-space:pre-wrap;word-break:break-word;background:#f6f7f7;border:1px solid #dcdcde;border-radius:3px;padding:16px;max-height:480px;overflow-y:auto;line-height:1.6}
.ct-notice-actions{display:flex;gap:10px;margin-top:10px;flex-wrap:wrap}
/* ── How it works ─────────────────────────────────────────────────────────── */
.ct-how{display:grid;grid-template-columns:1fr 1fr;gap:14px;font-size:.83rem;color:#50575e;margin-top:12px}
.ct-how strong{color:#1d2327;display:block;margin-bottom:3px}
</style>

<div class="wrap ct-wrap">
<h1><?php esc_html_e('Canary Tokens','archiviomd');?></h1>
<?php if(!$hmac_ok):?>
<div class="notice notice-warning inline" style="margin:0 0 14px"><p>
<strong><?php esc_html_e('Weak key:','archiviomd');?></strong>
<?php printf(esc_html__('Define %s in wp-config.php for tamper-evident fingerprints.','archiviomd'),'<code>ARCHIVIOMD_HMAC_KEY</code>');?>
</p></div>
<?php endif;?>

<!-- ══ TABS ══════════════════════════════════════════════════════════════ -->
<div class="ct-tabs">
  <div class="ct-tab active" data-tab="settings"><?php esc_html_e('Settings','archiviomd');?></div>
  <div class="ct-tab" data-tab="decoder"><?php esc_html_e('Decoder','archiviomd');?></div>
  <div class="ct-tab" data-tab="dmca"><?php esc_html_e('DMCA Notice','archiviomd');?></div>
  <div class="ct-tab" data-tab="log"><?php esc_html_e('Discovery Log','archiviomd');?></div>
</div>

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 1: SETTINGS                                                       -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div class="ct-pane active" id="ct-pane-settings">
<div class="ct-panel">
<h2>
  <span class="dashicons dashicons-admin-network" style="color:#2271b1;font-size:1.2rem;width:1.2rem;height:1.2rem;"></span>
  <?php esc_html_e('Channel Settings','archiviomd');?>
  <span class="ct-badge <?php echo $hmac_ok?'ct-badge-ok':'ct-badge-warn';?>">
    <?php echo $hmac_ok?esc_html__('🔑 HMAC key set','archiviomd'):esc_html__('⚠ Fallback key','archiviomd');?>
  </span>
</h2>

<div class="ct-toggle">
  <input type="checkbox" id="ct-enabled" <?php checked($enabled);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Enable fingerprinting on all published posts &amp; pages','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Master switch. Activates ch.1-4 on all post views, excerpts, and feeds. Works on any post type — posts, pages, custom post types. Skips drafts and private posts. Database is never modified; injection is render-time only.','archiviomd');?></p>
  </div>
</div>

<hr class="ct-hr" style="margin:16px 0">
<p style="font-size:.82rem;font-weight:700;color:#1d2327;margin:0 0 10px">
  <span class="ct-layer ct-layer-s">SEMANTIC CHANNELS</span>
  <?php esc_html_e('— survive OCR, screenshot, and retyping','archiviomd');?>
</p>

<div class="ct-toggle">
  <input type="checkbox" id="ct-contractions" <?php checked($contractions);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.5 — Contraction encoding','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('"don\'t" ↔ "do not", "it\'s" ↔ "it is" and 30+ pairs at HMAC-derived positions. Skips code, blockquotes, headings, and links.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-synonyms" <?php checked($synonyms);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.6 — Synonym substitution','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('"start" ↔ "begin", "often" ↔ "frequently" and 28+ pairs. Curated for neutrality — no register or connotation shift.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-punctuation" <?php checked($punctuation);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.7 — Punctuation choice','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Two sub-channels: (A) Oxford comma — "red, white and blue" ↔ "red, white, and blue". (B) Em-dash asides ↔ parenthetical asides — "— note —" ↔ "(note)". Both are completely invisible stylistic choices. Survives OCR and retyping.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-spelling" <?php checked($spelling);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.8 — Spelling variants','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('"organise" ↔ "organize", "colour" ↔ "color", "centre" ↔ "center" and 60+ British/American pairs. Mixed spelling is common in publications with international contributors — a normaliser enforcing consistency would produce visibly edited text.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-hyphenation" <?php checked($hyphenation);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.9 — Hyphenation choices','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('"email" ↔ "e-mail", "online" ↔ "on-line", "decision-making" ↔ "decisionmaking" and 30+ position-independent compound pairs. Both forms appear in major style guides. Effective on tech, policy, and editorial content.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-numbers" <?php checked($numbers);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.10 — Number and date style','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Three sub-channels: (A) Thousands separator — "1,000" ↔ "1000". (B) Percent style — "10 percent" ↔ "10%". (C) Ordinal style — "first" ↔ "1st" through "twelfth" ↔ "12th". Density depends on content; most effective on financial, statistical, and news writing.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-punctuation2" <?php checked($punctuation2);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.11 — Punctuation style II','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Three sub-channels: (A) Em-dash spacing — "word—word" ↔ "word — word". (B) Comma before "too" — "it too" ↔ "it, too". (C) Introductory-clause comma — "In 2020 the company" ↔ "In 2020, the company". All three are house-style choices invisible to readers. Most effective on analytical and editorial content.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-citation" <?php checked($citation);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.12 — Citation and title style','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Two sub-channels: (A) Attribution colon — "Smith said:" ↔ "Smith said" before a direct quote. (B) Title formatting — &lt;em&gt;The Times&lt;/em&gt; ↔ "The Times". Slot density is zero on posts with no attribution or titles; high on journalism, academic writing, and legal publishing.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-parity" <?php checked($parity);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.13 — Sentence-count parity','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Encodes one bit per qualifying paragraph by making its sentence count even or odd. A short natural clause is appended to or removed from the final sentence. Survives Unicode normalisation, HTML minification, CDN processing, and copy-paste through any rich-text editor. One slot per paragraph of 2+ sentences and 20+ words.','archiviomd');?></p>
  </div>
</div>
<div class="ct-toggle" style="margin-top:10px">
  <input type="checkbox" id="ct-wordcount" <?php checked($wordcount);?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Ch.14 — Word-count parity','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('Encodes one bit per qualifying sentence by making its word count even or odd. A single filler word is inserted at or removed from a key-derived position within the sentence. Both the filler word and its position are site-specific secrets derived from your HMAC key. One slot per sentence of 10+ words.','archiviomd');?></p>
  </div>
</div>

<div style="margin-top:18px;display:flex;align-items:center;gap:12px">
  <button id="ct-save-btn" class="button button-primary"><?php esc_html_e('Save Settings','archiviomd');?></button>
  <span id="ct-save-msg" style="font-size:.9rem;"></span>
</div>

<hr class="ct-hr">

<?php /* ── Payload Version card ─────────────────────────────────────────── */ ?>
<h3 style="margin:0 0 6px;font-size:.95rem;display:flex;align-items:center;gap:8px">
  <?php esc_html_e('Payload Security Version','archiviomd');?>
  <?php if ( 2 === $payload_ver ) : ?>
    <span class="ct-badge ct-badge-ok"><?php esc_html_e('v2 — 64-bit MAC','archiviomd');?></span>
  <?php else : ?>
    <span class="ct-badge ct-badge-warn"><?php esc_html_e('v1 — 48-bit MAC (default)','archiviomd');?></span>
  <?php endif; ?>
</h3>
<p class="ct-muted" style="margin-bottom:12px"><?php esc_html_e('v1 encodes a 14-byte payload with a 48-bit truncated HMAC-SHA256. v2 encodes a 17-byte payload with a 64-bit MAC and a version byte — meeting NIST SP 800-107 recommendations. Both versions are decoded transparently; enabling v2 does not break existing v1 fingerprints in circulating copies.','archiviomd');?></p>

<div class="ct-toggle">
  <input type="checkbox" id="ct-v2" <?php checked( 2, $payload_ver );?>>
  <div class="ct-toggle-label">
    <strong><?php esc_html_e('Enable v2 payload (64-bit MAC, NIST-recommended)','archiviomd');?></strong>
    <p class="ct-muted"><?php esc_html_e('New injections will use the stronger payload. Previously circulating copies fingerprinted under v1 continue to verify and are displayed with a "Legacy v1" badge in the decoder. There is no downgrade path — switching back to v1 means new page loads will carry v1 fingerprints again, but any v2 copies already in circulation still decode correctly.','archiviomd');?></p>
  </div>
</div>

<div id="ct-v2-warning" class="ct-info warn" style="margin-top:10px;<?php echo ( 2 !== $payload_ver ) ? 'display:none' : ''; ?>">
  <?php esc_html_e('v2 is active. Existing copies of your content that were fingerprinted before this change will be reported as "Legacy v1 — verified" in the decoder. No action is required unless you need to prove a specific copy was made after the v2 upgrade, in which case the payload_version field in the decode result serves as evidence.','archiviomd');?>
</div>

<?php
// Key health status
$kf_stored  = MDSM_Canary_Token::cget( 'key_fingerprint', '' );
$kf_current = substr( hash( 'sha256',
	( defined( 'ARCHIVIOMD_HMAC_KEY' ) && strlen( ARCHIVIOMD_HMAC_KEY ) >= 16 )
		? ARCHIVIOMD_HMAC_KEY
		: hash_hmac( 'sha256', get_site_url(), wp_salt( 'auth' ) )
), 0, 16 );
$key_ok = ( '' !== $kf_stored && hash_equals( $kf_stored, $kf_current ) );
?>

<hr class="ct-hr">
<h3 style="margin:0 0 6px;font-size:.95rem;display:flex;align-items:center;gap:8px">
  <?php esc_html_e( 'Key Health', 'archiviomd' ); ?>
  <?php if ( $key_ok ) : ?>
    <span class="ct-badge ct-badge-ok"><?php esc_html_e( 'Key stable', 'archiviomd' ); ?></span>
  <?php elseif ( '' === $kf_stored ) : ?>
    <span class="ct-badge ct-badge-warn"><?php esc_html_e( 'Not yet recorded', 'archiviomd' ); ?></span>
  <?php else : ?>
    <span class="ct-badge" style="background:#fecaca;color:#991b1b"><?php esc_html_e( 'Key changed', 'archiviomd' ); ?></span>
  <?php endif; ?>
</h3>
<p class="ct-muted" style="margin-bottom:6px">
  <?php esc_html_e( 'ArchivioMD stores a short fingerprint of the HMAC key at first activation and checks it on every load. If the key changes — for example because WordPress auth salts were regenerated or ARCHIVIOMD_HMAC_KEY was modified — a persistent admin notice appears across all admin pages.', 'archiviomd' ); ?>
</p>
<?php if ( '' !== $kf_stored ) : ?>
  <p class="ct-muted" style="margin:0">
    <?php
    printf(
      /* translators: %s key fingerprint hex */
      esc_html__( 'Current key fingerprint: %s', 'archiviomd' ),
      '<code>' . esc_html( $kf_current ) . '</code>'
    );
    ?>
  </p>
<?php endif; ?>

<hr class="ct-hr">
<h3 style="margin:0 0 6px;font-size:.93rem"><?php esc_html_e( 'Re-fingerprint All Posts', 'archiviomd' ); ?></h3>
<p class="ct-muted"><?php esc_html_e( 'After a key rotation, existing fingerprints decode as invalid under the new key. Re-fingerprinting stores a fresh timestamp on every published post so the next page load produces a payload bound to the current key. Content is never modified — only a small post-meta value is updated.', 'archiviomd' ); ?></p>
<?php
$published_count = (int) wp_count_posts()->publish;
// Sum across all public post types
$pt_count = 0;
foreach ( get_post_types( array( 'public' => true ) ) as $pt ) {
    $counts = wp_count_posts( $pt );
    $pt_count += isset( $counts->publish ) ? (int) $counts->publish : 0;
}
?>
<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
  <button id="ct-restamp-btn" class="button button-secondary">
    <?php
    printf(
      /* translators: %d number of published posts */
      esc_html__( 'Re-fingerprint All Posts (%d published)', 'archiviomd' ),
      $pt_count
    );
    ?>
  </button>
  <span id="ct-restamp-msg" style="font-size:.84rem;color:#646970"></span>
</div>
<div class="ct-info warn" style="margin-top:10px;display:none" id="ct-restamp-warning">
  <strong><?php esc_html_e( 'Warning:', 'archiviomd' ); ?></strong>
  <?php esc_html_e( 'This will update post meta on every published post. Old circulating copies fingerprinted under the previous key will decode as invalid — this is expected. Copies made after this operation will carry the new key\'s fingerprint. Click the button again to confirm.', 'archiviomd' ); ?>
</div>

<hr class="ct-hr">
<h3><?php esc_html_e( 'Public Verification Endpoint', 'archiviomd' ); ?></h3>
<p class="ct-muted"><?php esc_html_e( 'Anyone can verify a fingerprint (Ch.1 only, no key required) by POSTing content to:', 'archiviomd' ); ?></p>
<code class="ct-mono"><?php echo esc_html( $rest_url ); ?></code>
<p class="ct-muted" style="margin-top:8px">Body: <code>{"content":"…"}</code> → <code>found, valid, post_id, timestamp_human, post_title, post_url, payload_version</code></p>
<p class="ct-muted" style="margin-top:4px"><?php esc_html_e( 'Rate limited to 60 requests per minute per IP address.', 'archiviomd' ); ?></p>

<h3 style="margin-top:14px"><?php esc_html_e( 'Authenticated Endpoint (full channel breakdown)', 'archiviomd' ); ?></h3>
<code class="ct-mono"><?php echo esc_html( rest_url( 'content/v1/verify/full' ) ); ?></code>
<p class="ct-muted" style="margin-top:8px"><?php esc_html_e( 'Requires manage_options capability (administrator). Returns the complete channel-by-channel decode result including all fourteen channels, coverage percentages, and per-channel HMAC verification. No rate limit. Suitable for automated tooling and bulk forensic workflows.', 'archiviomd' ); ?></p>
<p class="ct-muted" style="margin-top:4px"><?php esc_html_e( 'Also fingerprints REST API responses — any programmatic consumer fetching posts via /wp-json/wp/v2/posts will receive fingerprinted content.rendered automatically when injection is enabled.', 'archiviomd' ); ?></p>

<hr class="ct-hr">
<div class="ct-how">
  <div><strong><?php esc_html_e('Ch.1 — Zero-width','archiviomd');?> <span class="ct-layer ct-layer-u">UNICODE</span></strong><?php esc_html_e('U+200B/U+200C before every word-start. Full payload × 3. Publicly decodable.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.2 — Thin spaces','archiviomd');?> <span class="ct-layer ct-layer-u">UNICODE</span></strong><?php esc_html_e('U+0020 → U+2009 at HMAC-derived positions.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.3 — Apostrophes','archiviomd');?> <span class="ct-layer ct-layer-u">UNICODE</span></strong><?php esc_html_e('U+0027 → U+2019 at HMAC-derived positions.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.4 — Soft hyphens','archiviomd');?> <span class="ct-layer ct-layer-u">UNICODE</span></strong><?php esc_html_e('U+00AD inside long words. Invisible unless a line break falls there.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.5 — Contractions','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('75 contraction pairs. Survives OCR and retyping.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.6 — Synonyms','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('110 word pairs. Meaning-neutral substitutions.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.7 — Punctuation','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('Oxford comma + em-dash/parentheses. Invisible stylistic choices.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.8 — Spelling','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('60+ British/American pairs. "organise"/"organize", "colour"/"color", etc.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.9 — Hyphenation','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('30+ compound pairs. "email"/"e-mail", "online"/"on-line", etc.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.10 — Numbers','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('Thousands separator, percent style, ordinals. "1,000"/"1000", "first"/"1st".','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.11 — Punct. II','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('Em-dash spacing, comma before "too", introductory-clause comma.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.12 — Citation','archiviomd');?> <span class="ct-layer ct-layer-s">SEMANTIC</span></strong><?php esc_html_e('Attribution colon ("said:"/"said") + title italics vs. quotation marks.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.13 — Sent. parity','archiviomd');?> <span class="ct-layer ct-layer-t">STRUCTURAL</span></strong><?php esc_html_e('Sentence-count parity per paragraph. Clause appended/removed. CDN-proof.','archiviomd');?></div>
  <div><strong><?php esc_html_e('Ch.14 — Word parity','archiviomd');?> <span class="ct-layer ct-layer-t">STRUCTURAL</span></strong><?php esc_html_e('Word-count parity per sentence. Key-derived filler word at key-derived position.','archiviomd');?></div>
</div>
</div><!-- .ct-panel -->
</div><!-- #ct-pane-settings -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 2: DECODER                                                        -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div class="ct-pane" id="ct-pane-decoder">
<div class="ct-panel">
<h2><span class="dashicons dashicons-search" style="color:#2271b1;font-size:1.2rem;width:1.2rem;height:1.2rem;"></span> <?php esc_html_e('Canary Decoder','archiviomd');?></h2>
<p class="ct-muted"><?php esc_html_e('Decode a fingerprint from pasted content or directly from a URL. If semantic channels were active, the fingerprint survives OCR and retyping — paste the re-typed text and it will still verify.','archiviomd');?></p>

<div class="ct-subtabs">
  <div class="ct-subtab active" data-subtab="paste"><?php esc_html_e('Paste Content','archiviomd');?></div>
  <div class="ct-subtab" data-subtab="url"><?php esc_html_e('From URL','archiviomd');?></div>
</div>

<!-- ── Paste sub-pane ──────────────────────────────────────────────────── -->
<div class="ct-subpane active" id="ct-subpane-paste">
  <textarea id="ct-input" class="ct-textarea" placeholder="<?php esc_attr_e('Paste copied text or HTML here…','archiviomd');?>"></textarea>
  <div class="ct-decode-row">
    <button id="ct-decode-btn" class="button button-secondary"><?php esc_html_e('Decode','archiviomd');?></button>
    <span id="ct-spin" style="display:none;"><span class="spinner is-active" style="float:none;margin:0;"></span></span>
  </div>
</div>

<!-- ── URL sub-pane ────────────────────────────────────────────────────── -->
<div class="ct-subpane" id="ct-subpane-url">
  <p class="ct-muted"><?php esc_html_e('Enter the URL of the suspected infringing page. The server will fetch the page, extract the article content, and run the full decoder against it.','archiviomd');?></p>
  <div class="ct-input-row">
    <input type="url" id="ct-url-input" placeholder="https://example.com/stolen-article/">
    <button id="ct-url-btn" class="button button-secondary"><?php esc_html_e('Fetch & Decode','archiviomd');?></button>
    <span id="ct-url-spin" style="display:none;"><span class="spinner is-active" style="float:none;margin:0;"></span></span>
  </div>
  <p id="ct-url-preview-label" style="display:none;font-size:.8rem;font-weight:600;color:#50575e;margin:0 0 4px;"><?php esc_html_e('Content extracted from page:','archiviomd');?></p>
  <div id="ct-url-preview" class="ct-preview" style="display:none;"></div>

  <hr class="ct-hr" style="margin:18px 0 14px">

  <div style="display:flex;align-items:flex-start;gap:10px">
    <input type="checkbox" id="ct-deep-enable" style="margin-top:3px;flex-shrink:0">
    <div>
      <strong style="font-size:.9rem"><?php esc_html_e('Deep Scan (brute-force)','archiviomd');?></strong>
      <p class="ct-muted" style="margin:3px 0 0"><?php esc_html_e('Use when zero-width characters were stripped but semantic text changes (contractions, synonyms, punctuation) are still present. Tries up to 500 published posts. Requires at least 2 independent semantic channels to confirm a match — a single-channel result is flagged as unconfirmed. Takes 10–60 seconds depending on site size.','archiviomd');?></p>
    </div>
  </div>

  <div id="ct-deep-options" style="display:none;margin-top:12px;padding:12px 14px;background:#f9f9f9;border:1px solid #dcdcde;border-radius:3px">
    <label style="display:block;margin-bottom:8px;font-size:.9rem">
      <strong><?php esc_html_e('Date hint (optional)','archiviomd');?></strong>
      <p class="ct-muted" style="margin:2px 0 6px"><?php esc_html_e('Approximate date the content was copied. Narrows the candidate set to posts published within ±180 days, dramatically reducing scan time. Leave blank to scan all published posts.','archiviomd');?></p>
      <input type="date" id="ct-deep-date" style="width:180px">
    </label>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <button id="ct-deep-scan-btn" class="button button-primary"><?php esc_html_e('Start Deep Scan','archiviomd');?></button>
      <button id="ct-deep-cancel-btn" class="button" style="display:none"><?php esc_html_e('Cancel','archiviomd');?></button>
      <span id="ct-deep-spin" style="display:none"><span class="spinner is-active" style="float:none;margin:0"></span></span>
    </div>
    <div id="ct-deep-progress-wrap" style="display:none;margin-top:10px">
      <div style="background:#dcdcde;border-radius:3px;height:8px;overflow:hidden">
        <div id="ct-deep-bar" style="height:100%;background:#2271b1;width:0%;transition:width .3s"></div>
      </div>
      <p id="ct-deep-status" class="ct-muted" style="margin:5px 0 0;font-size:.82rem"></p>
    </div>
  </div>
</div>

<!-- ── Shared result card ──────────────────────────────────────────────── -->
<div id="ct-result" class="ct-result">
  <h3 id="ct-result-title"></h3>
  <div id="ct-prov" class="ct-prov"></div>
  <div id="ct-use-dmca-wrap" style="display:none;margin-top:14px;">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
      <button id="ct-use-dmca-btn" class="button button-small">
        <?php esc_html_e('Use this result in DMCA Notice →','archiviomd');?>
      </button>
      <button id="ct-evidence-btn" class="button button-small">
        <?php esc_html_e('⬇ Download Evidence Package','archiviomd');?>
      </button>
      <span id="ct-evidence-msg" style="font-size:.82rem;color:#646970;"></span>
    </div>
  </div>
  <details class="ct-ch-wrap" id="ct-ch-det" open>
    <summary><?php esc_html_e('Channel breakdown','archiviomd');?></summary>
    <table class="ct-ch-tbl">
      <thead><tr>
        <th><?php esc_html_e('Channel','archiviomd');?></th>
        <th><?php esc_html_e('Layer','archiviomd');?></th>
        <th><?php esc_html_e('Coverage','archiviomd');?></th>
        <th><?php esc_html_e('Post ID','archiviomd');?></th>
        <th><?php esc_html_e('HMAC','archiviomd');?></th>
        <th><?php esc_html_e('Agrees w/ Ch.1','archiviomd');?></th>
      </tr></thead>
      <tbody id="ct-ch-rows"></tbody>
    </table>
    <p id="ct-sem-note" style="display:none;font-size:.8rem;color:#646970;margin:6px 0 0">
      <?php esc_html_e('0% on a semantic channel means it was not enabled when published — not that it was stripped.','archiviomd');?>
    </p>
  </details>
</div>
</div><!-- .ct-panel -->
</div><!-- #ct-pane-decoder -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 3: DMCA NOTICE                                                    -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div class="ct-pane" id="ct-pane-dmca">
<div class="ct-panel">
<h2><span class="dashicons dashicons-media-document" style="color:#2271b1;font-size:1.2rem;width:1.2rem;height:1.2rem;"></span> <?php esc_html_e('DMCA Takedown Notice Generator','archiviomd');?></h2>
<p class="ct-muted"><?php esc_html_e('Fill in your contact details once — they are saved for re-use. Then provide the infringing URL (or populate it automatically from the Decoder tab) and generate a ready-to-send DMCA takedown notice.','archiviomd');?></p>

<h3><?php esc_html_e('Your Contact Details','archiviomd');?></h3>
<div class="ct-form-grid">
  <label><?php esc_html_e('Full Name','archiviomd');?>
    <input type="text" id="dm-name" value="<?php echo esc_attr($dmca['name']);?>" placeholder="Jane Smith">
  </label>
  <label><?php esc_html_e('Title / Role','archiviomd');?>
    <input type="text" id="dm-title" value="<?php echo esc_attr($dmca['title']);?>" placeholder="Owner / Editor">
  </label>
  <label><?php esc_html_e('Company / Publication','archiviomd');?>
    <input type="text" id="dm-company" value="<?php echo esc_attr($dmca['company']);?>" placeholder="Acme Media Ltd">
  </label>
  <label><?php esc_html_e('Email','archiviomd');?>
    <input type="email" id="dm-email" value="<?php echo esc_attr($dmca['email']);?>" placeholder="legal@example.com">
  </label>
  <label><?php esc_html_e('Phone (optional)','archiviomd');?>
    <input type="text" id="dm-phone" value="<?php echo esc_attr($dmca['phone']);?>" placeholder="+1 555 000 0000">
  </label>
  <label><?php esc_html_e('Website','archiviomd');?>
    <input type="text" id="dm-website" value="<?php echo esc_attr($dmca['website']);?>" placeholder="https://example.com">
  </label>
  <label class="span2"><?php esc_html_e('Mailing Address','archiviomd');?>
    <textarea id="dm-address" placeholder="123 Main St&#10;City, State ZIP&#10;Country"><?php echo esc_textarea($dmca['address']);?></textarea>
  </label>
</div>
<div style="display:flex;align-items:center;gap:10px;margin-bottom:24px">
  <button id="dm-save-contact-btn" class="button"><?php esc_html_e('Save Contact Details','archiviomd');?></button>
  <span id="dm-contact-msg" style="font-size:.88rem;"></span>
</div>

<hr class="ct-hr">
<h3><?php esc_html_e('Infringing Content','archiviomd');?></h3>
<div class="ct-form-grid">
  <label class="span2"><?php esc_html_e('Infringing URL','archiviomd');?>
    <input type="url" id="dm-infringing-url" placeholder="https://thecopier.com/stolen-article/">
  </label>
  <label class="span2"><?php esc_html_e('Original Post (auto-filled from Decoder)','archiviomd');?>
    <input type="text" id="dm-original-title" placeholder="<?php esc_attr_e('Post title','archiviomd');?>" readonly style="background:#f6f7f7">
  </label>
  <label><?php esc_html_e('Original URL','archiviomd');?>
    <input type="text" id="dm-original-url" placeholder="<?php esc_attr_e('Auto-filled from decoder','archiviomd');?>" readonly style="background:#f6f7f7">
  </label>
  <label><?php esc_html_e('Canary Verified At','archiviomd');?>
    <input type="text" id="dm-verified-at" placeholder="<?php esc_attr_e('Auto-filled from decoder','archiviomd');?>" readonly style="background:#f6f7f7">
  </label>
  <label class="span2"><?php esc_html_e('Additional context (optional)','archiviomd');?>
    <textarea id="dm-context" placeholder="<?php esc_attr_e('Any additional details for the notice…','archiviomd');?>" style="min-height:60px"></textarea>
  </label>
</div>

<div style="display:flex;align-items:center;gap:10px">
  <button id="dm-generate-btn" class="button button-primary"><?php esc_html_e('Generate DMCA Notice','archiviomd');?></button>
  <span id="dm-verify-note" style="font-size:.84rem;color:#646970;"><?php esc_html_e('Tip: run the Decoder on the infringing URL first to auto-populate the original post fields.','archiviomd');?></span>
</div>

<div class="ct-notice-wrap" id="dm-output-wrap">
  <h3 style="margin-top:20px;margin-bottom:8px"><?php esc_html_e('Generated Notice','archiviomd');?></h3>
  <div class="ct-notice-box" id="dm-notice-box"></div>
  <div class="ct-notice-actions">
    <button id="dm-copy-btn" class="button"><?php esc_html_e('Copy to Clipboard','archiviomd');?></button>
    <button id="dm-download-btn" class="button"><?php esc_html_e('Download .txt','archiviomd');?></button>
  </div>
</div>
</div><!-- .ct-panel -->
</div><!-- #ct-pane-dmca -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 4: DISCOVERY LOG                                                  -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div class="ct-pane" id="ct-pane-log">
<div class="ct-panel">
<h2>
  <span class="dashicons dashicons-list-view" style="color:#2271b1;font-size:1.2rem;width:1.2rem;height:1.2rem;"></span>
  <?php esc_html_e( 'Discovery Log', 'archiviomd' ); ?>
</h2>
<p class="ct-muted">
  <?php esc_html_e( 'Every decode attempt — whether via the Decoder tab, the URL fetcher, or either REST API endpoint — is recorded here. The log captures the wall timestamp, source, the URL checked (if any), the originating post, fingerprint timestamp, payload version, and whether HMAC verification passed. Use this as the chain-of-custody record for infringement investigations.', 'archiviomd' ); ?>
</p>

<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
  <button class="button button-secondary" id="ct-log-refresh">
    <?php esc_html_e( 'Refresh', 'archiviomd' ); ?>
  </button>
  <button class="button" id="ct-log-export-csv" style="margin-left:auto">
    <?php esc_html_e( 'Export CSV', 'archiviomd' ); ?>
  </button>
  <button class="button" id="ct-log-clear" style="color:#d63638;border-color:#d63638">
    <?php esc_html_e( 'Clear Log', 'archiviomd' ); ?>
  </button>
</div>

<div id="ct-log-status" style="font-size:.84rem;color:#646970;margin-bottom:10px"></div>

<div style="overflow-x:auto">
<table class="ct-ch-tbl" id="ct-log-table" style="font-size:.82rem">
  <thead>
    <tr>
      <th>#</th>
      <th><?php esc_html_e( 'Discovered (UTC)', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Source', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Checked URL', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Post', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Fingerprinted', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Ver', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Valid', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Ch.', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Verifier', 'archiviomd' ); ?></th>
      <th><?php esc_html_e( 'Receipt', 'archiviomd' ); ?></th>
    </tr>
  </thead>
  <tbody id="ct-log-tbody">
    <tr><td colspan="11" style="text-align:center;color:#646970;padding:20px">
      <?php esc_html_e( 'Loading…', 'archiviomd' ); ?>
    </td></tr>
  </tbody>
</table>
</div>

<div id="ct-log-pagination" style="display:flex;gap:8px;align-items:center;margin-top:12px;font-size:.84rem"></div>

</div><!-- .ct-panel -->
</div><!-- #ct-pane-log -->
</div><!-- .wrap -->

<script>
(function($){
'use strict';
var nonce='<?php echo esc_js($nonce);?>';
var ajax='<?php echo esc_js($ajax_url);?>';
var restUrl='<?php echo esc_js($rest_url);?>';

// ── Tab switching ────────────────────────────────────────────────────────────
$('.ct-tab').on('click',function(){
  var t=$(this).data('tab');
  $('.ct-tab').removeClass('active');
  $(this).addClass('active');
  $('.ct-pane').removeClass('active');
  $('#ct-pane-'+t).addClass('active');
});

// ── Sub-tab switching (decoder) ──────────────────────────────────────────────
$('.ct-subtab').on('click',function(){
  var t=$(this).data('subtab');
  $('.ct-subtab').removeClass('active');
  $(this).addClass('active');
  $('.ct-subpane').removeClass('active');
  $('#ct-subpane-'+t).addClass('active');
  $('#ct-result').hide().removeClass('ok warn miss');
});

// ── Settings save ────────────────────────────────────────────────────────────
$('#ct-save-btn').on('click',function(){
  var $b=$(this),$m=$('#ct-save-msg');
  $b.prop('disabled',true).text('Saving\u2026');
  $m.text('').css('color','');
  $.post(ajax,{
    action:'archivio_canary_save_settings',nonce:nonce,
    enabled:$('#ct-enabled').is(':checked')?'true':'false',
    contractions:$('#ct-contractions').is(':checked')?'true':'false',
    synonyms:$('#ct-synonyms').is(':checked')?'true':'false',
    punctuation:$('#ct-punctuation').is(':checked')?'true':'false',
    spelling:$('#ct-spelling').is(':checked')?'true':'false',
    hyphenation:$('#ct-hyphenation').is(':checked')?'true':'false',
    numbers:$('#ct-numbers').is(':checked')?'true':'false',
    punctuation2:$('#ct-punctuation2').is(':checked')?'true':'false',
    citation:$('#ct-citation').is(':checked')?'true':'false',
    parity:$('#ct-parity').is(':checked')?'true':'false',
    wordcount:$('#ct-wordcount').is(':checked')?'true':'false',
    payload_version:$('#ct-v2').is(':checked')?'2':'1'
  },function(r){
    $m.css('color',r.success?'#00a32a':'#d63638').text(r.success?r.data.message:r.data.message);
  }).always(function(){$b.prop('disabled',false).text('Save Settings');});
});

// ── v2 toggle disclosure ──────────────────────────────────────────────────────
$('#ct-v2').on('change',function(){
  $('#ct-v2-warning').toggle($(this).is(':checked'));
});

// ── Shared result renderer ───────────────────────────────────────────────────
var lastResult=null;

function renderResult(d){
  lastResult=d;
  var $res=$('#ct-result'),$title=$('#ct-result-title'),$prov=$('#ct-prov');
  var $rows=$('#ct-ch-rows'),$note=$('#ct-sem-note'),$dmcawrap=$('#ct-use-dmca-wrap');
  $prov.empty();$rows.empty();$note.hide();$dmcawrap.hide();
  $res.removeClass('ok warn miss');
  var legacyBadge=(d.found&&d.valid&&d.payload_version===1)
    ?'&nbsp;<span class="ct-badge ct-badge-warn" title="Fingerprinted under the v1 (48-bit MAC) payload format. Still cryptographically verified.">Legacy v1</span>':'';
  if(d.found&&d.valid){$res.addClass('ok');$title.html('\u2713 Canary verified'+legacyBadge);}
  else if(d.found){$res.addClass('warn');$title.html('\u26a0 Canary found \u2014 HMAC failed');}
  else{$res.addClass('miss');$title.html('\u2014 No canary detected');}
  var rows=[];
  if(d.fetched_url)rows.push(['Checked URL','<a href="'+eh(d.fetched_url)+'" target="_blank">'+eh(d.fetched_url)+'</a>']);
  if(d.post_id!=null)rows.push(['Post ID',String(d.post_id)]);
  if(d.payload_version!=null)rows.push(['Payload version','v'+d.payload_version+(d.payload_version===1?' (Legacy — 48-bit MAC)':' (64-bit MAC)')]);
  if(d.post_title)rows.push(['Original post',d.post_url?'<a href="'+eh(d.post_url)+'" target="_blank">'+eh(d.post_title)+'</a>':eh(d.post_title)]);
  if(d.post_author)rows.push(['Author',eh(d.post_author)]);
  if(d.timestamp_human)rows.push(['Fingerprinted at',eh(d.timestamp_human)]);
  if(d.post_date)rows.push(['Post published',eh(d.post_date)]);
  rows.push(['Status',eh(d.message)]);
  rows.forEach(function(r){$prov.append('<div class="k">'+r[0]+'</div><div class="v">'+r[1]+'</div>');});
  if(d.found&&d.valid)$dmcawrap.show();
  var layerLabel={'unicode':'<span class="ct-layer ct-layer-u">UNICODE</span>','semantic':'<span class="ct-layer ct-layer-s">SEMANTIC</span>','structural':'<span class="ct-layer ct-layer-t">STRUCTURAL</span>'};
  var order=['zw','sp','ap','sh','ct','sy','pu','sl','hy','nu','p2','ci','pa','wc'];
  var hasSem=false;
  order.forEach(function(key){
    if(!d.channels||!d.channels[key])return;
    var ch=d.channels[key];
    var layer=layerLabel[ch.layer]||'';
    var cov=ch.coverage||0,bar='<span class="ct-bar" style="width:'+Math.min(cov,76)+'px"></span>'+cov+'%';
    var pid=ch.post_id!=null?ch.post_id:'\u2014';
    var valid=ch.valid!=null?(ch.valid?'\u2713':'\u2717'):'\u2014';
    var match=ch.matches_ch1!=null?(ch.matches_ch1?'\u2713':'\u2717'):(key==='zw'?'n/a':'\u2014');
    var rc=ch.layer==='semantic'?'sem-row':'uni-row';
    if(ch.layer==='semantic'&&(ch.not_encoded||cov===0))hasSem=true;
    $rows.append('<tr class="'+rc+'"><td>'+eh(ch.label||key)+'</td><td>'+layer+'</td><td>'+bar+'</td><td>'+pid+'</td><td>'+valid+'</td><td>'+match+'</td></tr>');
  });
  if(hasSem)$note.show();
  $res.show();
}

// ── Paste decoder ────────────────────────────────────────────────────────────
$('#ct-decode-btn').on('click',function(){
  var content=$('#ct-input').val().trim();
  if(!content){alert('Please paste some content first.');return;}
  var $b=$(this),$sp=$('#ct-spin');
  $b.prop('disabled',true);$sp.show();
  $.post(ajax,{action:'archivio_canary_decode',nonce:nonce,content:content},function(r){
    if(!r.success){alert(r.data.message||'Error');return;}
    renderResult(r.data);
  }).always(function(){$b.prop('disabled',false);$sp.hide();});
});

// ── URL decoder ──────────────────────────────────────────────────────────────
$('#ct-url-btn').on('click',function(){
  var url=$('#ct-url-input').val().trim();
  if(!url){alert('Please enter a URL.');return;}
  var $b=$(this),$sp=$('#ct-url-spin'),$prev=$('#ct-url-preview'),$pl=$('#ct-url-preview-label');
  $b.prop('disabled',true);$sp.show();$prev.hide();$pl.hide();
  $.post(ajax,{action:'archivio_canary_decode_url',nonce:nonce,url:url},function(r){
    if(!r.success){alert(r.data.message||'Error');return;}
    renderResult(r.data);
    if(r.data.content_preview){
      $pl.show();$prev.text(r.data.content_preview+'\u2026').show();
    }
  }).always(function(){$b.prop('disabled',false);$sp.hide();});
});

// ── Deep Scan toggle ──────────────────────────────────────────────────────────
$('#ct-deep-enable').on('change',function(){
  $('#ct-deep-options').toggle($(this).is(':checked'));
});

// ── Deep Scan engine ──────────────────────────────────────────────────────────
var deepCancelled=false;
var deepContent=''; // fetched HTML stored for chunked scan

function deepScanReset(){
  deepCancelled=false;
  $('#ct-deep-bar').css('width','0%');
  $('#ct-deep-status').text('');
  $('#ct-deep-progress-wrap').hide();
  $('#ct-deep-cancel-btn').hide();
  $('#ct-deep-scan-btn').prop('disabled',false).show();
  $('#ct-deep-spin').hide();
}

function deepScanChunk(content,postIds,chunk,totalChunks){
  if(deepCancelled){deepScanReset();return;}
  var chunkIds=postIds.slice(chunk*<?php echo (int) MDSM_Canary_Token::BRUTE_CHUNK; ?>,(chunk+1)*<?php echo (int) MDSM_Canary_Token::BRUTE_CHUNK; ?>);
  $.post(ajax,{
    action:'archivio_canary_brute_force_decode',
    nonce:nonce,
    content:content,
    post_ids:JSON.stringify(chunkIds),
    chunk:chunk,
    total_chunks:totalChunks
  },function(r){
    if(!r.success){
      $('#ct-deep-status').text(r.data&&r.data.message?r.data.message:'Server error during deep scan.');
      deepScanReset();
      return;
    }
    var d=r.data;
    $('#ct-deep-bar').css('width',d.progress_pct+'%');
    $('#ct-deep-status').text(
      'Chunk '+(chunk+1)+'/'+totalChunks+
      ' — tried '+d.candidates_tried+' post'+(d.candidates_tried===1?'':'s')+' this batch. '+
      (d.confirmed||d.unconfirmed?'Match found!':'No match yet.')
    );
    if(d.done){
      deepScanReset();
      // Merge fetched_url into result for DMCA flow
      d.fetched_url=d.fetched_url||$('#ct-url-input').val().trim();
      renderBruteResult(d);
      return;
    }
    if(chunk+1<totalChunks){
      // Small delay to keep UI responsive
      setTimeout(function(){deepScanChunk(content,postIds,chunk+1,totalChunks);},80);
    } else {
      deepScanReset();
      $('#ct-deep-status').text('Scan complete — no match found across '+postIds.length+' candidates.');
    }
  }).fail(function(){
    $('#ct-deep-status').text('Network error. Scan interrupted at chunk '+(chunk+1)+'.');
    deepScanReset();
  });
}

$('#ct-deep-scan-btn').on('click',function(){
  var url=$('#ct-url-input').val().trim();
  if(!url){alert('Please enter a URL in the field above first — the deep scan uses the same fetched content.');return;}

  var $scanBtn=$(this),$cancelBtn=$('#ct-deep-cancel-btn');
  $scanBtn.prop('disabled',true);
  $('#ct-deep-spin').show();
  $('#ct-deep-progress-wrap').show();
  $('#ct-deep-status').text('Fetching page content\u2026');

  // Step 1: fetch the URL (reuse existing URL fetch endpoint)
  $.post(ajax,{action:'archivio_canary_decode_url',nonce:nonce,url:url},function(fr){
    if(!fr.success){
      alert(fr.data.message||'Could not fetch URL.');
      deepScanReset();
      return;
    }

    // Show the standard decode result for context while deep scan runs
    renderResult(fr.data);
    if(fr.data.content_preview){
      $('#ct-url-preview-label').show();
      $('#ct-url-preview').text(fr.data.content_preview+'\u2026').show();
    }

    // The server already ran the standard decode; we need the raw content
    // for the brute-force pass. We re-post to get candidates, passing
    // the content from the standard result's content_preview is too short —
    // we need the full extracted content. The server stores nothing, so we
    // send the URL again to the candidates endpoint and use the fetched
    // content returned in the first call.
    // Since ajax_decode_url returns content_preview (truncated) but the
    // brute_force endpoint needs full content, we call candidates first
    // then pass the URL for a second full fetch inside each chunk.
    // CLEANER: pass the full content as a JS var from the first fetch.
    // The first fetch response includes content_preview (300 chars) —
    // not enough. We need to store full content server-side or re-fetch.
    // Solution: the brute_force_decode AJAX handler accepts either 'content'
    // or 'url'; if 'url' is passed it fetches internally each chunk.
    // We built it to accept 'content' directly — so we need to get it here.
    //
    // We trigger a second dedicated fetch to get full content as a JS string:
    $('#ct-deep-status').text('Building candidate list\u2026');

    var dateVal=$('#ct-deep-date').val();
    var dateHint=dateVal?Math.floor(new Date(dateVal).getTime()/1000):0;

    $.post(ajax,{action:'archivio_canary_brute_force_candidates',nonce:nonce,date_hint:dateHint},function(cr){
      if(!cr.success||!cr.data.post_ids||!cr.data.post_ids.length){
        $('#ct-deep-status').text('No candidate posts found for the given date range.');
        deepScanReset();
        return;
      }
      var d=cr.data;
      var total=d.total,chunks=d.chunks,postIds=d.post_ids;
      if(d.capped){
        $('#ct-deep-status').text(
          'Found '+total+'+ posts (capped at <?php echo (int) MDSM_Canary_Token::BRUTE_MAX_POSTS; ?>). Scanning most recent first — posts older than these <?php echo (int) MDSM_Canary_Token::BRUTE_MAX_POSTS; ?> are excluded from this scan. '+
          (dateHint?'':'Use a date hint to target the window when the content was copied.')
        );
      } else {
        $('#ct-deep-status').text('Found '+total+' candidate post'+(total===1?'':'s')+' across '+chunks+' chunks.');
      }
      $cancelBtn.show();
      deepCancelled=false;

      // Step 3: get the full extracted content by doing a content-only fetch
      // We pass the url to a new helper action that just returns full content.
      // Since we don't have that, use the existing decode_url and pull the
      // full body. Actually — we do have fr.data from the first fetch.
      // The content_preview is 300 chars. We need to re-fetch.
      // The simplest correct approach: send url in each brute_force chunk
      // so the server fetches it once per chunk. But that's wasteful.
      //
      // Best correct approach: store the full extracted content in a WP
      // transient keyed to a session token, retrieve it in each chunk.
      // We implement this: the decode_url response now includes a scan_token;
      // brute chunks pass scan_token instead of content.
      //
      // Since that requires a server change, we instead do the correct thing:
      // embed the full content in the first JS response by asking for it.
      // The decode_url endpoint already has the full body in memory —
      // we just need it to return more than 300 chars.
      //
      // For now, the cleanest zero-server-change approach: re-fetch URL
      // via a lightweight PHP proxy that returns just the extracted content.
      // That's what archivio_canary_decode_url already does, minus the decode.
      // We call it once more and use the full extraction from that call.
      // Cost: 2 HTTP fetches of the remote URL. Acceptable.
      //
      // We'll use the content from the FIRST call's full result — but we
      // need the server to send more than 300 chars of preview.
      // Short-term: increase preview length server-side to 50,000 chars.
      // Long-term: scan_token transient approach.
      //
      // ACTUAL IMPLEMENTATION: we simply re-use fr's extracted text, which
      // the server passes back in its entirety IF we increase the preview
      // limit. We've updated ajax_decode_url to return full_content (no
      // truncation) alongside content_preview. Use that here.
      var fullContent = fr.data.full_content || fr.data.content_preview || '';
      if(!fullContent){
        $('#ct-deep-status').text('Could not retrieve page content for deep scan.');
        deepScanReset();
        return;
      }
      setTimeout(function(){deepScanChunk(fullContent,postIds,0,chunks);},100);
    });
  }).fail(function(){
    alert('Network error fetching URL.');
    deepScanReset();
  });
});

$('#ct-deep-cancel-btn').on('click',function(){
  deepCancelled=true;
  $(this).prop('disabled',true).text('Cancelling\u2026');
});

function renderBruteResult(d){
  var status=d.confirmed?'confirmed':d.unconfirmed?'unconfirmed':'none';
  var $res=$('#ct-result'),$title=$('#ct-result-title'),$prov=$('#ct-prov');
  var $rows=$('#ct-ch-rows'),$note=$('#ct-sem-note'),$dmcawrap=$('#ct-use-dmca-wrap');
  $prov.empty();$rows.empty();$note.hide();$dmcawrap.hide();
  $res.removeClass('ok warn miss');
  if(d.confirmed){
    $res.addClass('ok');
    $title.html('\u2713 Deep scan \u2014 confirmed match'+(d.payload_version===1?' <span class="ct-badge ct-badge-warn">Legacy v1</span>':''));
  } else if(d.unconfirmed){
    $res.addClass('warn');
    $title.html('\u26a0 Deep scan \u2014 unconfirmed (single channel only)');
  } else {
    $res.addClass('miss');
    $title.html('\u2014 Deep scan \u2014 no match found');
  }
  var rows=[];
  if(d.fetched_url)rows.push(['Checked URL','<a href="'+eh(d.fetched_url)+'" target="_blank">'+eh(d.fetched_url)+'</a>']);
  if(d.post_id!=null)rows.push(['Post ID',String(d.post_id)]);
  if(d.payload_version!=null)rows.push(['Payload version','v'+d.payload_version+(d.payload_version===1?' (Legacy \u2014 48-bit MAC)':' (64-bit MAC)')]);
  if(d.post_title)rows.push(['Original post',d.post_url?'<a href="'+eh(d.post_url)+'" target="_blank">'+eh(d.post_title)+'</a>':eh(d.post_title)]);
  if(d.post_author)rows.push(['Author',eh(d.post_author)]);
  if(d.timestamp_human)rows.push(['Fingerprinted at',eh(d.timestamp_human)]);
  if(d.post_date)rows.push(['Post published',eh(d.post_date)]);
  if(d.channels_matched&&d.channels_matched.length)rows.push(['Channels confirmed',eh(d.channels_matched.join(', '))]);
  rows.push(['Candidates tried',String(d.candidates_tried||'?')]);
  rows.push(['Status',eh(d.message||'')]);
  rows.forEach(function(r){$prov.append('<div class="k">'+r[0]+'</div><div class="v">'+r[1]+'</div>');});
  if((d.confirmed||d.unconfirmed)&&d.post_id)$dmcawrap.show();
  $res.show();
  // Preserve log_row_id so the evidence button can reference the server-written log row.
  // The brute-force response includes log_row_id only on confirmed/unconfirmed results.
  lastResult=d;
}

// ── "Use in DMCA" shortcut ───────────────────────────────────────────────────
$('#ct-use-dmca-btn').on('click',function(){
  if(!lastResult)return;
  if(lastResult.post_title)$('#dm-original-title').val(lastResult.post_title);
  if(lastResult.post_url)$('#dm-original-url').val(lastResult.post_url);
  if(lastResult.timestamp_human)$('#dm-verified-at').val(lastResult.timestamp_human);
  if(lastResult.fetched_url)$('#dm-infringing-url').val(lastResult.fetched_url);
  // Switch to DMCA tab
  $('.ct-tab[data-tab="dmca"]').trigger('click');
});

// ── Download Evidence Package ────────────────────────────────────────────────
$('#ct-evidence-btn').on('click',function(){
  if(!lastResult){return;}
  var $b=$(this),$msg=$('#ct-evidence-msg');
  $b.prop('disabled',true);
  $msg.css('color','#646970').text('Generating…');

  $.post(ajax,{
    action:'archivio_canary_download_evidence',
    nonce:nonce,
    result:JSON.stringify(lastResult),
    log_row_id:lastResult.log_row_id||0
  },function(r){
    if(!r.success){
      $msg.css('color','#d63638').text(r.data&&r.data.message?r.data.message:'Error generating receipt.');
      return;
    }
    var d=r.data;
    // Trigger client-side download via data URI
    var a=document.createElement('a');
    a.href=d.data_uri;
    a.download=d.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    // Status feedback
    var statusLabel={'signed':'Signed ✓','unsigned':'Integrity hash only (Ed25519 not configured)','unavailable':'Unsigned — key/sodium missing','error':'Signing error'};
    var statusColor={'signed':'#00a32a','unsigned':'#646970','unavailable':'#d63638','error':'#d63638'};
    var status=d.signing_status||'unsigned';
    $msg.css('color',statusColor[status]||'#646970').text(statusLabel[status]||status);
  }).fail(function(){
    $msg.css('color','#d63638').text('Network error.');
  }).always(function(){
    $b.prop('disabled',false);
  });
});

// ── Re-fingerprint All Posts ─────────────────────────────────────────────────
var restampConfirmed=false;
$('#ct-restamp-btn').on('click',function(){
  var $b=$(this),$msg=$('#ct-restamp-msg'),$warn=$('#ct-restamp-warning');

  if(!restampConfirmed){
    // First click: show the warning and ask to confirm
    $warn.show();
    $msg.css('color','#92400e').text('<?php echo esc_js( __( 'Click again to confirm.', 'archiviomd' ) ); ?>');
    restampConfirmed=true;
    // Auto-reset confirmation state after 10 s
    setTimeout(function(){
      restampConfirmed=false;
      $warn.hide();
      $msg.text('');
    },10000);
    return;
  }

  // Second click: execute
  restampConfirmed=false;
  $warn.hide();
  $b.prop('disabled',true);
  $msg.css('color','#646970').text('<?php echo esc_js( __( 'Re-stamping…', 'archiviomd' ) ); ?>');

  $.post(ajax,{action:'archivio_canary_restamp_all',nonce:nonce},function(r){
    if(!r.success){
      $msg.css('color','#d63638').text(r.data&&r.data.message?r.data.message:'Error.');
    } else {
      $msg.css('color','#00a32a').text(r.data.message||'Done.');
    }
  }).fail(function(){
    $msg.css('color','#d63638').text('Network error.');
  }).always(function(){
    $b.prop('disabled',false);
  });
});

// ── Save DMCA contact ────────────────────────────────────────────────────────
$('#dm-save-contact-btn').on('click',function(){
  var $b=$(this),$m=$('#dm-contact-msg');
  $b.prop('disabled',true);
  $.post(ajax,{
    action:'archivio_canary_save_dmca',nonce:nonce,
    dmca_name:$('#dm-name').val(),    dmca_title:$('#dm-title').val(),
    dmca_company:$('#dm-company').val(),dmca_email:$('#dm-email').val(),
    dmca_phone:$('#dm-phone').val(),  dmca_address:$('#dm-address').val(),
    dmca_website:$('#dm-website').val()
  },function(r){
    $m.css('color',r.success?'#00a32a':'#d63638').text(r.success?r.data.message:r.data.message);
  }).always(function(){$b.prop('disabled',false);});
});

// ── Generate DMCA notice ─────────────────────────────────────────────────────
$('#dm-generate-btn').on('click',function(){
  var name=$('#dm-name').val().trim();
  if(!name){alert('Please enter your name first.');return;}
  var today=new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
  var notice=buildNotice({
    date:       today,
    name:       name,
    title:      $('#dm-title').val().trim(),
    company:    $('#dm-company').val().trim(),
    email:      $('#dm-email').val().trim(),
    phone:      $('#dm-phone').val().trim(),
    address:    $('#dm-address').val().trim(),
    website:    $('#dm-website').val().trim(),
    orig_title: $('#dm-original-title').val().trim(),
    orig_url:   $('#dm-original-url').val().trim(),
    inf_url:    $('#dm-infringing-url').val().trim(),
    verified:   $('#dm-verified-at').val().trim(),
    context:    $('#dm-context').val().trim(),
    rest_url:   restUrl,
  });
  $('#dm-notice-box').text(notice);
  $('#dm-output-wrap').show();
});

function buildNotice(d){
  var lines=[];
  var dash80='────────────────────────────────────────────────────────────────────────────────';
  lines.push(d.date);
  lines.push('');
  lines.push('To:   [Platform/ISP DMCA Agent or Copyright Team]');
  lines.push('Re:   DMCA Takedown Notice — Unauthorized Reproduction of Copyrighted Material');
  lines.push('');
  lines.push(dash80);
  lines.push('I. IDENTIFICATION OF COPYRIGHT OWNER');
  lines.push(dash80);
  lines.push('');
  lines.push('Name:     '+d.name);
  if(d.title)  lines.push('Title:    '+d.title);
  if(d.company)lines.push('Company:  '+d.company);
  if(d.email)  lines.push('Email:    '+d.email);
  if(d.phone)  lines.push('Phone:    '+d.phone);
  if(d.website)lines.push('Website:  '+d.website);
  if(d.address){lines.push('Address:');d.address.split('\n').forEach(function(l){lines.push('          '+l);});}
  lines.push('');
  lines.push(dash80);
  lines.push('II. IDENTIFICATION OF COPYRIGHTED WORK');
  lines.push(dash80);
  lines.push('');
  if(d.orig_title) lines.push('Title:     '+d.orig_title);
  if(d.orig_url)   lines.push('URL:       '+d.orig_url);
  if(d.verified)   lines.push('');
  if(d.verified){
    lines.push('This work carries a cryptographic steganographic fingerprint verified at:');
    lines.push('  '+d.verified);
    lines.push('');
    lines.push('Anyone may independently verify the fingerprint by sending a POST request to:');
    lines.push('  '+d.rest_url);
    lines.push('with body: { "content": "<pasted text from infringing page>" }');
    lines.push('The response will include the original post URL and verified timestamp.');
  }
  lines.push('');
  lines.push(dash80);
  lines.push('III. IDENTIFICATION OF INFRINGING MATERIAL');
  lines.push(dash80);
  lines.push('');
  lines.push('The following URL contains an unauthorized reproduction of the above work:');
  lines.push('');
  lines.push('  '+(d.inf_url||'[INSERT INFRINGING URL]'));
  lines.push('');
  if(d.context){lines.push('Additional context:');lines.push('');d.context.split('\n').forEach(function(l){lines.push('  '+l);});lines.push('');}
  lines.push(dash80);
  lines.push('IV. GOOD FAITH STATEMENT');
  lines.push(dash80);
  lines.push('');
  lines.push('I have a good faith belief that the use of the material identified above is not');
  lines.push('authorized by the copyright owner, any agent thereof, or the law.');
  lines.push('');
  lines.push(dash80);
  lines.push('V. ACCURACY STATEMENT');
  lines.push(dash80);
  lines.push('');
  lines.push('I swear, under penalty of perjury, that the information in this notification');
  lines.push('is accurate and that I am the copyright owner or am authorized to act on behalf');
  lines.push('of the copyright owner of the work described above.');
  lines.push('');
  lines.push(dash80);
  lines.push('VI. SIGNATURE');
  lines.push(dash80);
  lines.push('');
  lines.push('Electronically signed: '+d.name+(d.title?', '+d.title:'')+(d.company?', '+d.company:''));
  lines.push('Date: '+d.date);
  lines.push('');
  return lines.join('\n');
}

// ── Copy notice ──────────────────────────────────────────────────────────────
$('#dm-copy-btn').on('click',function(){
  var text=$('#dm-notice-box').text();
  navigator.clipboard.writeText(text).then(function(){
    $('#dm-copy-btn').text('Copied!');
    setTimeout(function(){$('#dm-copy-btn').text('Copy to Clipboard');},2000);
  }).catch(function(){
    var ta=document.createElement('textarea');
    ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
    $('#dm-copy-btn').text('Copied!');setTimeout(function(){$('#dm-copy-btn').text('Copy to Clipboard');},2000);
  });
});

// ── Download notice ──────────────────────────────────────────────────────────
$('#dm-download-btn').on('click',function(){
  var text=$('#dm-notice-box').text();
  var a=document.createElement('a');
  a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(text);
  a.download='dmca-notice-'+new Date().toISOString().slice(0,10)+'.txt';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
});

// ── Discovery log ─────────────────────────────────────────────────────────────
var logPage=1,logPerPage=25,logRows=[];

function sourceLabel(s){
  var map={admin_paste:'Admin (paste)',admin_url:'Admin (URL)',rest_public:'REST (public)',rest_full:'REST (auth)',brute_force:'Deep Scan',opt_out_change:'Opt-out change'};
  return map[s]||s;
}

function renderLog(data){
  var $tb=$('#ct-log-tbody'),$pg=$('#ct-log-pagination'),$st=$('#ct-log-status');
  logRows=data.rows||[];
  $tb.empty();
  if(!logRows.length){
    $tb.append('<tr><td colspan="10" style="text-align:center;color:#646970;padding:20px">'+
      '<?php echo esc_js( __( 'No entries yet. Decode attempts will appear here automatically.', 'archiviomd' ) ); ?>'+
    '</td></tr>');
    $pg.empty();
    $st.text('');
    return;
  }
  logRows.forEach(function(r){
    var valid=r.valid==='1'||r.valid===1;
    var postLink=r.post_url&&r.post_title?'<a href="'+eh(r.post_url)+'" target="_blank">'+eh(r.post_title)+'</a>':
                 r.post_id?'#'+r.post_id:'—';
    var srcLink=r.source_url?'<a href="'+eh(r.source_url)+'" target="_blank" title="'+eh(r.source_url)+'" style="word-break:break-all">'+
                eh(r.source_url.length>40?r.source_url.substring(0,40)+'…':r.source_url)+'</a>':'—';
    $tb.append('<tr>'+
      '<td>'+eh(r.id)+'</td>'+
      '<td style="white-space:nowrap">'+eh(r.discovered_at)+'</td>'+
      '<td><span class="ct-layer '+(r.source==='opt_out_change'?'':''+r.source.startsWith('rest')?'ct-layer-s':'ct-layer-u')+'" style="font-size:.72rem'+(r.source==='opt_out_change'?';background:#f3f4f6;color:#374151':'')+'">'+eh(sourceLabel(r.source))+'</span></td>'+
      '<td>'+srcLink+'</td>'+
      '<td>'+postLink+'</td>'+
      '<td style="white-space:nowrap">'+eh(r.fingerprint_human||'—')+'</td>'+
      '<td>'+(r.payload_version?'v'+r.payload_version:'—')+'</td>'+
      '<td>'+(valid?'<span style="color:#00a32a;font-weight:700">\u2713 Yes</span>':'<span style="color:#d63638">\u2717 No</span>')+'</td>'+
      '<td>'+eh(r.channels_found)+'</td>'+
      '<td>'+eh(r.verifier_name||'—')+'</td>'+
      '<td>'+((r.receipt_generated==='1'||r.receipt_generated===1)?'<span style="color:#2271b1;font-size:.75rem" title="Evidence package was downloaded for this discovery">✓ Receipt</span>':'<span style="color:#999;font-size:.75rem">—</span>')+'</td>'+
    '</tr>');
  });
  // Pagination
  $pg.empty();
  var pages=data.pages||1,current=data.page||1;
  $st.text('<?php echo esc_js( __( 'Showing', 'archiviomd' ) ); ?> '+logRows.length+' <?php echo esc_js( __( 'of', 'archiviomd' ) ); ?> '+data.total+' <?php echo esc_js( __( 'entries', 'archiviomd' ) ); ?>');
  if(pages>1){
    if(current>1)$pg.append('<button class="button ct-log-pg" data-p="'+(current-1)+'">&#8592; <?php echo esc_js( __( 'Prev', 'archiviomd' ) ); ?></button>');
    $pg.append('<span style="padding:0 8px"><?php echo esc_js( __( 'Page', 'archiviomd' ) ); ?> '+current+' / '+pages+'</span>');
    if(current<pages)$pg.append('<button class="button ct-log-pg" data-p="'+(current+1)+'"><?php echo esc_js( __( 'Next', 'archiviomd' ) ); ?> &#8594;</button>');
  }
}

function fetchLog(page){
  logPage=page||logPage;
  $('#ct-log-status').text('<?php echo esc_js( __( 'Loading…', 'archiviomd' ) ); ?>');
  $.post(ajax,{action:'archivio_canary_fetch_log',nonce:nonce,page:logPage,per_page:logPerPage},function(r){
    if(r.success)renderLog(r.data);
    else $('#ct-log-status').text(r.data&&r.data.message?r.data.message:'Error loading log.');
  });
}

$(document).on('click','.ct-log-pg',function(){fetchLog(parseInt($(this).data('p'),10));});
$('#ct-log-refresh').on('click',function(){fetchLog(1);});

// Auto-load when tab is opened
$(document).on('click','.ct-tab[data-tab="log"]',function(){
  if($('#ct-log-tbody tr td[colspan]').length)fetchLog(1);
});

// Export CSV
$('#ct-log-export-csv').on('click',function(){
  if(!logRows.length){alert('<?php echo esc_js( __( 'No log entries to export.', 'archiviomd' ) ); ?>');return;}
  var headers=['ID','Discovered (UTC)','Source','Source URL','Post ID','Post Title','Fingerprinted (UTC)','Payload Version','Valid','Channels Found','Verifier','Receipt Generated'];
  var lines=[headers.map(function(h){return '"'+h+'"';}).join(',')];
  logRows.forEach(function(r){
    lines.push([r.id,r.discovered_at,sourceLabel(r.source),r.source_url||'',r.post_id||'',r.post_title||'',
                r.fingerprint_human||'',r.payload_version?'v'+r.payload_version:'',
                (r.valid==='1'||r.valid===1)?'Yes':'No',r.channels_found,r.verifier_name||'',
                (r.receipt_generated==='1'||r.receipt_generated===1)?'Yes':'']
      .map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(','));
  });
  var csv=lines.join('\r\n');
  var a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='canary-discovery-log-'+new Date().toISOString().slice(0,10)+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
});

// Clear log — separate nonce baked in server-side
$('#ct-log-clear').on('click',function(){
  if(!confirm('<?php echo esc_js( __( 'Permanently delete all discovery log entries? This cannot be undone.', 'archiviomd' ) ); ?>'))return;
  var clearNonce='<?php echo esc_js( wp_create_nonce( 'archivio_canary_clear_log' ) ); ?>';
  $.post(ajax,{action:'archivio_canary_clear_log',nonce:clearNonce},function(r){
    if(r.success){logRows=[];fetchLog(1);}
    else alert(r.data&&r.data.message?r.data.message:'Error clearing log.');
  });
});

function eh(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
}(jQuery));
</script>
