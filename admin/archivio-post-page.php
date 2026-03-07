<?php
/**
 * Archivio Post Admin Page
 *
 * @package ArchivioMD
 * @since   1.2.0
 * @updated 1.4.0 – HMAC Integrity Mode toggle + status panel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Current settings - default to false (unchecked)
$auto_generate    = get_option( 'archivio_post_auto_generate', false );
$show_badge       = get_option( 'archivio_post_show_badge', false );
$show_badge_posts = get_option( 'archivio_post_show_badge_posts', false );
$show_badge_pages = get_option( 'archivio_post_show_badge_pages', false );

// Ensure boolean values for proper checked() comparison
$auto_generate    = filter_var( $auto_generate, FILTER_VALIDATE_BOOLEAN );
$show_badge       = filter_var( $show_badge, FILTER_VALIDATE_BOOLEAN );
$show_badge_posts = filter_var( $show_badge_posts, FILTER_VALIDATE_BOOLEAN );
$show_badge_pages = filter_var( $show_badge_pages, FILTER_VALIDATE_BOOLEAN );

// Algorithm settings
$active_algorithm  = MDSM_Hash_Helper::get_active_algorithm();
$allowed_algos     = MDSM_Hash_Helper::allowed_algorithms();
$blake2b_available = MDSM_Hash_Helper::is_blake2b_available();
$sha3_available    = MDSM_Hash_Helper::is_sha3_available();

// HMAC settings
$hmac_status = MDSM_Hash_Helper::hmac_status();

// Active tab
$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'settings';
?>

<div class="wrap archivio-post-admin">
	<h1><?php esc_html_e( 'Archivio Post – Content Hash Verification', 'archiviomd' ); ?></h1>

	<p class="description">
		<?php esc_html_e( 'Generate and verify deterministic cryptographic hashes for your posts to ensure content integrity. Supports SHA-256, SHA-512, SHA3-256, SHA3-512, and BLAKE2b in Standard and HMAC modes.', 'archiviomd' ); ?>
	</p>

	<nav class="nav-tab-wrapper wp-clearfix" style="margin-top:20px;">
		<a href="?page=archivio-post&tab=settings"
		   class="nav-tab <?php echo $active_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
			<?php esc_html_e( 'Settings', 'archiviomd' ); ?>
		</a>
		<a href="?page=archivio-post&tab=extended"
		   class="nav-tab <?php echo $active_tab === 'extended' ? 'nav-tab-active' : ''; ?>">
			<?php esc_html_e( 'Extended', 'archiviomd' ); ?>
		</a>
		<a href="?page=archivio-post&tab=audit"
		   class="nav-tab <?php echo $active_tab === 'audit' ? 'nav-tab-active' : ''; ?>">
			<?php esc_html_e( 'Audit Log', 'archiviomd' ); ?>
		</a>
		<a href="?page=archivio-post&tab=help"
		   class="nav-tab <?php echo $active_tab === 'help' ? 'nav-tab-active' : ''; ?>">
			<?php esc_html_e( 'Help & Documentation', 'archiviomd' ); ?>
		</a>
	</nav>

	<div class="archivio-post-content">

	<?php if ( $active_tab === 'settings' ) : ?>
	<!-- ================================================================
	     SETTINGS TAB
	     ================================================================ -->
	<div class="archivio-post-tab-content">

		<!-- ── HMAC Integrity Mode ──────────────────────────────────── -->
		<h2><?php esc_html_e( 'HMAC Integrity Mode', 'archiviomd' ); ?></h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;margin-bottom:30px;">

			<?php
			// ── HMAC status banner ──────────────────────────────────
			if ( $hmac_status['mode_enabled'] ) {
				if ( $hmac_status['notice_level'] === 'error' ) {
					echo '<div style="padding:12px 15px;background:#fde8e8;border-left:4px solid #d73a49;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>' . esc_html__( 'Error:', 'archiviomd' ) . '</strong> ';
					echo wp_kses( $hmac_status['notice_message'], array( 'code' => array() ) );
					echo '</div>';
				} elseif ( $hmac_status['notice_level'] === 'warning' ) {
					echo '<div style="padding:12px 15px;background:#fff8e5;border-left:4px solid #dba617;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>' . esc_html__( 'Warning:', 'archiviomd' ) . '</strong> ';
					echo esc_html( $hmac_status['notice_message'] );
					echo '</div>';
				} else {
					echo '<div style="padding:12px 15px;background:#edfaed;border-left:4px solid #0a7537;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>✓ </strong>';
					echo esc_html( $hmac_status['notice_message'] );
					echo '</div>';
				}
			}
			?>

			<p style="margin-top:0;">
				<?php esc_html_e( 'When enabled, all new hashes are produced using <code>hash_hmac()</code> with a secret key defined in <code>wp-config.php</code>. Existing standard hashes remain fully verifiable.', 'archiviomd' ); ?>
			</p>

			<!-- Key status checklist -->
			<table style="border-collapse:collapse;margin-bottom:20px;">
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $hmac_status['key_defined'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">✓ <?php esc_html_e( 'Key constant defined', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#d73a49;font-weight:600;">✗ <?php esc_html_e( 'Key constant missing', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;">
						<?php echo sprintf( '<code>%s</code>', esc_html( MDSM_Hash_Helper::HMAC_KEY_CONSTANT ) ); ?>
						<?php esc_html_e( 'in wp-config.php', 'archiviomd' ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $hmac_status['key_strong'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">✓ <?php esc_html_e( 'Key length sufficient', 'archiviomd' ); ?></span>
						<?php elseif ( $hmac_status['key_defined'] ) : ?>
							<span style="color:#dba617;font-weight:600;">⚠ <?php esc_html_e( 'Key too short', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#646970;">— <?php esc_html_e( 'Key length unknown', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;">
						<?php echo sprintf( esc_html__(  'Minimum recommended: %d characters', 'archiviomd' ), MDSM_Hash_Helper::HMAC_KEY_MIN_LENGTH ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $hmac_status['hmac_available'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">✓ <?php esc_html_e( 'hash_hmac() available', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#d73a49;font-weight:600;">✗ <?php esc_html_e( 'hash_hmac() not available', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;"><?php esc_html_e( 'Built-in PHP function', 'archiviomd' ); ?></td>
				</tr>
			</table>

			<?php if ( ! $hmac_status['key_defined'] ) : ?>
			<!-- wp-config.php snippet -->
			<div style="background:#f5f5f5;padding:12px 15px;border-radius:4px;margin-bottom:20px;border:1px solid #ddd;">
				<p style="margin:0 0 8px;font-weight:600;"><?php esc_html_e( 'Add this to your wp-config.php (before "stop editing"):', 'archiviomd' ); ?></p>
				<pre style="margin:0;font-size:13px;overflow-x:auto;white-space:pre-wrap;">define( '<?php echo esc_html( MDSM_Hash_Helper::HMAC_KEY_CONSTANT ); ?>', 'replace-with-a-long-random-secret-key' );</pre>
				<p style="margin:8px 0 0;font-size:12px;color:#646970;">
					<?php esc_html_e( 'Generate a strong key: <code>openssl rand -base64 48</code>', 'archiviomd' ); ?>
				</p>
			</div>
			<?php endif; ?>

			<!-- Toggle form -->
			<form id="archivio-hmac-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $hmac_status['key_defined'] || ! $hmac_status['hmac_available'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="hmac-mode-toggle"
					       name="hmac_mode"
					       value="1"
					       <?php checked( $hmac_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $hmac_status['key_defined'] || ! $hmac_status['hmac_available'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable HMAC Integrity Mode', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Uses hash_hmac() instead of hash() for all new hashes.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>

				<div style="margin-top:15px;">
					<button type="submit" class="button button-primary" id="save-hmac-btn"
					        <?php disabled( ! $hmac_status['key_defined'] || ! $hmac_status['hmac_available'], true ); ?>>
						<?php esc_html_e( 'Save HMAC Setting', 'archiviomd' ); ?>
					</button>
					<span class="archivio-hmac-status" style="margin-left:10px;"></span>
				</div>
			</form>

			<div style="margin-top:15px;padding:10px 15px;background:#f0f6ff;border-left:3px solid #2271b1;border-radius:4px;font-size:12px;color:#1d2327;">
				<strong><?php esc_html_e( 'Key rotation note:', 'archiviomd' ); ?></strong>
				<?php esc_html_e( 'Changing ARCHIVIOMD_HMAC_KEY invalidates all existing HMAC hashes. After rotating the key, republish affected posts to regenerate their HMAC hashes.', 'archiviomd' ); ?>
			</div>
		</div>

		<!-- ── Ed25519 Document Signing ─────────────────────────────── -->
		<h2><?php esc_html_e( 'Ed25519 Document Signing', 'archiviomd' ); ?></h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;margin-bottom:30px;">

			<?php
			$ed25519_status = MDSM_Ed25519_Signing::status();

			// ── Status banner ────────────────────────────────────────────
			if ( $ed25519_status['mode_enabled'] ) {
				if ( $ed25519_status['notice_level'] === 'error' ) {
					echo '<div style="padding:12px 15px;background:#fde8e8;border-left:4px solid #d73a49;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>' . esc_html__( 'Error:', 'archiviomd' ) . '</strong> ';
					echo wp_kses( $ed25519_status['notice_message'], array( 'code' => array() ) );
					echo '</div>';
				} elseif ( $ed25519_status['notice_level'] === 'warning' ) {
					echo '<div style="padding:12px 15px;background:#fff8e5;border-left:4px solid #dba617;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>' . esc_html__( 'Warning:', 'archiviomd' ) . '</strong> ';
					echo esc_html( $ed25519_status['notice_message'] );
					echo '</div>';
				} else {
					echo '<div style="padding:12px 15px;background:#edfaed;border-left:4px solid #0a7537;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>✓ </strong>';
					echo esc_html( $ed25519_status['notice_message'] );
					echo '</div>';
				}
			}
			?>

			<p style="margin-top:0;">
				<?php esc_html_e( 'When enabled, posts, pages, and media are automatically signed on save using Ed25519 (PHP sodium). The private key lives in wp-config.php — never in the database. The public key is published at /.well-known/ed25519-pubkey.txt so anyone can verify content came from your site.', 'archiviomd' ); ?>
			</p>

			<!-- Key status checklist — same layout as HMAC -->
			<table style="border-collapse:collapse;margin-bottom:20px;">
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $ed25519_status['private_key_defined'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">✓ <?php esc_html_e( 'Private key defined', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#d73a49;font-weight:600;">✗ <?php esc_html_e( 'Private key missing', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;">
						<code><?php echo esc_html( MDSM_Ed25519_Signing::PRIVATE_KEY_CONSTANT ); ?></code>
						<?php esc_html_e( 'in wp-config.php', 'archiviomd' ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $ed25519_status['public_key_defined'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">✓ <?php esc_html_e( 'Public key defined', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#646970;">— <?php esc_html_e( 'Public key not set', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;">
						<code><?php echo esc_html( MDSM_Ed25519_Signing::PUBLIC_KEY_CONSTANT ); ?></code>
						<?php esc_html_e( 'in wp-config.php', 'archiviomd' ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $ed25519_status['sodium_available'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">✓ <?php esc_html_e( 'sodium_crypto_sign() available', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#d73a49;font-weight:600;">✗ <?php esc_html_e( 'sodium_crypto_sign() not available', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;"><?php esc_html_e( 'Built-in PHP 7.2+ (ext-sodium)', 'archiviomd' ); ?></td>
				</tr>
			</table>

			<?php if ( ! $ed25519_status['private_key_defined'] ) : ?>
			<!-- wp-config.php keypair snippet — shown only when keys are missing -->
			<div style="background:#f5f5f5;padding:12px 15px;border-radius:4px;margin-bottom:20px;border:1px solid #ddd;">
				<p style="margin:0 0 8px;font-weight:600;"><?php esc_html_e( 'Add this to your wp-config.php (before "stop editing"):', 'archiviomd' ); ?></p>
				<pre style="margin:0;font-size:12px;overflow-x:auto;white-space:pre-wrap;">// Ed25519 keypair — generate once with sodium_crypto_sign_keypair()
define( 'ARCHIVIOMD_ED25519_PRIVATE_KEY', 'paste-128-char-hex-private-key-here' );
define( 'ARCHIVIOMD_ED25519_PUBLIC_KEY',  'paste-64-char-hex-public-key-here' );</pre>
				<p style="margin:10px 0 4px;font-weight:600;font-size:12px;"><?php esc_html_e( 'Generate a keypair (PHP CLI):', 'archiviomd' ); ?></p>
				<pre style="margin:0;font-size:12px;overflow-x:auto;white-space:pre-wrap;">$kp   = sodium_crypto_sign_keypair();
echo bin2hex( sodium_crypto_sign_secretkey( $kp ) ) . "\n"; // → PRIVATE_KEY (128 hex)
echo bin2hex( sodium_crypto_sign_publickey( $kp ) ) . "\n"; // → PUBLIC_KEY  ( 64 hex)</pre>
				<p style="margin:8px 0 0;font-size:12px;color:#646970;">
					<?php esc_html_e( 'Or use the button below to generate in your browser — private key shown once and never transmitted.', 'archiviomd' ); ?>
				</p>
				<p style="margin:10px 0 0;">
					<button type="button" id="ed25519-keygen-btn" class="button">
						<?php esc_html_e( 'Generate Keypair in Browser', 'archiviomd' ); ?>
					</button>
				</p>
				<div id="ed25519-keygen-output" style="display:none;margin-top:12px;">
					<p style="margin:0 0 6px;font-size:12px;font-weight:600;color:#d73a49;">
						<?php esc_html_e( '⚠ Copy both values now — the private key will not be shown again.', 'archiviomd' ); ?>
					</p>
					<table style="border-collapse:collapse;width:100%;">
						<tr>
							<td style="padding:4px 8px 4px 0;font-size:12px;white-space:nowrap;font-weight:600;">
								<?php esc_html_e( 'PRIVATE_KEY', 'archiviomd' ); ?>
							</td>
							<td style="width:100%;">
								<input type="text" id="ed25519-privkey-out" readonly
								       style="width:100%;font-family:monospace;font-size:11px;"
								       onclick="this.select();">
							</td>
						</tr>
						<tr>
							<td style="padding:4px 8px 4px 0;font-size:12px;white-space:nowrap;font-weight:600;">
								<?php esc_html_e( 'PUBLIC_KEY', 'archiviomd' ); ?>
							</td>
							<td>
								<input type="text" id="ed25519-pubkey-out" readonly
								       style="width:100%;font-family:monospace;font-size:11px;"
								       onclick="this.select();">
							</td>
						</tr>
					</table>
				</div>
			</div>
			<?php endif; ?>

			<!-- Toggle form — identical structure to HMAC form -->
			<form id="archivio-ed25519-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $ed25519_status['private_key_defined'] || ! $ed25519_status['sodium_available'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="ed25519-mode-toggle"
					       name="ed25519_enabled"
					       value="1"
					       <?php checked( $ed25519_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $ed25519_status['private_key_defined'] || ! $ed25519_status['sodium_available'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable Ed25519 Document Signing', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Signs posts, pages, and media automatically on save using the private key in wp-config.php.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>

				<div style="margin-top:15px;">
					<button type="submit" class="button button-primary" id="save-ed25519-btn"
					        <?php disabled( ! $ed25519_status['private_key_defined'] || ! $ed25519_status['sodium_available'], true ); ?>>
						<?php esc_html_e( 'Save Ed25519 Setting', 'archiviomd' ); ?>
					</button>
					<span class="archivio-ed25519-status" style="margin-left:10px;"></span>
				</div>
			</form>

			<div style="margin-top:15px;padding:10px 15px;background:#f0f6ff;border-left:3px solid #2271b1;border-radius:4px;font-size:12px;color:#1d2327;">
				<strong><?php esc_html_e( 'Public key endpoint:', 'archiviomd' ); ?></strong>
				<?php
				printf(
					/* translators: %s: well-known URL */
					esc_html__( 'When the public key is defined, it is published at %s so anyone can verify signatures independently.', 'archiviomd' ),
					'<code>' . esc_html( home_url( '/.well-known/ed25519-pubkey.txt' ) ) . '</code>'
				);
				?>
				<?php if ( $ed25519_status['public_key_defined'] ) : ?>
				— <a href="<?php echo esc_url( home_url( '/.well-known/ed25519-pubkey.txt' ) ); ?>" target="_blank"><?php esc_html_e( 'View', 'archiviomd' ); ?></a>
				<?php endif; ?>
			</div>

			<!-- ── DSSE Envelope Mode ──────────────────────────────── -->
			<div style="margin-top:20px;padding:15px 20px;background:#f8f9fa;border:1px solid #ddd;border-radius:4px;">
				<h3 style="margin:0 0 6px;"><?php esc_html_e( 'DSSE Envelope Mode', 'archiviomd' ); ?></h3>
				<p style="margin:0 0 12px;font-size:13px;color:#1d2327;">
					<?php esc_html_e( 'When enabled, each signature is wrapped in a Dead Simple Signing Envelope (DSSE) and stored alongside the bare Ed25519 signature. The DSSE envelope includes a Pre-Authentication Encoding (PAE) that binds the payload type to the signature, preventing cross-protocol replay attacks. The bare signature is always kept for backward compatibility.', 'archiviomd' ); ?>
				</p>

				<?php if ( $ed25519_status['public_key_defined'] ) : ?>
				<p style="margin:0 0 12px;font-size:12px;color:#646970;">
					<?php
					printf(
						/* translators: %s: fingerprint hex */
						esc_html__( 'Public key fingerprint (SHA-256): %s', 'archiviomd' ),
						'<code>' . esc_html( MDSM_Ed25519_Signing::public_key_fingerprint() ) . '</code>'
					);
					?>
				</p>
				<?php endif; ?>

				<p style="margin:0 0 12px;font-size:12px;color:#646970;">
					<?php esc_html_e( 'DSSE envelope format:', 'archiviomd' ); ?>
					<code style="display:block;margin-top:4px;white-space:pre;overflow-x:auto;">{ "payload": base64(canonical_msg), "payloadType": "application/vnd.archiviomd.document", "signatures": [{ "keyid": sha256_hex(pubkey), "sig": base64(sig) }] }</code>
				</p>

				<form id="archivio-dsse-form">
					<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $ed25519_status['ready'] ) ? 'not-allowed' : 'pointer'; ?>;">
						<input type="checkbox"
						       id="dsse-mode-toggle"
						       name="dsse_enabled"
						       value="1"
						       <?php checked( $ed25519_status['dsse_enabled'], true ); ?>
						       <?php disabled( ! $ed25519_status['ready'], true ); ?>>
						<span>
							<strong><?php esc_html_e( 'Enable DSSE Envelope Mode', 'archiviomd' ); ?></strong>
							<span style="font-size:12px;color:#646970;display:block;">
								<?php esc_html_e( 'Requires Ed25519 signing to be active. Stores a DSSE envelope in _mdsm_ed25519_dsse post meta on each save.', 'archiviomd' ); ?>
							</span>
						</span>
					</label>

					<div style="margin-top:12px;">
						<button type="submit" class="button button-secondary" id="save-dsse-btn"
						        <?php disabled( ! $ed25519_status['ready'], true ); ?>>
							<?php esc_html_e( 'Save DSSE Setting', 'archiviomd' ); ?>
						</button>
						<span class="archivio-dsse-status" style="margin-left:10px;"></span>
					</div>
				</form>

				<?php if ( ! $ed25519_status['ready'] ) : ?>
				<p style="margin:10px 0 0;font-size:12px;color:#646970;">
					<?php esc_html_e( 'Enable and configure Ed25519 signing above before enabling DSSE mode.', 'archiviomd' ); ?>
				</p>
				<?php endif; ?>
			</div>
		</div>

		<!-- ── SLH-DSA Document Signing ────────────────────────────── -->
		<h2><?php esc_html_e( 'SLH-DSA Document Signing', 'archiviomd' ); ?></h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;margin-bottom:30px;">

			<?php
			$slhdsa_status = MDSM_SLHDSA_Signing::status();
			if ( $slhdsa_status['mode_enabled'] ) {
				if ( $slhdsa_status['notice_level'] === 'error' ) {
					echo '<div style="padding:12px 15px;background:#fde8e8;border-left:4px solid #d73a49;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>' . esc_html__( 'Error:', 'archiviomd' ) . '</strong> ';
					echo wp_kses( $slhdsa_status['notice_message'], array( 'code' => array() ) );
					echo '</div>';
				} elseif ( $slhdsa_status['notice_level'] === 'warning' ) {
					echo '<div style="padding:12px 15px;background:#fff8e5;border-left:4px solid #dba617;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>' . esc_html__( 'Warning:', 'archiviomd' ) . '</strong> ';
					echo esc_html( $slhdsa_status['notice_message'] );
					echo '</div>';
				} else {
					echo '<div style="padding:12px 15px;background:#edfaed;border-left:4px solid #0a7537;border-radius:4px;margin-bottom:15px;">';
					echo '<strong>\u2713 </strong>';
					echo esc_html( $slhdsa_status['notice_message'] );
					echo '</div>';
				}
			}
			?>

			<p style="margin-top:0;">
				<?php esc_html_e( 'Quantum-resistant document signing using SLH-DSA (SPHINCS+, NIST FIPS 205). Pure PHP — no extensions, no FFI, no Composer. Works on any shared host. Private key lives in wp-config.php. Public key published at /.well-known/slhdsa-pubkey.txt.', 'archiviomd' ); ?>
			</p>

			<p style="margin:0 0 15px;font-size:12px;color:#646970;">
				<?php
				printf(
					/* translators: 1: param set name, 2: sig byte count */
					esc_html__( 'Active parameter set: %1$s — signatures are %2$s bytes. Security: NIST Category 1, quantum-resistant. Backend: pure-PHP hash() only.', 'archiviomd' ),
					'<strong>' . esc_html( $slhdsa_status['param'] ) . '</strong>',
					'<strong>' . esc_html( number_format( $slhdsa_status['sig_bytes'] ) ) . '</strong>'
				);
				?>
			</p>

			<!-- Key status checklist -->
			<table style="border-collapse:collapse;margin-bottom:20px;">
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $slhdsa_status['private_key_defined'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">&#10003; <?php esc_html_e( 'Private key defined', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#d73a49;font-weight:600;">&#10007; <?php esc_html_e( 'Private key missing', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;"><code><?php echo esc_html( MDSM_SLHDSA_Signing::PRIVATE_KEY_CONSTANT ); ?></code> <?php esc_html_e( 'in wp-config.php', 'archiviomd' ); ?></td>
				</tr>
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<?php if ( $slhdsa_status['public_key_defined'] ) : ?>
							<span style="color:#0a7537;font-weight:600;">&#10003; <?php esc_html_e( 'Public key defined', 'archiviomd' ); ?></span>
						<?php else : ?>
							<span style="color:#646970;">&#8212; <?php esc_html_e( 'Public key not set', 'archiviomd' ); ?></span>
						<?php endif; ?>
					</td>
					<td style="color:#646970;font-size:12px;"><code><?php echo esc_html( MDSM_SLHDSA_Signing::PUBLIC_KEY_CONSTANT ); ?></code> <?php esc_html_e( 'in wp-config.php', 'archiviomd' ); ?></td>
				</tr>
				<tr>
					<td style="padding:4px 10px 4px 0;">
						<span style="color:#0a7537;font-weight:600;">&#10003; <?php esc_html_e( 'hash() available', 'archiviomd' ); ?></span>
					</td>
					<td style="color:#646970;font-size:12px;"><?php esc_html_e( 'Always — pure PHP, no extensions required', 'archiviomd' ); ?></td>
				</tr>
			</table>

			<!-- Parameter set selector -->
			<div style="margin-bottom:20px;">
				<label style="font-weight:600;display:block;margin-bottom:6px;"><?php esc_html_e( 'Parameter Set', 'archiviomd' ); ?></label>
				<select id="slhdsa-param-select" style="max-width:280px;">
					<?php foreach ( array_keys( MDSM_SLHDSA_Core::parameter_sets() ) as $pset ) :
						$pinfo = MDSM_SLHDSA_Core::parameter_sets()[ $pset ]; ?>
					<option value="<?php echo esc_attr( $pset ); ?>" <?php selected( $slhdsa_status['param'], $pset ); ?>>
						<?php echo esc_html( $pset ); ?> &mdash; <?php echo esc_html( number_format( $pinfo['sig_bytes'] ) ); ?> byte sig
					</option>
					<?php endforeach; ?>
				</select>
				<p style="margin:6px 0 0;font-size:12px;color:#646970;"><?php esc_html_e( 'SHA2-128s recommended: smallest signatures, NIST Category 1. Changing this requires new keys.', 'archiviomd' ); ?></p>
			</div>

			<?php if ( ! $slhdsa_status['private_key_defined'] ) : ?>
			<!-- Keypair generation block -->
			<div style="background:#f5f5f5;padding:12px 15px;border-radius:4px;margin-bottom:20px;border:1px solid #ddd;">
				<p style="margin:0 0 8px;font-weight:600;"><?php esc_html_e( 'Add this to your wp-config.php:', 'archiviomd' ); ?></p>
				<pre style="margin:0;font-size:12px;overflow-x:auto;white-space:pre-wrap;">define( 'ARCHIVIOMD_SLHDSA_PRIVATE_KEY', 'paste-private-key-hex-here' );
define( 'ARCHIVIOMD_SLHDSA_PUBLIC_KEY',  'paste-public-key-hex-here' );
define( 'ARCHIVIOMD_SLHDSA_PARAM',       '<?php echo esc_html( $slhdsa_status['param'] ); ?>' );</pre>
				<p style="margin:10px 0 0;">
					<button type="button" id="slhdsa-keygen-btn" class="button"><?php esc_html_e( 'Generate Keypair', 'archiviomd' ); ?></button>
					<span id="slhdsa-keygen-spinner" style="display:none;margin-left:8px;">
						<span class="spinner is-active" style="float:none;"></span>
						<span style="font-size:12px;color:#646970;vertical-align:middle;"><?php esc_html_e( 'Generating\xe2\x80\xa6 this may take a few seconds on slower servers.', 'archiviomd' ); ?></span>
					</span>
				</p>
				<div id="slhdsa-keygen-output" style="display:none;margin-top:12px;">
					<p style="margin:0 0 6px;font-size:12px;font-weight:600;color:#d73a49;">
						<?php esc_html_e( 'Copy all values now — the private key will not be shown again.', 'archiviomd' ); ?>
					</p>
					<table style="border-collapse:collapse;width:100%;">
						<tr>
							<td style="padding:4px 8px 4px 0;font-size:12px;white-space:nowrap;font-weight:600;vertical-align:top;"><?php esc_html_e( 'PRIVATE_KEY', 'archiviomd' ); ?></td>
							<td style="width:100%;"><input type="text" id="slhdsa-privkey-out" readonly style="width:100%;font-family:monospace;font-size:11px;" onclick="this.select();"></td>
						</tr>
						<tr>
							<td style="padding:4px 8px 4px 0;font-size:12px;white-space:nowrap;font-weight:600;vertical-align:top;"><?php esc_html_e( 'PUBLIC_KEY', 'archiviomd' ); ?></td>
							<td><input type="text" id="slhdsa-pubkey-out" readonly style="width:100%;font-family:monospace;font-size:11px;" onclick="this.select();"></td>
						</tr>
						<tr>
							<td style="padding:4px 8px 4px 0;font-size:12px;white-space:nowrap;font-weight:600;vertical-align:top;"><?php esc_html_e( 'wp-config.php', 'archiviomd' ); ?></td>
							<td><textarea id="slhdsa-wpconfig-out" readonly rows="4" style="width:100%;font-family:monospace;font-size:11px;" onclick="this.select();"></textarea></td>
						</tr>
					</table>
				</div>
			</div>
			<?php endif; ?>

			<!-- Enable toggle -->
			<form id="archivio-slhdsa-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo $slhdsa_status['private_key_defined'] ? 'pointer' : 'not-allowed'; ?>;">
					<input type="checkbox" id="slhdsa-mode-toggle" name="slhdsa_enabled" value="1"
					       <?php checked( $slhdsa_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $slhdsa_status['private_key_defined'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable SLH-DSA Document Signing', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;"><?php esc_html_e( 'Signs posts, pages, and media automatically on save.', 'archiviomd' ); ?></span>
					</span>
				</label>
				<div style="margin-top:15px;">
					<button type="submit" class="button button-primary" id="save-slhdsa-btn"
					        <?php disabled( ! $slhdsa_status['private_key_defined'], true ); ?>>
						<?php esc_html_e( 'Save SLH-DSA Setting', 'archiviomd' ); ?>
					</button>
					<span class="archivio-slhdsa-status" style="margin-left:10px;"></span>
				</div>
			</form>

			<div style="margin-top:15px;padding:10px 15px;background:#f0f6ff;border-left:3px solid #2271b1;border-radius:4px;font-size:12px;color:#1d2327;">
				<strong><?php esc_html_e( 'Public key endpoint:', 'archiviomd' ); ?></strong>
				<?php printf( esc_html__( 'Published at %s for independent verification.', 'archiviomd' ), '<code>' . esc_html( home_url( '/.well-known/slhdsa-pubkey.txt' ) ) . '</code>' ); ?>
				<?php if ( $slhdsa_status['public_key_defined'] ) : ?>
				&mdash; <a href="<?php echo esc_url( home_url( '/.well-known/slhdsa-pubkey.txt' ) ); ?>" target="_blank"><?php esc_html_e( 'View', 'archiviomd' ); ?></a>
				<?php endif; ?>
			</div>

			<!-- DSSE sub-card -->
			<div style="margin-top:20px;padding:15px 20px;background:#f8f9fa;border:1px solid #ddd;border-radius:4px;">
				<h3 style="margin:0 0 6px;"><?php esc_html_e( 'DSSE Envelope Mode', 'archiviomd' ); ?></h3>
				<p style="margin:0 0 12px;font-size:13px;color:#1d2327;">
					<?php esc_html_e( 'Wraps the SLH-DSA signature in a DSSE envelope. When Ed25519 DSSE is also active, the shared envelope is extended with a second signatures[] entry for SLH-DSA. Old verifiers ignore the new entry and continue to verify Ed25519 unchanged.', 'archiviomd' ); ?>
				</p>
				<?php if ( $slhdsa_status['public_key_defined'] ) : ?>
				<p style="margin:0 0 12px;font-size:12px;color:#646970;">
					<?php printf( esc_html__( 'Public key fingerprint (SHA-256): %s', 'archiviomd' ), '<code>' . esc_html( MDSM_SLHDSA_Signing::public_key_fingerprint() ) . '</code>' ); ?>
				</p>
				<?php endif; ?>
				<p style="margin:0 0 12px;font-size:12px;color:#646970;">
					<?php esc_html_e( 'Hybrid envelope adds:', 'archiviomd' ); ?>
					<code style="display:block;margin-top:4px;white-space:pre;overflow-x:auto;">{ "alg": "<?php echo esc_html( strtolower( $slhdsa_status['param'] ) ); ?>", "keyid": "...", "sig": "..." }</code>
				</p>
				<form id="archivio-slhdsa-dsse-form">
					<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo $slhdsa_status['ready'] ? 'pointer' : 'not-allowed'; ?>;">
						<input type="checkbox" id="slhdsa-dsse-mode-toggle" name="slhdsa_dsse_enabled" value="1"
						       <?php checked( $slhdsa_status['dsse_enabled'], true ); ?>
						       <?php disabled( ! $slhdsa_status['ready'], true ); ?>>
						<span>
							<strong><?php esc_html_e( 'Enable SLH-DSA DSSE Envelope Mode', 'archiviomd' ); ?></strong>
							<span style="font-size:12px;color:#646970;display:block;"><?php esc_html_e( 'Stores a DSSE envelope in _mdsm_slhdsa_dsse. Extends _mdsm_ed25519_dsse when Ed25519 DSSE is also active.', 'archiviomd' ); ?></span>
						</span>
					</label>
					<div style="margin-top:12px;">
						<button type="submit" class="button button-secondary" id="save-slhdsa-dsse-btn"
						        <?php disabled( ! $slhdsa_status['ready'], true ); ?>>
							<?php esc_html_e( 'Save DSSE Setting', 'archiviomd' ); ?>
						</button>
						<span class="archivio-slhdsa-dsse-status" style="margin-left:10px;"></span>
					</div>
				</form>
				<?php if ( ! $slhdsa_status['ready'] ) : ?>
				<p style="margin:10px 0 0;font-size:12px;color:#646970;"><?php esc_html_e( 'Enable SLH-DSA signing above before enabling DSSE mode.', 'archiviomd' ); ?></p>
				<?php endif; ?>
			</div>
		</div>

			<!-- ── ECDSA Enterprise / Compliance Mode ──────────────────── -->
		<?php
		$ecdsa_status = MDSM_ECDSA_Signing::status();
		?>
		<h2 style="display:flex;align-items:center;gap:10px;">
			<?php esc_html_e( 'ECDSA P-256 Signing', 'archiviomd' ); ?>
			<span style="display:inline-block;padding:2px 10px;border-radius:12px;background:#7c3aed;color:#fff;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;">
				<?php esc_html_e( 'Enterprise / Compliance Mode', 'archiviomd' ); ?>
			</span>
		</h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-left:4px solid #7c3aed;border-radius:4px;margin-bottom:30px;">

			<!-- Enterprise warning banner -->
			<div style="background:#faf5ff;border:1px solid #c4b5fd;border-radius:4px;padding:14px 18px;margin-bottom:18px;">
				<p style="margin:0 0 8px;font-weight:600;color:#5b21b6;">
					⚠ <?php esc_html_e( 'Not recommended for general use', 'archiviomd' ); ?>
				</p>
				<p style="margin:0;font-size:13px;color:#6d28d9;line-height:1.6;">
					<?php esc_html_e( 'Use this mode only when an external compliance requirement (eIDAS, SOC 2, HIPAA audit, government PKI) explicitly mandates X.509 certificate-backed ECDSA signatures. For all other sites, Ed25519 is simpler, faster, and equally secure.', 'archiviomd' ); ?>
				</p>
				<p style="margin:8px 0 0;font-size:12px;color:#7c3aed;">
					<strong><?php esc_html_e( 'Security note:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'ECDSA is catastrophically broken by nonce reuse or weak RNG. This plugin never touches nonce generation — 100% of signing math is delegated to OpenSSL (libssl), which sources nonces from the OS CSPRNG. Never use a custom or pure-PHP ECDSA implementation.', 'archiviomd' ); ?>
				</p>
			</div>

			<?php if ( $ecdsa_status['mode_enabled'] ) : ?>
				<?php if ( $ecdsa_status['notice_level'] === 'error' ) : ?>
					<div class="notice notice-error inline" style="margin:0 0 16px;"><p><?php echo esc_html( $ecdsa_status['notice_message'] ); ?></p></div>
				<?php elseif ( $ecdsa_status['notice_level'] === 'warning' ) : ?>
					<div class="notice notice-warning inline" style="margin:0 0 16px;"><p><?php echo esc_html( $ecdsa_status['notice_message'] ); ?></p></div>
				<?php else : ?>
					<div class="notice notice-success inline" style="margin:0 0 16px;"><p><?php echo esc_html( $ecdsa_status['notice_message'] ); ?></p></div>
				<?php endif; ?>
			<?php endif; ?>

			<!-- Prerequisite checks -->
			<table style="border-collapse:collapse;margin-bottom:18px;font-size:13px;">
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'PHP ext-openssl', 'archiviomd' ); ?></td>
					<td><?php if ( $ecdsa_status['openssl_available'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Available', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#dc3232;">&#10007; <?php esc_html_e( 'Not available — required for ECDSA signing', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Private key', 'archiviomd' ); ?></td>
					<td><?php if ( defined( MDSM_ECDSA_Signing::CONSTANT_PRIVATE_KEY ) ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Set via wp-config.php constant', 'archiviomd' ); ?></span>
					<?php elseif ( $ecdsa_status['private_key_configured'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'PEM file configured', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#996800;">&#9888; <?php esc_html_e( 'Not configured', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Certificate', 'archiviomd' ); ?></td>
					<td><?php if ( defined( MDSM_ECDSA_Signing::CONSTANT_CERTIFICATE ) ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Set via wp-config.php constant', 'archiviomd' ); ?></span>
					<?php elseif ( $ecdsa_status['certificate_configured'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'PEM file configured', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#996800;">&#9888; <?php esc_html_e( 'Not configured', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<?php if ( $ecdsa_status['certificate_configured'] ) : ?>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Certificate valid', 'archiviomd' ); ?></td>
					<td><?php if ( $ecdsa_status['certificate_valid'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'P-256 / secp256r1, chain OK', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#dc3232;">&#10007; <?php esc_html_e( 'Validation failed — see notice above', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<?php endif; ?>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'CA bundle', 'archiviomd' ); ?></td>
					<td><?php if ( $ecdsa_status['ca_bundle_configured'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Configured — chain will be validated on every signing operation', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#646970;">&mdash; <?php esc_html_e( 'Optional — omit only if using a self-signed certificate for testing', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
			</table>

			<!-- Certificate info card -->
			<?php if ( $ecdsa_status['certificate_valid'] && ! empty( $ecdsa_status['cert_info'] ) ) :
				$ci = $ecdsa_status['cert_info'];
				$subject_cn = $ci['subject']['CN'] ?? ( $ci['subject']['O'] ?? '' );
				$issuer_cn  = $ci['issuer']['CN']  ?? ( $ci['issuer']['O']  ?? '' );
			?>
			<div style="background:#f6f7f7;border:1px solid #ddd;border-radius:4px;padding:14px 18px;margin-bottom:18px;font-size:13px;">
				<strong style="display:block;margin-bottom:8px;color:#1d2327;"><?php esc_html_e( 'Certificate details', 'archiviomd' ); ?></strong>
				<table style="border-collapse:collapse;width:100%;">
					<tr><td style="padding:2px 16px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Subject', 'archiviomd' ); ?></td><td><?php echo esc_html( $subject_cn ); ?></td></tr>
					<tr><td style="padding:2px 16px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Issuer', 'archiviomd' ); ?></td><td><?php echo esc_html( $issuer_cn ); ?></td></tr>
					<tr><td style="padding:2px 16px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Curve', 'archiviomd' ); ?></td><td><?php echo esc_html( $ci['curve'] ); ?></td></tr>
					<tr><td style="padding:2px 16px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Valid from', 'archiviomd' ); ?></td><td><?php echo esc_html( $ci['not_before'] ); ?></td></tr>
					<tr><td style="padding:2px 16px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Expires', 'archiviomd' ); ?></td>
						<td><?php echo esc_html( $ci['not_after'] ); ?>
							<?php if ( $ci['expired'] ) : ?>
								<strong style="color:#dc3232;margin-left:8px;"><?php esc_html_e( 'EXPIRED', 'archiviomd' ); ?></strong>
							<?php elseif ( isset( $ci['days_left'] ) && $ci['days_left'] <= 30 ) : ?>
								<strong style="color:#996800;margin-left:8px;"><?php echo esc_html( sprintf(
									/* translators: %d: days */
									_n( '%d day left', '%d days left', $ci['days_left'], 'archiviomd' ),
									$ci['days_left']
								) ); ?></strong>
							<?php endif; ?>
						</td>
					</tr>
					<tr><td style="padding:2px 16px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'SHA-256 fingerprint', 'archiviomd' ); ?></td>
						<td><code style="font-size:11px;"><?php echo esc_html( $ci['fingerprint'] ); ?></code></td>
					</tr>
				</table>
				<p style="margin:10px 0 0;font-size:12px;">
					<?php esc_html_e( 'Certificate is published at', 'archiviomd' ); ?>
					<a href="<?php echo esc_url( home_url( '/.well-known/ecdsa-cert.pem' ) ); ?>" target="_blank"><code><?php echo esc_html( home_url( '/.well-known/ecdsa-cert.pem' ) ); ?></code></a>
				</p>
			</div>
			<?php endif; ?>

			<!-- PEM upload section (shown only when constants are not set) -->
			<?php if ( ! defined( MDSM_ECDSA_Signing::CONSTANT_PRIVATE_KEY ) || ! defined( MDSM_ECDSA_Signing::CONSTANT_CERTIFICATE ) ) : ?>
			<div style="border:1px solid #e2e4e7;border-radius:4px;padding:16px;margin-bottom:18px;">
				<strong style="display:block;margin-bottom:12px;font-size:13px;"><?php esc_html_e( 'Upload PEM files', 'archiviomd' ); ?></strong>
				<p style="font-size:12px;color:#646970;margin:0 0 12px;">
					<?php esc_html_e( 'Files are stored outside your webroot in a protected directory. The private key is never stored in the database or echoed back.', 'archiviomd' ); ?><br>
					<?php esc_html_e( 'Alternatively, set constants directly in wp-config.php — constants take priority over uploaded files.', 'archiviomd' ); ?>
				</p>
				<p style="font-size:12px;color:#646970;margin:0 0 16px;font-family:monospace;">
					define( '<?php echo esc_html( MDSM_ECDSA_Signing::CONSTANT_PRIVATE_KEY ); ?>', '-----BEGIN EC PRIVATE KEY-----\n...' );<br>
					define( '<?php echo esc_html( MDSM_ECDSA_Signing::CONSTANT_CERTIFICATE ); ?>', '-----BEGIN CERTIFICATE-----\n...' );<br>
					define( '<?php echo esc_html( MDSM_ECDSA_Signing::CONSTANT_CA_BUNDLE );   ?>', '-----BEGIN CERTIFICATE-----\n...' ); <em style="color:#999;">// optional chain</em>
				</p>

				<table style="border-collapse:collapse;width:100%;font-size:13px;">
					<!-- Private key row -->
					<tr>
						<td style="padding:6px 12px 6px 0;white-space:nowrap;color:#646970;vertical-align:middle;">
							<?php esc_html_e( 'EC Private Key (.pem)', 'archiviomd' ); ?>
							<span style="display:inline-block;background:#dc3232;color:#fff;border-radius:3px;padding:0 5px;font-size:10px;margin-left:4px;">PRIVATE</span>
						</td>
						<td style="vertical-align:middle;">
							<?php if ( $ecdsa_status['private_key_configured'] && ! defined( MDSM_ECDSA_Signing::CONSTANT_PRIVATE_KEY ) ) : ?>
								<span style="color:#0a7537;margin-right:8px;">&#10003; <?php esc_html_e( 'Uploaded', 'archiviomd' ); ?></span>
								<button type="button" class="button button-small ecdsa-clear-btn" data-action="archivio_ecdsa_clear_key"><?php esc_html_e( 'Remove', 'archiviomd' ); ?></button>
							<?php else : ?>
								<input type="file" id="ecdsa-key-upload" accept=".pem" style="font-size:13px;">
								<button type="button" class="button button-small" id="ecdsa-key-upload-btn"><?php esc_html_e( 'Upload', 'archiviomd' ); ?></button>
								<span class="ecdsa-upload-status" id="ecdsa-key-status" style="margin-left:8px;font-size:12px;"></span>
							<?php endif; ?>
						</td>
					</tr>
					<!-- Certificate row -->
					<tr>
						<td style="padding:6px 12px 6px 0;white-space:nowrap;color:#646970;vertical-align:middle;"><?php esc_html_e( 'X.509 Certificate (.pem)', 'archiviomd' ); ?></td>
						<td style="vertical-align:middle;">
							<?php if ( $ecdsa_status['certificate_configured'] && ! defined( MDSM_ECDSA_Signing::CONSTANT_CERTIFICATE ) ) : ?>
								<span style="color:#0a7537;margin-right:8px;">&#10003; <?php esc_html_e( 'Uploaded', 'archiviomd' ); ?></span>
								<button type="button" class="button button-small ecdsa-clear-btn" data-action="archivio_ecdsa_clear_cert"><?php esc_html_e( 'Remove', 'archiviomd' ); ?></button>
							<?php else : ?>
								<input type="file" id="ecdsa-cert-upload" accept=".pem" style="font-size:13px;">
								<button type="button" class="button button-small" id="ecdsa-cert-upload-btn"><?php esc_html_e( 'Upload', 'archiviomd' ); ?></button>
								<span class="ecdsa-upload-status" id="ecdsa-cert-status" style="margin-left:8px;font-size:12px;"></span>
							<?php endif; ?>
						</td>
					</tr>
					<!-- CA bundle row -->
					<tr>
						<td style="padding:6px 12px 6px 0;white-space:nowrap;color:#646970;vertical-align:middle;"><?php esc_html_e( 'CA Bundle — optional (.pem)', 'archiviomd' ); ?></td>
						<td style="vertical-align:middle;">
							<?php if ( $ecdsa_status['ca_bundle_configured'] && ! defined( MDSM_ECDSA_Signing::CONSTANT_CA_BUNDLE ) ) : ?>
								<span style="color:#0a7537;margin-right:8px;">&#10003; <?php esc_html_e( 'Uploaded', 'archiviomd' ); ?></span>
								<button type="button" class="button button-small ecdsa-clear-btn" data-action="archivio_ecdsa_clear_ca"><?php esc_html_e( 'Remove', 'archiviomd' ); ?></button>
							<?php else : ?>
								<input type="file" id="ecdsa-ca-upload" accept=".pem" style="font-size:13px;">
								<button type="button" class="button button-small" id="ecdsa-ca-upload-btn"><?php esc_html_e( 'Upload', 'archiviomd' ); ?></button>
								<span class="ecdsa-upload-status" id="ecdsa-ca-status" style="margin-left:8px;font-size:12px;"></span>
							<?php endif; ?>
						</td>
					</tr>
				</table>
			</div>
			<?php endif; ?>

			<!-- Enable / disable toggle -->
			<form id="archivio-ecdsa-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $ecdsa_status['openssl_available'] || ! $ecdsa_status['private_key_configured'] || ! $ecdsa_status['certificate_configured'] || ! $ecdsa_status['certificate_valid'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="ecdsa-mode-toggle"
					       name="ecdsa_enabled"
					       value="true"
					       <?php checked( $ecdsa_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $ecdsa_status['openssl_available'] || ! $ecdsa_status['certificate_valid'], true ); ?>>
					<strong><?php esc_html_e( 'Enable ECDSA Enterprise Signing', 'archiviomd' ); ?></strong>
				</label>
				<p style="margin:8px 0 12px 26px;font-size:13px;color:#646970;">
					<?php esc_html_e( 'When enabled, posts and media are signed with your CA-issued X.509 certificate. The certificate is validated (including expiry and CA chain) on every signing operation.', 'archiviomd' ); ?>
				</p>
				<div style="display:flex;align-items:center;gap:12px;">
					<button type="submit" class="button button-primary" id="save-ecdsa-btn"
					        <?php disabled( ! $ecdsa_status['openssl_available'] || ! $ecdsa_status['certificate_valid'], true ); ?>>
						<?php esc_html_e( 'Save', 'archiviomd' ); ?>
					</button>
					<span class="archivio-ecdsa-status" style="font-size:13px;"></span>
				</div>
			</form>

			<!-- Public endpoint note -->
			<p style="margin:18px 0 0;font-size:13px;color:#646970;">
				<?php echo wp_kses(
					sprintf(
						/* translators: %s: well-known URL */
						__( 'Leaf certificate is published at %s so anyone can verify documents came from your site.', 'archiviomd' ),
						'<code>' . esc_html( home_url( '/.well-known/ecdsa-cert.pem' ) ) . '</code>'
					),
					array( 'code' => array() )
				); ?>
				<?php if ( $ecdsa_status['certificate_configured'] ) : ?>
					&nbsp;<a href="<?php echo esc_url( home_url( '/.well-known/ecdsa-cert.pem' ) ); ?>" target="_blank"><?php esc_html_e( 'View', 'archiviomd' ); ?></a>
				<?php endif; ?>
			</p>

			<!-- DSSE sub-toggle -->
			<div style="margin-top:20px;padding-top:16px;border-top:1px solid #f0f0f0;">
				<form id="archivio-ecdsa-dsse-form">
					<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $ecdsa_status['ready'] ) ? 'not-allowed' : 'pointer'; ?>;">
						<input type="checkbox"
						       id="ecdsa-dsse-mode-toggle"
						       name="dsse_enabled"
						       value="true"
						       <?php checked( $ecdsa_status['dsse_enabled'], true ); ?>
						       <?php disabled( ! $ecdsa_status['ready'], true ); ?>>
						<strong><?php esc_html_e( 'DSSE Envelope Mode', 'archiviomd' ); ?></strong>
					</label>
					<p style="margin:6px 0 10px 26px;font-size:12px;color:#646970;">
						<?php esc_html_e( 'Stores a DSSE envelope (with embedded leaf certificate) in _mdsm_ecdsa_dsse post meta. Requires ECDSA signing to be active.', 'archiviomd' ); ?>
					</p>
					<div style="margin-left:26px;">
						<button type="submit" class="button" id="save-ecdsa-dsse-btn"
						        <?php disabled( ! $ecdsa_status['ready'], true ); ?>>
							<?php esc_html_e( 'Save', 'archiviomd' ); ?>
						</button>
						<span class="archivio-ecdsa-dsse-status" style="margin-left:10px;font-size:13px;"></span>
					</div>
				</form>
				<?php if ( ! $ecdsa_status['ready'] ) : ?>
				<p style="margin:10px 0 0;font-size:12px;color:#646970;"><?php esc_html_e( 'Enable and configure ECDSA signing above before enabling DSSE mode.', 'archiviomd' ); ?></p>
				<?php endif; ?>
			</div>

		</div><!-- /.ecdsa-enterprise-card -->

			<!-- ── Hash Algorithm ────────────────────────────────────────── -->
		<h2><?php esc_html_e( 'Hash Algorithm', 'archiviomd' ); ?></h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;margin-bottom:30px;">
			<p style="margin-top:0;">
				<?php esc_html_e( 'Select the algorithm used for new hashes. Existing hashes are never re-computed; they remain verifiable using the algorithm recorded at the time they were created.', 'archiviomd' ); ?>
			</p>

			<form id="archivio-algorithm-form">
				<fieldset style="border:0;padding:0;margin:0;">
					<legend class="screen-reader-text"><?php esc_html_e( 'Hash Algorithm', 'archiviomd' ); ?></legend>

					<!-- Standard Algorithms -->
					<div class="algorithm-section" style="margin-bottom:25px;">
						<h3 style="margin-top:0;margin-bottom:12px;font-size:14px;font-weight:600;color:#1d2327;">
							<?php esc_html_e( 'Standard Algorithms', 'archiviomd' ); ?>
						</h3>
						<?php
						$standard_algos = MDSM_Hash_Helper::standard_algorithms();
						$algo_meta = array(
							'sha256'     => array( 'desc' => __( 'Default, universally supported, 64-char hex', 'archiviomd' ) ),
							'sha224'     => array( 'desc' => __( 'SHA-2 truncated, 56-char hex, common in TLS certs', 'archiviomd' ) ),
							'sha384'     => array( 'desc' => __( 'SHA-2 truncated, 96-char hex, common in TLS certs', 'archiviomd' ) ),
							'sha512'     => array( 'desc' => __( 'Stronger collision resistance, 128-char hex', 'archiviomd' ) ),
							'sha512-224' => array( 'desc' => __( 'FIPS-approved SHA-512 truncated to 224-bit, 56-char hex', 'archiviomd' ) ),
							'sha512-256' => array( 'desc' => __( 'FIPS-approved SHA-512 truncated to 256-bit, 64-char hex', 'archiviomd' ) ),
							'sha3-256'   => array( 'desc' => __( 'SHA-3 / Keccak sponge, 64-char hex (PHP 7.1+)', 'archiviomd' ) ),
							'sha3-512'   => array( 'desc' => __( 'SHA-3 / Keccak sponge, 128-char hex (PHP 7.1+)', 'archiviomd' ) ),
							'blake2b'    => array( 'desc' => __( 'Modern, fast, 128-char hex (PHP 7.2+)', 'archiviomd' ) ),
							'blake2s'    => array( 'desc' => __( 'BLAKE2s 32-bit optimised, 64-char hex (PHP 7.2+)', 'archiviomd' ) ),
							'sha256d'    => array( 'desc' => __( 'Double SHA-256, Bitcoin-compatible, 64-char hex', 'archiviomd' ) ),
							'ripemd160'  => array( 'desc' => __( 'Bitcoin address hashing primitive, 40-char hex', 'archiviomd' ) ),
							'whirlpool'  => array( 'desc' => __( 'Legacy 512-bit hash, ISO/IEC 10118-3, 128-char hex', 'archiviomd' ) ),
						);
						foreach ( $standard_algos as $algo_key => $algo_label ) :
							$avail       = MDSM_Hash_Helper::get_algorithm_availability( $algo_key );
							$desc        = isset( $algo_meta[ $algo_key ] ) ? $algo_meta[ $algo_key ]['desc'] : '';
							$unavailable = ! $avail;
						?>
						<label style="display:block;margin-bottom:10px;cursor:<?php echo $unavailable ? 'not-allowed' : 'pointer'; ?>;padding-left:22px;position:relative;">
							<input type="radio"
							       name="algorithm"
							       value="<?php echo esc_attr( $algo_key ); ?>"
							       <?php checked( $active_algorithm, $algo_key ); ?>
							       <?php disabled( $unavailable, true ); ?>
							       style="position:absolute;left:0;top:3px;margin:0;">
							<strong style="font-weight:500;"><?php echo esc_html( $algo_label ); ?></strong>
							<br>
							<span style="color:#646970;font-size:12px;line-height:1.6;">
								<?php echo esc_html( $desc ); ?>
								<?php if ( $unavailable ) : ?>
									<span style="color:#d73a49;">(<?php esc_html_e( 'not available on this PHP build', 'archiviomd' ); ?>)</span>
								<?php else : ?>
									<span style="color:#0a7537;">(<?php esc_html_e( 'available', 'archiviomd' ); ?>)</span>
								<?php endif; ?>
							</span>
						</label>
						<?php endforeach; ?>
					</div>

					<!-- Experimental / Advanced Algorithms -->
					<div class="algorithm-section" style="margin-bottom:20px;padding:15px;background:#fff8e5;border:1px solid #dba617;border-radius:4px;">
						<h3 style="margin-top:0;margin-bottom:8px;font-size:14px;font-weight:600;color:#1d2327;">
							<?php esc_html_e( 'Advanced / Experimental Algorithms', 'archiviomd' ); ?>
						</h3>
						<p style="margin:0 0 12px 0;font-size:12px;color:#646970;">
							<strong><?php esc_html_e( 'Warning:', 'archiviomd' ); ?></strong>
							<?php esc_html_e( 'Experimental algorithms may be slower, may not work on all hosts, and will automatically fall back to SHA-256 or BLAKE2b if unavailable. Use standard algorithms for production sites.', 'archiviomd' ); ?>
						</p>
						<?php
						$experimental_algos = MDSM_Hash_Helper::experimental_algorithms();
						$exp_algo_meta = array(
							'blake3'   => array( 'desc' => __( 'BLAKE3 with 256-bit output, extremely fast (PHP 8.1+ or fallback)', 'archiviomd' ) ),
							'shake128' => array( 'desc' => __( 'SHAKE128 XOF with 256-bit output (PHP 7.1+ or fallback)', 'archiviomd' ) ),
							'shake256' => array( 'desc' => __( 'SHAKE256 XOF with 512-bit output (PHP 7.1+ or fallback)', 'archiviomd' ) ),
						);
						foreach ( $experimental_algos as $algo_key => $algo_label ) :
							$avail = MDSM_Hash_Helper::get_algorithm_availability( $algo_key );
							$desc  = isset( $exp_algo_meta[ $algo_key ] ) ? $exp_algo_meta[ $algo_key ]['desc'] : '';
						?>
						<label style="display:block;margin-bottom:10px;cursor:pointer;padding-left:22px;position:relative;">
							<input type="radio"
							       name="algorithm"
							       value="<?php echo esc_attr( $algo_key ); ?>"
							       <?php checked( $active_algorithm, $algo_key ); ?>
							       style="position:absolute;left:0;top:3px;margin:0;">
							<strong style="font-weight:500;color:#8c400b;"><?php echo esc_html( $algo_label ); ?></strong>
							<br>
							<span style="color:#646970;font-size:12px;line-height:1.6;">
								<?php echo esc_html( $desc ); ?>
								<?php if ( $avail ) : ?>
									<span style="color:#0a7537;">(<?php esc_html_e( 'native available', 'archiviomd' ); ?>)</span>
								<?php else : ?>
									<span style="color:#d73a49;">(<?php esc_html_e( 'fallback mode', 'archiviomd' ); ?>)</span>
								<?php endif; ?>
							</span>
						</label>
						<?php endforeach; ?>
					</div>

					<!-- Regional / Compliance Algorithms -->
					<div class="algorithm-section" style="margin-bottom:20px;padding:15px;background:#f0f4ff;border:1px solid #6b8ec7;border-radius:4px;">
						<h3 style="margin-top:0;margin-bottom:8px;font-size:14px;font-weight:600;color:#1d2327;">
							<?php esc_html_e( 'Regional / Compliance Algorithms', 'archiviomd' ); ?>
						</h3>
						<p style="margin:0 0 12px 0;font-size:12px;color:#646970;">
							<?php esc_html_e( 'Algorithms required by specific national or regulatory standards. Availability depends on your PHP build and OpenSSL configuration.', 'archiviomd' ); ?>
						</p>
						<?php
						$regional_algos = MDSM_Hash_Helper::regional_algorithms();
						$regional_algo_meta = array(
							'gost'        => array( 'desc' => __( 'GOST R 34.11-94, Russian federal standard, 64-char hex', 'archiviomd' ) ),
							'gost-crypto' => array( 'desc' => __( 'GOST R 34.11-94 with CryptoPro S-box, used in Russian PKI/eGov', 'archiviomd' ) ),
						);
						foreach ( $regional_algos as $algo_key => $algo_label ) :
							$avail       = MDSM_Hash_Helper::get_algorithm_availability( $algo_key );
							$desc        = isset( $regional_algo_meta[ $algo_key ] ) ? $regional_algo_meta[ $algo_key ]['desc'] : '';
							$unavailable = ! $avail;
						?>
						<label style="display:block;margin-bottom:10px;cursor:<?php echo $unavailable ? 'not-allowed' : 'pointer'; ?>;padding-left:22px;position:relative;">
							<input type="radio"
							       name="algorithm"
							       value="<?php echo esc_attr( $algo_key ); ?>"
							       <?php checked( $active_algorithm, $algo_key ); ?>
							       <?php disabled( $unavailable, true ); ?>
							       style="position:absolute;left:0;top:3px;margin:0;">
							<strong style="font-weight:500;color:#2c4a8c;"><?php echo esc_html( $algo_label ); ?></strong>
							<br>
							<span style="color:#646970;font-size:12px;line-height:1.6;">
								<?php echo esc_html( $desc ); ?>
								<?php if ( $unavailable ) : ?>
									<span style="color:#d73a49;">(<?php esc_html_e( 'not available on this PHP build', 'archiviomd' ); ?>)</span>
								<?php else : ?>
									<span style="color:#0a7537;">(<?php esc_html_e( 'available', 'archiviomd' ); ?>)</span>
								<?php endif; ?>
							</span>
						</label>
						<?php endforeach; ?>
					</div>

					<!-- Legacy / Deprecated Algorithms -->
					<div class="algorithm-section" style="margin-bottom:20px;padding:15px;background:#fff0f0;border:1px solid #c92b2b;border-radius:4px;">
						<h3 style="margin-top:0;margin-bottom:8px;font-size:14px;font-weight:600;color:#c92b2b;">
							<?php esc_html_e( 'Legacy / Deprecated Algorithms', 'archiviomd' ); ?>
						</h3>
						<p style="margin:0 0 12px 0;font-size:12px;color:#646970;">
							<strong style="color:#c92b2b;"><?php esc_html_e( 'Cryptographically broken.', 'archiviomd' ); ?></strong>
							<?php esc_html_e( 'Only use these to verify hashes from legacy systems or archives. Never use for new integrity-critical hashing.', 'archiviomd' ); ?>
						</p>
						<?php
						$deprecated_algos = MDSM_Hash_Helper::deprecated_algorithms();
						$dep_algo_meta = array(
							'md5'  => array( 'desc' => __( 'MD5 – broken, collision attacks known, 32-char hex. Legacy verification only.', 'archiviomd' ) ),
							'sha1' => array( 'desc' => __( 'SHA-1 – broken, SHAttered collision demonstrated, 40-char hex. Legacy verification only.', 'archiviomd' ) ),
						);
						foreach ( $deprecated_algos as $algo_key => $algo_label ) :
							$desc = isset( $dep_algo_meta[ $algo_key ] ) ? $dep_algo_meta[ $algo_key ]['desc'] : '';
						?>
						<label style="display:block;margin-bottom:10px;cursor:pointer;padding-left:22px;position:relative;">
							<input type="radio"
							       name="algorithm"
							       value="<?php echo esc_attr( $algo_key ); ?>"
							       <?php checked( $active_algorithm, $algo_key ); ?>
							       style="position:absolute;left:0;top:3px;margin:0;">
							<strong style="font-weight:500;color:#c92b2b;"><?php echo esc_html( $algo_label ); ?></strong>
							<br>
							<span style="color:#646970;font-size:12px;line-height:1.6;">
								<?php echo esc_html( $desc ); ?>
								<span style="color:#0a7537;">(<?php esc_html_e( 'available', 'archiviomd' ); ?>)</span>
							</span>
						</label>
						<?php endforeach; ?>
					</div>

				</fieldset>

				<div style="margin-top:15px;">
					<button type="submit" class="button button-primary" id="save-algorithm-btn">
						<?php esc_html_e( 'Save Algorithm', 'archiviomd' ); ?>
					</button>
					<span class="archivio-algorithm-status" style="margin-left:10px;"></span>
				</div>
			</form>

			<?php if ( ! $blake2b_available || ! $sha3_available ) : ?>
			<div style="margin-top:15px;padding:10px 15px;background:#fff8e5;border-left:4px solid #dba617;border-radius:4px;">
				<strong><?php esc_html_e( 'Note:', 'archiviomd' ); ?></strong>
				<?php if ( ! $sha3_available ) : ?>
					<?php esc_html_e( 'SHA3-256 and SHA3-512 require PHP 7.1+. They are not available on this server.', 'archiviomd' ); ?>
				<?php endif; ?>
				<?php if ( ! $blake2b_available ) : ?>
					<?php esc_html_e( 'BLAKE2b requires PHP 7.2+ with OpenSSL support. It is not available on this server.', 'archiviomd' ); ?>
				<?php endif; ?>
			</div>
			<?php endif; ?>
		</div>

		<!-- ── Hash Generation Settings ──────────────────────────────── -->
		<h2><?php esc_html_e( 'Hash Generation Settings', 'archiviomd' ); ?></h2>

		<form id="archivio-post-settings-form">
			<table class="form-table" role="presentation">
				<tbody>
					<tr>
						<th scope="row">
							<label for="auto-generate">
								<?php esc_html_e( 'Automatic Hash Generation', 'archiviomd' ); ?>
							</label>
						</th>
						<td>
							<label>
								<input type="checkbox"
								       id="auto-generate"
								       name="auto_generate"
								       value="1"
								       <?php checked( $auto_generate, true ); ?>>
								<?php esc_html_e( 'Automatically generate hash when posts are published or updated', 'archiviomd' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'When enabled, a hash using the selected algorithm and current mode is generated for each post on publish/update.', 'archiviomd' ); ?>
							</p>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Display Verification Badge', 'archiviomd' ); ?></label>
						</th>
						<td>
							<fieldset>
								<legend class="screen-reader-text">
									<span><?php esc_html_e( 'Badge Display Options', 'archiviomd' ); ?></span>
								</legend>

								<label style="display:block;margin-bottom:10px;">
									<input type="checkbox"
									       id="show-badge"
									       name="show_badge"
									       value="1"
									       <?php checked( $show_badge, true ); ?>>
									<?php esc_html_e( 'Display verification badge (master toggle)', 'archiviomd' ); ?>
								</label>

								<div style="margin-left:25px;padding-left:15px;border-left:3px solid #ddd;">
									<label style="display:block;margin-bottom:10px;">
										<input type="checkbox"
										       id="show-badge-posts"
										       name="show_badge_posts"
										       value="1"
										       <?php checked( $show_badge_posts, true ); ?>>
										<?php esc_html_e( 'Show badge on Posts', 'archiviomd' ); ?>
									</label>

									<label style="display:block;">
										<input type="checkbox"
										       id="show-badge-pages"
										       name="show_badge_pages"
										       value="1"
										       <?php checked( $show_badge_pages, true ); ?>>
										<?php esc_html_e( 'Show badge on Pages', 'archiviomd' ); ?>
									</label>
								</div>
							</fieldset>

							<!-- Badge preview -->
							<div style="margin-top:15px;padding:15px;background:#f9f9f9;border-left:4px solid #2271b1;">
								<strong><?php esc_html_e( 'Badge Preview:', 'archiviomd' ); ?></strong>
								<div style="margin-top:10px;">
									<span class="archivio-post-badge archivio-post-badge-verified">
										<svg class="archivio-post-icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
											<path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"/>
										</svg>
										<span class="archivio-post-badge-text"><?php esc_html_e( 'Verified', 'archiviomd' ); ?></span>
										<button class="archivio-post-download" title="<?php esc_attr_e( 'Download verification file', 'archiviomd' ); ?>">
											<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
												<path d="M8.5 1.75a.75.75 0 00-1.5 0v6.69L5.03 6.47a.75.75 0 00-1.06 1.06l3.5 3.5a.75.75 0 001.06 0l3.5-3.5a.75.75 0 10-1.06-1.06L8.5 8.44V1.75zM3.5 11.25a.75.75 0 00-1.5 0v2.5c0 .69.56 1.25 1.25 1.25h10.5A1.25 1.25 0 0015 13.75v-2.5a.75.75 0 00-1.5 0v2.5H3.5v-2.5z"/>
											</svg>
										</button>
									</span>
									<span style="margin-left:10px;" class="archivio-post-badge archivio-post-badge-unverified">
										<svg class="archivio-post-icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
											<path d="M3.72 3.72a.75.75 0 011.06 0L8 6.94l3.22-3.22a.75.75 0 111.06 1.06L9.06 8l3.22 3.22a.75.75 0 11-1.06 1.06L8 9.06l-3.22 3.22a.75.75 0 01-1.06-1.06L6.94 8 3.72 4.78a.75.75 0 010-1.06z"/>
										</svg>
										<span class="archivio-post-badge-text"><?php esc_html_e( 'Unverified', 'archiviomd' ); ?></span>
									</span>
									<span style="margin-left:10px;" class="archivio-post-badge archivio-post-badge-not_signed">
										<svg class="archivio-post-icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
											<path d="M8 2a.75.75 0 01.75.75v4.5a.75.75 0 01-1.5 0v-4.5A.75.75 0 018 2zM8 10a1 1 0 100 2 1 1 0 000-2z"/>
										</svg>
										<span class="archivio-post-badge-text"><?php esc_html_e( 'Not Signed', 'archiviomd' ); ?></span>
									</span>
								</div>
							</div>
						</td>
					</tr>
				</tbody>
			</table>

			<p class="submit">
				<button type="submit" class="button button-primary" id="save-settings-btn">
					<?php esc_html_e( 'Save Settings', 'archiviomd' ); ?>
				</button>
				<span class="archivio-post-save-status" style="margin-left:10px;"></span>
			</p>
		</form>

		<hr style="margin:40px 0;">

		<!-- Troubleshooting -->
		<h2><?php esc_html_e( 'Troubleshooting', 'archiviomd' ); ?></h2>
		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;margin-bottom:20px;">
			<h3><?php esc_html_e( 'Enable All Settings', 'archiviomd' ); ?></h3>
			<p><?php esc_html_e( 'Click this button to enable Auto-Generate and all badge display options.', 'archiviomd' ); ?></p>
			<p style="font-size:12px;color:#666;">
				<?php
				$current_value = get_option( 'archivio_post_auto_generate' );
				printf( '<code>%s</code>', esc_html( $current_value ? 'enabled' : 'disabled' ) );
				?>
			</p>
			<button type="button" id="fix-settings-btn" class="button button-secondary">
				<?php esc_html_e( 'Enable All Settings', 'archiviomd' ); ?>
			</button>
			<span class="fix-settings-status" style="margin-left:10px;"></span>
		</div>
		
		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;">
			<h3><?php esc_html_e( 'Recreate Audit Log Table', 'archiviomd' ); ?></h3>
			<p><?php esc_html_e( 'If the audit log is not working, recreate the database table. Existing entries are preserved.', 'archiviomd' ); ?></p>
			<button type="button" id="recreate-table-btn" class="button button-secondary">
				<?php esc_html_e( 'Recreate Database Table', 'archiviomd' ); ?>
			</button>
			<span class="recreate-table-status" style="margin-left:10px;"></span>
		</div>

		<hr style="margin:40px 0;">

		<!-- How It Works -->
		<h2><?php esc_html_e( 'How It Works', 'archiviomd' ); ?></h2>
		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-radius:4px;">
			<ol style="line-height:2;">
				<li><strong><?php esc_html_e( 'Content Canonicalization:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'Post content is normalized (LF line endings, trimmed whitespace) and prefixed with post_id and author_id.', 'archiviomd' ); ?>
				</li>
				<li><strong><?php esc_html_e( 'Hash Generation:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'A hash is computed using the selected algorithm in Standard or HMAC mode. Both the algorithm and mode are stored alongside the hash.', 'archiviomd' ); ?>
				</li>
				<li><strong><?php esc_html_e( 'Storage:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'Standard hashes are packed as "algo:hex". HMAC hashes are packed as "hmac-algo:hex". Author ID and timestamp are saved in post meta and the audit log.', 'archiviomd' ); ?>
				</li>
				<li><strong><?php esc_html_e( 'Verification:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'The stored packed string determines the algorithm and mode for re-computation. Standard hashes verify with hash(); HMAC hashes verify with hash_hmac() and the configured key. Legacy SHA-256 bare-hex hashes always verify correctly.', 'archiviomd' ); ?>
				</li>
				<li><strong><?php esc_html_e( 'Badge Display:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'The badge shows "Verified" (green), "Unverified" (red), or "Not Signed" (gray).', 'archiviomd' ); ?>
				</li>
			</ol>
		</div>
	</div>

	<?php elseif ( $active_tab === 'audit' ) : ?>
	<!-- ================================================================
	     AUDIT LOG TAB
	     ================================================================ -->
	<div class="archivio-post-tab-content">
		<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
			<h2 style="margin:0;"><?php esc_html_e( 'Audit Log', 'archiviomd' ); ?></h2>
			<div style="display:flex;gap:8px;align-items:center;">
			<button type="button" id="refresh-audit-log" class="button button-secondary">
				<span class="dashicons dashicons-update" style="vertical-align:middle;margin-right:5px;"></span>
				<?php esc_html_e( 'Refresh', 'archiviomd' ); ?>
			</button>
			<button type="button" id="export-audit-csv" class="button button-secondary">
				<span class="dashicons dashicons-download" style="vertical-align:middle;margin-right:5px;"></span>
				<?php esc_html_e( 'Export to CSV', 'archiviomd' ); ?>
			</button>
		</div>
		</div>

		<p class="description">
			<?php esc_html_e( 'All hash generation and unverified events are logged here. The Algorithm and Mode columns show how each hash was produced.', 'archiviomd' ); ?>
		</p>

		<div id="audit-log-container">
			<div class="audit-log-loading" style="text-align:center;padding:40px;">
				<span class="spinner is-active" style="float:none;margin:0 auto;"></span>
				<p><?php esc_html_e( 'Loading audit logs...', 'archiviomd' ); ?></p>
			</div>
		</div>
		<div id="audit-log-pagination" style="margin-top:20px;text-align:center;"></div>
	</div>

	<?php elseif ( $active_tab === 'extended' ) : ?>
	<!-- ================================================================
	     EXTENDED FORMATS TAB
	     ================================================================ -->
	<div class="archivio-post-tab-content">
		<h2><?php esc_html_e( 'Extended Format Support', 'archiviomd' ); ?></h2>

		<p class="description" style="font-size:13px;margin-bottom:24px;">
			<?php esc_html_e( 'These modules produce additional signature formats alongside the core Ed25519 / SLH-DSA / ECDSA signatures. Each format targets a specific interoperability surface — legacy enterprise tooling, document management systems, or W3C credential ecosystems. The underlying signature material is always derived from the same canonical message signed by the core algorithms; no new key material is introduced.', 'archiviomd' ); ?>
		</p>

		<?php
		// ── Live status objects ────────────────────────────────────────────
		$rsa_status    = class_exists( 'MDSM_RSA_Signing' )    ? MDSM_RSA_Signing::status()    : array( 'ready' => false, 'mode_enabled' => false, 'notice_level' => 'ok', 'notice_message' => '', 'key_configured' => false, 'openssl_available' => false, 'scheme' => 'rsa-pss-sha256' );
		$cms_status    = class_exists( 'MDSM_CMS_Signing' )    ? MDSM_CMS_Signing::status()    : array( 'ready' => false, 'mode_enabled' => false, 'notice_level' => 'ok', 'notice_message' => '', 'key_available' => false, 'openssl_available' => false, 'key_source' => null );
		$jsonld_status = class_exists( 'MDSM_JSONLD_Signing' ) ? MDSM_JSONLD_Signing::status() : array( 'ready' => false, 'mode_enabled' => false, 'notice_level' => 'ok', 'notice_message' => '', 'signer_available' => false, 'active_suites' => array(), 'did_url' => '' );
		$dane_status   = class_exists( 'MDSM_DANE_Corroboration' ) ? MDSM_DANE_Corroboration::status() : array( 'ready' => false, 'mode_enabled' => false, 'prereq_met' => false, 'notice_level' => 'ok', 'notice_message' => '', 'dns_record_name' => '', 'expected_txt' => '', 'public_key_b64' => '', 'active_algos' => array(), 'records' => array(), 'staleness' => array(), 'json_endpoint' => '', 'rotation_mode' => false, 'rotation_elapsed' => 0, 'doh_url' => 'https://1.1.1.1/dns-query', 'dane_ttl' => 3600, 'tlsa_enabled' => false, 'tlsa_prereq_met' => false, 'tlsa_record_name' => '', 'tlsa_record_value' => '' );

		$badge_ent = '<span style="display:inline-block;background:#f0e6ff;color:#6b21a8;font-size:11px;font-weight:600;letter-spacing:.04em;padding:2px 8px;border-radius:3px;text-transform:uppercase;vertical-align:middle;">Enterprise</span>';
		$badge_w3c = '<span style="display:inline-block;background:#e6f4ff;color:#0369a1;font-size:11px;font-weight:600;letter-spacing:.04em;padding:2px 8px;border-radius:3px;text-transform:uppercase;vertical-align:middle;">W3C Standard</span>';

		// Helper: status banner (mirrors the signing-tab pattern exactly).
		function mdsm_ext_status_banner( array $s ): void {
			if ( ! $s['mode_enabled'] ) return;
			$lvl = $s['notice_level'] ?? 'ok';
			if ( $lvl === 'error' ) {
				echo '<div class="notice notice-error inline" style="margin:0 0 16px;"><p>' . esc_html( $s['notice_message'] ) . '</p></div>';
			} elseif ( $lvl === 'warning' ) {
				echo '<div class="notice notice-warning inline" style="margin:0 0 16px;"><p>' . esc_html( $s['notice_message'] ) . '</p></div>';
			} else {
				echo '<div class="notice notice-success inline" style="margin:0 0 16px;"><p>' . esc_html( $s['notice_message'] ) . '</p></div>';
			}
		}

		// Helper: prerequisite row.
		function mdsm_prereq_row( bool $ok, string $label, string $detail = '' ): void {
			if ( $ok ) {
				echo '<tr><td style="padding:3px 12px 3px 0;color:#646970;">' . esc_html( $label ) . '</td>';
				echo '<td><span style="color:#0a7537;">&#10003; ' . esc_html( $detail ?: __( 'Available', 'archiviomd' ) ) . '</span></td></tr>';
			} else {
				echo '<tr><td style="padding:3px 12px 3px 0;color:#646970;">' . esc_html( $label ) . '</td>';
				echo '<td><span style="color:#996800;">&#9888; ' . esc_html( $detail ?: __( 'Not configured', 'archiviomd' ) ) . '</span></td></tr>';
			}
		}
		?>

		<!-- ══════════════════════════════════════════════════════════════
		     RSA COMPATIBILITY SIGNING
		     ══════════════════════════════════════════════════════════════ -->
		<h2 style="display:flex;align-items:center;gap:10px;">
			<?php esc_html_e( 'RSA Compatibility Signing', 'archiviomd' ); ?>
			<?php echo $badge_ent; // phpcs:ignore WordPress.Security.EscapeOutput ?>
		</h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-left:4px solid #7c3aed;border-radius:4px;margin-bottom:30px;">

			<!-- Enterprise caution banner -->
			<div style="background:#faf5ff;border:1px solid #c4b5fd;border-radius:4px;padding:14px 18px;margin-bottom:18px;">
				<p style="margin:0 0 6px;font-weight:600;color:#5b21b6;">⚠ <?php esc_html_e( 'Legacy compatibility mode — not recommended for general use', 'archiviomd' ); ?></p>
				<p style="margin:0;font-size:13px;color:#6d28d9;line-height:1.6;"><?php esc_html_e( 'Use only when a downstream system cannot accept Ed25519, EC, or SLH-DSA keys. For all other sites Ed25519 is simpler, faster, and equally secure.', 'archiviomd' ); ?></p>
			</div>

			<?php mdsm_ext_status_banner( $rsa_status ); ?>

			<!-- Prerequisite checklist -->
			<table style="border-collapse:collapse;margin-bottom:18px;font-size:13px;">
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'PHP ext-openssl', 'archiviomd' ); ?></td>
					<td><?php if ( $rsa_status['openssl_available'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Available', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#dc3232;">&#10007; <?php esc_html_e( 'Not available — required for RSA signing', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'RSA private key', 'archiviomd' ); ?></td>
					<td><?php if ( defined( MDSM_RSA_Signing::CONSTANT_PRIVATE_KEY ) ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Set via wp-config.php constant', 'archiviomd' ); ?></span>
					<?php elseif ( $rsa_status['key_configured'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'PEM file uploaded', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#996800;">&#9888; <?php esc_html_e( 'Not configured', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Certificate', 'archiviomd' ); ?></td>
					<td><?php if ( defined( MDSM_RSA_Signing::CONSTANT_CERTIFICATE ) ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Set via wp-config.php constant', 'archiviomd' ); ?></span>
					<?php elseif ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::load_certificate_pem() ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Certificate configured', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#646970;">&mdash; <?php esc_html_e( 'Optional — public key published instead when absent', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
			</table>

			<!-- PEM upload section — shown only when constant is not set -->
			<?php if ( ! defined( MDSM_RSA_Signing::CONSTANT_PRIVATE_KEY ) ) : ?>
			<div style="border:1px solid #e2e4e7;border-radius:4px;padding:16px;margin-bottom:18px;">
				<strong style="display:block;margin-bottom:10px;font-size:13px;"><?php esc_html_e( 'Key Configuration', 'archiviomd' ); ?></strong>
				<p style="font-size:12px;color:#646970;margin:0 0 10px;">
					<?php esc_html_e( 'Upload PEM files or define wp-config.php constants. Constants take priority.', 'archiviomd' ); ?>
				</p>
				<p style="font-size:12px;font-family:monospace;color:#646970;margin:0 0 14px;background:#f6f7f7;padding:10px;border-radius:3px;">
					define( '<?php echo esc_html( MDSM_RSA_Signing::CONSTANT_PRIVATE_KEY ); ?>', '-----BEGIN RSA PRIVATE KEY-----\n...' );<br>
					define( '<?php echo esc_html( MDSM_RSA_Signing::CONSTANT_CERTIFICATE ); ?>', '-----BEGIN CERTIFICATE-----\n...' ); <em style="color:#999;">// optional</em><br>
					define( '<?php echo esc_html( MDSM_RSA_Signing::CONSTANT_SCHEME ); ?>', 'rsa-pss-sha256' ); <em style="color:#999;">// optional</em>
				</p>

				<table style="border-collapse:collapse;width:100%;font-size:13px;">
					<!-- Private key row -->
					<tr>
						<td style="padding:6px 12px 6px 0;white-space:nowrap;color:#646970;vertical-align:middle;">
							<?php esc_html_e( 'RSA Private Key (.pem)', 'archiviomd' ); ?>
							<span style="display:inline-block;background:#dc3232;color:#fff;border-radius:3px;padding:0 5px;font-size:10px;margin-left:4px;">PRIVATE</span>
						</td>
						<td style="vertical-align:middle;">
							<?php if ( $rsa_status['key_configured'] ) : ?>
								<span style="color:#0a7537;margin-right:8px;">&#10003; <?php esc_html_e( 'Uploaded', 'archiviomd' ); ?></span>
								<button type="button" class="button button-small rsa-clear-btn" data-action="archivio_rsa_clear_key"><?php esc_html_e( 'Remove', 'archiviomd' ); ?></button>
							<?php else : ?>
								<input type="file" id="rsa-key-upload" accept=".pem" style="font-size:13px;">
								<button type="button" class="button button-small" id="rsa-key-upload-btn"><?php esc_html_e( 'Upload', 'archiviomd' ); ?></button>
								<span id="rsa-key-status" style="margin-left:8px;font-size:12px;"></span>
							<?php endif; ?>
						</td>
					</tr>
					<!-- Certificate row -->
					<tr>
						<td style="padding:6px 12px 6px 0;white-space:nowrap;color:#646970;vertical-align:middle;"><?php esc_html_e( 'X.509 Certificate (.pem) — optional', 'archiviomd' ); ?></td>
						<td style="vertical-align:middle;">
							<?php
							$rsa_cert_uploaded = class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::load_certificate_pem() && ! defined( MDSM_RSA_Signing::CONSTANT_CERTIFICATE );
							if ( $rsa_cert_uploaded ) : ?>
								<span style="color:#0a7537;margin-right:8px;">&#10003; <?php esc_html_e( 'Uploaded', 'archiviomd' ); ?></span>
								<button type="button" class="button button-small rsa-clear-btn" data-action="archivio_rsa_clear_cert"><?php esc_html_e( 'Remove', 'archiviomd' ); ?></button>
							<?php else : ?>
								<input type="file" id="rsa-cert-upload" accept=".pem" style="font-size:13px;">
								<button type="button" class="button button-small" id="rsa-cert-upload-btn"><?php esc_html_e( 'Upload', 'archiviomd' ); ?></button>
								<span id="rsa-cert-status" style="margin-left:8px;font-size:12px;"></span>
							<?php endif; ?>
						</td>
					</tr>
				</table>
			</div>
			<?php endif; ?>

			<!-- Signing scheme selector -->
			<div style="margin-bottom:16px;font-size:13px;">
				<strong style="display:block;margin-bottom:8px;"><?php esc_html_e( 'Signing Scheme', 'archiviomd' ); ?></strong>
				<label style="display:inline-flex;align-items:center;gap:6px;margin-right:20px;cursor:pointer;">
					<input type="radio" name="rsa_scheme" value="rsa-pss-sha256"
						<?php checked( class_exists( 'MDSM_RSA_Signing' ) ? MDSM_RSA_Signing::get_scheme() : 'rsa-pss-sha256', 'rsa-pss-sha256' ); ?>>
					<span><?php esc_html_e( 'RSA-PSS / SHA-256', 'archiviomd' ); ?> <em style="color:#646970;font-size:11px;"><?php esc_html_e( '(recommended)', 'archiviomd' ); ?></em></span>
				</label>
				<label style="display:inline-flex;align-items:center;gap:6px;cursor:pointer;">
					<input type="radio" name="rsa_scheme" value="rsa-pkcs1v15-sha256"
						<?php checked( class_exists( 'MDSM_RSA_Signing' ) ? MDSM_RSA_Signing::get_scheme() : 'rsa-pss-sha256', 'rsa-pkcs1v15-sha256' ); ?>>
					<span><?php esc_html_e( 'PKCS#1 v1.5 / SHA-256', 'archiviomd' ); ?> <em style="color:#646970;font-size:11px;"><?php esc_html_e( '(legacy compatibility)', 'archiviomd' ); ?></em></span>
				</label>
			</div>

			<!-- Well-known endpoint note -->
			<?php if ( $rsa_status['key_configured'] || defined( MDSM_RSA_Signing::CONSTANT_PRIVATE_KEY ) ) : ?>
			<p style="margin:0 0 14px;font-size:13px;color:#646970;">
				<?php printf(
					/* translators: %s: URL */
					esc_html__( 'Public key published at %s', 'archiviomd' ),
					'<a href="' . esc_url( home_url( '/.well-known/rsa-pubkey.pem' ) ) . '" target="_blank"><code>' . esc_html( home_url( '/.well-known/rsa-pubkey.pem' ) ) . '</code></a>'
				); // phpcs:ignore WordPress.Security.EscapeOutput ?>
			</p>
			<?php endif; ?>

			<!-- Enable toggle + save -->
			<form id="archivio-rsa-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $rsa_status['openssl_available'] || ! $rsa_status['key_configured'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="rsa-mode-toggle"
					       name="rsa_enabled"
					       value="true"
					       <?php checked( $rsa_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $rsa_status['openssl_available'] || ! $rsa_status['key_configured'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable RSA Compatibility Signing', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Signs posts and media with the configured RSA key on every save. Signature stored in _mdsm_rsa_sig post meta.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>
				<div style="margin-top:14px;display:flex;align-items:center;gap:12px;">
					<button type="submit" class="button button-primary" id="save-rsa-btn"
					        <?php disabled( ! $rsa_status['openssl_available'] || ! $rsa_status['key_configured'], true ); ?>>
						<?php esc_html_e( 'Save RSA Settings', 'archiviomd' ); ?>
					</button>
					<span class="archivio-rsa-status" style="font-size:13px;"></span>
				</div>
			</form>

		</div><!-- /rsa card -->

		<!-- ══════════════════════════════════════════════════════════════
		     CMS / PKCS#7 DETACHED SIGNATURES
		     ══════════════════════════════════════════════════════════════ -->
		<h2 style="display:flex;align-items:center;gap:10px;">
			<?php esc_html_e( 'CMS / PKCS#7 Detached Signatures', 'archiviomd' ); ?>
			<?php echo $badge_ent; // phpcs:ignore WordPress.Security.EscapeOutput ?>
		</h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-left:4px solid #7c3aed;border-radius:4px;margin-bottom:30px;">

			<p style="margin-top:0;font-size:13px;color:#1d2327;">
				<?php esc_html_e( 'Produces a Cryptographic Message Syntax (CMS / PKCS#7, RFC 5652) detached signature verifiable with OpenSSL, Adobe Acrobat, Java Bouncy Castle, Windows CertUtil, and regulated-industry audit tooling. Reuses your ECDSA P-256 or RSA key — no additional key material required.', 'archiviomd' ); ?>
			</p>

			<?php mdsm_ext_status_banner( $cms_status ); ?>

			<!-- Prerequisite checklist -->
			<table style="border-collapse:collapse;margin-bottom:18px;font-size:13px;">
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'PHP ext-openssl + pkcs7', 'archiviomd' ); ?></td>
					<td><?php if ( $cms_status['openssl_available'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Available', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#dc3232;">&#10007; <?php esc_html_e( 'Not available — required for CMS signing', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<?php
				// Show which key source will be used
				$cms_ecdsa_ready = class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::status()['ready'];
				$cms_rsa_ready   = class_exists( 'MDSM_RSA_Signing' )   && MDSM_RSA_Signing::status()['ready'];
				?>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'ECDSA P-256 key source', 'archiviomd' ); ?></td>
					<td><?php if ( $cms_ecdsa_ready ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Ready — will be used as primary key source', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#646970;">&mdash; <?php esc_html_e( 'Not active (configure ECDSA P-256 on the Signing tab)', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'RSA key source (fallback)', 'archiviomd' ); ?></td>
					<td><?php if ( $cms_rsa_ready ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Ready — will be used as fallback key source', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#646970;">&mdash; <?php esc_html_e( 'Not active (configure RSA signing above)', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<?php if ( $cms_status['key_available'] ) : ?>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Key source that will be used', 'archiviomd' ); ?></td>
					<td><span style="color:#0a7537;font-weight:600;">
						<?php echo $cms_ecdsa_ready ? esc_html__( 'ECDSA P-256', 'archiviomd' ) : esc_html__( 'RSA', 'archiviomd' ); ?>
					</span></td>
				</tr>
				<?php endif; ?>
			</table>

			<?php if ( ! $cms_status['key_available'] ) : ?>
			<div style="background:#fff8e5;padding:12px 16px;border-left:3px solid #dba617;border-radius:3px;font-size:13px;margin-bottom:16px;">
				<?php esc_html_e( 'CMS/PKCS#7 signing requires at least one of: ECDSA P-256 (from the Signing tab) or RSA (configured above) to be active and ready before this module can be enabled.', 'archiviomd' ); ?>
			</div>
			<?php endif; ?>

			<!-- Offline verification note -->
			<div style="background:#f0f6ff;border-left:3px solid #2271b1;border-radius:3px;padding:12px 16px;font-size:12px;margin-bottom:16px;">
				<strong><?php esc_html_e( 'Offline verify:', 'archiviomd' ); ?></strong>
				<code style="display:block;margin-top:4px;">openssl cms -verify -inform DER -in sig.der -content message.txt -noverify</code>
				<p style="margin:6px 0 0;"><?php esc_html_e( 'The base64-encoded DER blob stored in _mdsm_cms_sig can be decoded and saved as a .p7s file for import into Adobe Acrobat or enterprise DMS platforms.', 'archiviomd' ); ?></p>
			</div>

			<!-- Enable toggle + save -->
			<form id="archivio-cms-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $cms_status['openssl_available'] || ! $cms_status['key_available'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="cms-mode-toggle"
					       name="cms_enabled"
					       value="true"
					       <?php checked( $cms_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $cms_status['openssl_available'] || ! $cms_status['key_available'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable CMS / PKCS#7 Signing', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Produces a DER-encoded CMS SignedData blob on every post/media save. Stored in _mdsm_cms_sig post meta.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>
				<div style="margin-top:14px;display:flex;align-items:center;gap:12px;">
					<button type="submit" class="button button-primary" id="save-cms-btn"
					        <?php disabled( ! $cms_status['openssl_available'] || ! $cms_status['key_available'], true ); ?>>
						<?php esc_html_e( 'Save CMS Settings', 'archiviomd' ); ?>
					</button>
					<span class="archivio-cms-status" style="font-size:13px;"></span>
				</div>
			</form>

		</div><!-- /cms card -->

		<!-- ══════════════════════════════════════════════════════════════
		     JSON-LD / W3C DATA INTEGRITY
		     ══════════════════════════════════════════════════════════════ -->
		<h2 style="display:flex;align-items:center;gap:10px;">
			<?php esc_html_e( 'JSON-LD / W3C Data Integrity', 'archiviomd' ); ?>
			<?php echo $badge_w3c; // phpcs:ignore WordPress.Security.EscapeOutput ?>
		</h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-left:4px solid #0369a1;border-radius:4px;margin-bottom:30px;">

			<p style="margin-top:0;font-size:13px;color:#1d2327;">
				<?php esc_html_e( 'Publishes W3C Data Integrity proofs for each post and a did:web DID document listing your public keys. Signed JSON-LD documents are consumable by W3C Verifiable Credential libraries, ActivityPub implementations, and decentralised identity wallets. No blockchain, no external registry — the domain itself is the trust anchor.', 'archiviomd' ); ?>
			</p>

			<?php mdsm_ext_status_banner( $jsonld_status ); ?>

			<!-- Prerequisite checklist -->
			<?php
			$jl_ed_ready    = class_exists( 'MDSM_Ed25519_Signing' ) && MDSM_Ed25519_Signing::is_mode_enabled() && MDSM_Ed25519_Signing::is_private_key_defined() && MDSM_Ed25519_Signing::is_sodium_available();
			$jl_ecdsa_ready = class_exists( 'MDSM_ECDSA_Signing' )   && MDSM_ECDSA_Signing::status()['ready'];
			?>
			<table style="border-collapse:collapse;margin-bottom:18px;font-size:13px;">
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Ed25519 signer (eddsa-rdfc-2022)', 'archiviomd' ); ?></td>
					<td><?php if ( $jl_ed_ready ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Active — Ed25519 proof will be produced', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#646970;">&mdash; <?php esc_html_e( 'Not active (enable Ed25519 signing on the Signing tab)', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'ECDSA P-256 signer (ecdsa-rdfc-2019)', 'archiviomd' ); ?></td>
					<td><?php if ( $jl_ecdsa_ready ) : ?>
						<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Active — ECDSA P-256 proof will be produced', 'archiviomd' ); ?></span>
					<?php else : ?>
						<span style="color:#646970;">&mdash; <?php esc_html_e( 'Not active (enable ECDSA P-256 signing on the Signing tab)', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
				<?php if ( $jsonld_status['signer_available'] ) : ?>
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Active cryptosuites', 'archiviomd' ); ?></td>
					<td><span style="color:#0a7537;font-weight:600;">
						<?php echo esc_html( implode( ', ', $jsonld_status['active_suites'] ) ); ?>
					</span></td>
				</tr>
				<?php endif; ?>
			</table>

			<?php if ( ! $jsonld_status['signer_available'] ) : ?>
			<div style="background:#fff8e5;padding:12px 16px;border-left:3px solid #dba617;border-radius:3px;font-size:13px;margin-bottom:16px;">
				<?php esc_html_e( 'JSON-LD signing requires at least one of Ed25519 or ECDSA P-256 to be active on the Signing tab before this module can be enabled.', 'archiviomd' ); ?>
			</div>
			<?php endif; ?>

			<!-- Endpoints info -->
			<div style="background:#f0fdf4;border-left:3px solid #16a34a;border-radius:3px;padding:12px 16px;font-size:12px;margin-bottom:16px;">
				<strong><?php esc_html_e( 'Endpoints:', 'archiviomd' ); ?></strong>
				<table style="border-collapse:collapse;margin-top:6px;font-size:12px;">
					<tr>
						<td style="padding:2px 12px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'DID document', 'archiviomd' ); ?></td>
						<td><a href="<?php echo esc_url( home_url( '/.well-known/did.json' ) ); ?>" target="_blank"><code><?php echo esc_html( home_url( '/.well-known/did.json' ) ); ?></code></a>
						<?php if ( $jsonld_status['ready'] ) : ?>&nbsp;<span style="color:#0a7537;">&#10003; <?php esc_html_e( 'Live', 'archiviomd' ); ?></span><?php endif; ?></td>
					</tr>
					<tr>
						<td style="padding:2px 12px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Per-post JSON-LD', 'archiviomd' ); ?></td>
						<td><code>/?p={id}&amp;format=json-ld</code></td>
					</tr>
				</table>
			</div>

			<!-- Enable toggle + save -->
			<form id="archivio-jsonld-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $jsonld_status['signer_available'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="jsonld-mode-toggle"
					       name="jsonld_enabled"
					       value="true"
					       <?php checked( $jsonld_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $jsonld_status['signer_available'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable JSON-LD / W3C Data Integrity', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Produces W3C Data Integrity proof blocks on every post/media save. Proof set stored in _mdsm_jsonld_proof post meta. DID document served at /.well-known/did.json.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>
				<div style="margin-top:14px;display:flex;align-items:center;gap:12px;">
					<button type="submit" class="button button-primary" id="save-jsonld-btn"
					        <?php disabled( ! $jsonld_status['signer_available'], true ); ?>>
						<?php esc_html_e( 'Save JSON-LD Settings', 'archiviomd' ); ?>
					</button>
					<span class="archivio-jsonld-status" style="font-size:13px;"></span>
				</div>
			</form>

		</div><!-- /json-ld card -->

		<!-- ══════════════════════════════════════════════════════════════
		     DANE / DNS KEY CORROBORATION
		     ══════════════════════════════════════════════════════════════ -->
		<h2 style="display:flex;align-items:center;gap:10px;">
			<?php esc_html_e( 'DANE / DNS Key Corroboration', 'archiviomd' ); ?>
		</h2>

		<div style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-left:4px solid #0e7490;border-radius:4px;margin-bottom:30px;">

			<p style="margin-top:0;font-size:13px;color:#1d2327;">
				<?php esc_html_e( 'Publishes your Ed25519 public key as a DNSSEC-protected DNS TXT record, enabling independent key authentication without trust-on-first-use. Any verifier can cross-check the /.well-known/ed25519-pubkey.txt endpoint against DNS — a path that bypasses your web server entirely. No new key material required.', 'archiviomd' ); ?>
			</p>

			<?php mdsm_ext_status_banner( $dane_status ); ?>

			<!-- Prerequisite -->
			<table style="border-collapse:collapse;margin-bottom:18px;font-size:13px;">
				<tr>
					<td style="padding:3px 12px 3px 0;color:#646970;"><?php esc_html_e( 'Signing keys configured', 'archiviomd' ); ?></td>
					<td><?php if ( $dane_status['prereq_met'] ) : ?>
						<span style="color:#0a7537;">&#10003; <?php
						$_algo_labels = array_map( 'strtoupper', $dane_status['active_algos'] );
						echo esc_html( sprintf(
							/* translators: %s: comma-separated algorithm names */
							__( 'Active: %s', 'archiviomd' ),
							implode( ', ', $_algo_labels )
						) );
						?></span>
					<?php else : ?>
						<span style="color:#dc3232;">&#10007; <?php esc_html_e( 'No signing key constants found — define at least one in wp-config.php', 'archiviomd' ); ?></span>
					<?php endif; ?></td>
				</tr>
			</table>

			<?php if ( $dane_status['prereq_met'] ) : ?>

			<!-- DNS records to publish -->
			<div style="background:#f0f9ff;border-left:3px solid #0e7490;border-radius:3px;padding:14px 16px;font-size:12px;margin-bottom:16px;">
				<strong style="display:block;margin-bottom:8px;"><?php esc_html_e( 'Publish these DNS TXT records at your DNS provider:', 'archiviomd' ); ?></strong>
				<?php foreach ( $dane_status['records'] as $algo => $rec ) : ?>
				<div style="margin-bottom:12px;">
					<div style="font-weight:600;color:#0e7490;margin-bottom:4px;text-transform:uppercase;font-size:11px;letter-spacing:.05em;"><?php echo esc_html( $algo ); ?></div>
					<table style="border-collapse:collapse;font-size:12px;width:100%;">
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;vertical-align:top;"><?php esc_html_e( 'Name', 'archiviomd' ); ?></td>
							<td><code style="word-break:break-all;"><?php echo esc_html( $rec['dns_name'] ); ?></code></td>
						</tr>
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Type', 'archiviomd' ); ?></td>
							<td><code>TXT</code></td>
						</tr>
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'TTL', 'archiviomd' ); ?></td>
							<td><code><?php echo esc_html( (string) $dane_status['dane_ttl'] ); ?></code></td>
						</tr>
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;vertical-align:top;"><?php esc_html_e( 'Value', 'archiviomd' ); ?></td>
							<td style="display:flex;align-items:flex-start;gap:8px;">
								<code style="word-break:break-all;flex:1;"><?php echo esc_html( $rec['txt_value'] ); ?></code>
								<button type="button"
								        class="button button-small archiviomd-copy-btn"
								        data-copy="<?php echo esc_attr( $rec['txt_value'] ); ?>"
								        style="flex-shrink:0;margin-top:1px;"
								        title="<?php esc_attr_e( 'Copy value', 'archiviomd' ); ?>">
									<?php esc_html_e( 'Copy', 'archiviomd' ); ?>
								</button>
							</td>
						</tr>
					</table>
				</div>
				<?php endforeach; ?>
				<p style="margin:8px 0 0;color:#64748b;">
					<?php esc_html_e( 'Cloudflare users: add the records in the DNS tab, then enable DNSSEC with the single toggle in the DNS settings. The AD flag will be set once DNSSEC propagates.', 'archiviomd' ); ?>
				</p>
			</div>

			<!-- JSON discovery endpoint -->
			<div style="background:#f0fdf4;border-left:3px solid #16a34a;border-radius:3px;padding:10px 14px;font-size:12px;margin-bottom:16px;">
				<strong><?php esc_html_e( 'Machine-readable discovery endpoint:', 'archiviomd' ); ?></strong>
				<a href="<?php echo esc_url( $dane_status['json_endpoint'] ); ?>" target="_blank" style="margin-left:8px;">
					<code><?php echo esc_html( $dane_status['json_endpoint'] ); ?></code>
				</a>
				<span style="color:#646970;margin-left:8px;"><?php esc_html_e( '— lists all active DANE records for external verifier tooling', 'archiviomd' ); ?></span>
			</div>

			<!-- Staleness warnings -->
			<?php foreach ( $dane_status['staleness'] as $sw ) : ?>
			<div style="background:#fff8e5;padding:10px 14px;border-left:3px solid #dba617;border-radius:3px;font-size:13px;margin-bottom:12px;">
				&#9888; <?php echo esc_html( $sw ); ?>
			</div>
			<?php endforeach; ?>

			<!-- DoH resolver hint -->
			<p style="font-size:12px;color:#646970;margin-bottom:16px;">
				<?php
				printf(
					/* translators: %s: DoH URL */
					esc_html__( 'Health checks use DNS-over-HTTPS via %s. Override with the ARCHIVIOMD_DOH_URL constant in wp-config.php or the archiviomd_doh_url filter.', 'archiviomd' ),
					'<code>' . esc_html( $dane_status['doh_url'] ) . '</code>'
				);
				?>
			</p>

			<!-- Key rotation panel -->
			<div style="background:#f8f8f8;border:1px solid #ddd;border-radius:3px;padding:14px 16px;margin-bottom:16px;font-size:13px;">
				<strong style="display:block;margin-bottom:8px;"><?php esc_html_e( 'Key Rotation', 'archiviomd' ); ?></strong>
				<?php if ( $dane_status['rotation_mode'] ) : ?>
				<div style="background:#fff8e5;border-left:3px solid #dba617;border-radius:3px;padding:10px 14px;margin-bottom:10px;">
					<?php
					$elapsed_min = $dane_status['rotation_elapsed'] > 0 ? (int) ceil( $dane_status['rotation_elapsed'] / 60 ) : 0;
					printf(
						/* translators: 1: minutes elapsed 2: TTL in seconds */
						esc_html__( 'Rotation in progress — %1$d min elapsed. Steps: (1) Publish new TXT record alongside old one ✓ → (2) Wait one TTL (%2$d s) → (3) Update wp-config.php with new keypair → (4) Click "Finish Rotation" → (5) Remove old TXT record after one more TTL.', 'archiviomd' ),
						$elapsed_min,
						(int) $dane_status['dane_ttl']
					);
					?>
				</div>
				<button type="button" class="button" id="dane-finish-rotation-btn">
					<?php esc_html_e( 'Finish Rotation', 'archiviomd' ); ?>
				</button>
				<span id="dane-rotation-status" style="margin-left:10px;font-size:13px;"></span>
				<?php else : ?>
				<p style="margin:0 0 8px;color:#646970;">
					<?php esc_html_e( 'When rotating your Ed25519 keypair, use rotation mode to suppress false-positive mismatch warnings during the DNS TTL window.', 'archiviomd' ); ?>
				</p>
				<button type="button" class="button" id="dane-start-rotation-btn">
					<?php esc_html_e( 'Start Key Rotation', 'archiviomd' ); ?>
				</button>
				<span id="dane-rotation-status" style="margin-left:10px;font-size:13px;"></span>
				<?php endif; ?>
			</div>

			<!-- Health check panel -->
			<div style="margin-bottom:16px;">
				<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
					<button type="button" class="button" id="dane-health-check-btn">
						<?php esc_html_e( 'Run DNS Health Check', 'archiviomd' ); ?>
					</button>
					<span id="dane-health-spinner" class="spinner" style="float:none;visibility:hidden;margin:0;"></span>
				</div>
				<div id="dane-health-result" style="font-size:13px;display:none;background:#f9f9f9;border:1px solid #ddd;border-radius:3px;padding:12px 16px;">
					<table style="border-collapse:collapse;font-size:13px;width:100%;">
						<thead>
							<tr>
								<th style="padding:3px 14px 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'Algorithm', 'archiviomd' ); ?></th>
								<th style="padding:3px 14px 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'Record found', 'archiviomd' ); ?></th>
								<th style="padding:3px 14px 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'Key matches', 'archiviomd' ); ?></th>
								<th style="padding:3px 0 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'DNSSEC (AD)', 'archiviomd' ); ?></th>
							</tr>
						</thead>
						<tbody id="dane-health-rows">
							<tr><td colspan="4" style="color:#646970;"><?php esc_html_e( 'Run the check to see results.', 'archiviomd' ); ?></td></tr>
						</tbody>
					</table>
					<div id="dane-health-errors" style="margin-top:8px;font-size:12px;color:#7a4e00;"></div>
				</div>
			</div>

			<?php else : ?>
			<div style="background:#fff8e5;padding:12px 16px;border-left:3px solid #dba617;border-radius:3px;font-size:13px;margin-bottom:16px;">
				<?php esc_html_e( 'DANE Corroboration requires at least one signing key to be defined in wp-config.php (e.g. ARCHIVIOMD_ED25519_PUBLIC_KEY) before this module can be enabled.', 'archiviomd' ); ?>
			</div>
			<?php endif; ?>

			<!-- ══ TLSA panel ══════════════════════════════════════════════════════ -->
			<div style="background:#f8f8f8;border:1px solid #ddd;border-radius:3px;padding:14px 16px;margin-bottom:16px;font-size:13px;">
				<strong style="display:block;margin-bottom:8px;">
					<?php esc_html_e( 'TLSA / DANE-EE (RFC 6698)', 'archiviomd' ); ?>
					<span style="font-size:11px;font-weight:400;color:#646970;margin-left:6px;"><?php esc_html_e( '— ECDSA certificate only', 'archiviomd' ); ?></span>
				</strong>

				<p style="margin:0 0 10px;color:#50575e;">
					<?php esc_html_e( 'TLSA publishes a cryptographic binding of your ECDSA leaf certificate directly in DNS (type 52), independently of any CA. Verifiers can confirm your certificate without trusting a third-party CA hierarchy. Selector 1 (SubjectPublicKeyInfo) is used so the record survives certificate renewal as long as the key pair does not change.', 'archiviomd' ); ?>
				</p>

				<?php if ( $dane_status['tlsa_prereq_met'] ) : ?>

				<!-- TLSA record to publish -->
				<div style="background:#f0f9ff;border-left:3px solid #0e7490;border-radius:3px;padding:12px 14px;font-size:12px;margin-bottom:12px;">
					<strong style="display:block;margin-bottom:6px;"><?php esc_html_e( 'Publish this DNS TLSA record:', 'archiviomd' ); ?></strong>
					<table style="border-collapse:collapse;font-size:12px;width:100%;">
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Name', 'archiviomd' ); ?></td>
							<td><code style="word-break:break-all;"><?php echo esc_html( $dane_status['tlsa_record_name'] ); ?></code></td>
						</tr>
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'Type', 'archiviomd' ); ?></td>
							<td><code>TLSA</code></td>
						</tr>
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;"><?php esc_html_e( 'TTL', 'archiviomd' ); ?></td>
							<td><code><?php echo esc_html( (string) $dane_status['dane_ttl'] ); ?></code></td>
						</tr>
						<tr>
							<td style="padding:2px 14px 2px 0;color:#646970;white-space:nowrap;vertical-align:top;"><?php esc_html_e( 'Value', 'archiviomd' ); ?></td>
							<td style="display:flex;align-items:flex-start;gap:8px;">
								<code style="word-break:break-all;flex:1;"><?php echo esc_html( $dane_status['tlsa_record_value'] ); ?></code>
								<button type="button"
								        class="button button-small archiviomd-copy-btn"
								        data-copy="<?php echo esc_attr( $dane_status['tlsa_record_value'] ); ?>"
								        style="flex-shrink:0;margin-top:1px;"
								        title="<?php esc_attr_e( 'Copy value', 'archiviomd' ); ?>">
									<?php esc_html_e( 'Copy', 'archiviomd' ); ?>
								</button>
							</td>
						</tr>
					</table>
					<p style="margin:8px 0 0;color:#64748b;font-size:11px;">
						<?php esc_html_e( 'Parameters: Usage=3 (DANE-EE) · Selector=1 (SPKI) · Matching-type=1 (SHA-256). DNSSEC must be active on your zone for TLSA to provide any security benefit.', 'archiviomd' ); ?>
					</p>
				</div>

				<!-- TLSA health check -->
				<div style="margin-bottom:10px;" id="dane-tlsa-check-wrap" <?php echo $dane_status['tlsa_enabled'] ? '' : 'style="display:none;"'; ?>>
					<div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">
						<button type="button" class="button" id="dane-tlsa-check-btn">
							<?php esc_html_e( 'Run TLSA Health Check', 'archiviomd' ); ?>
						</button>
						<span id="dane-tlsa-spinner" class="spinner" style="float:none;visibility:hidden;margin:0;"></span>
					</div>
					<div id="dane-tlsa-result" style="font-size:13px;display:none;background:#f9f9f9;border:1px solid #ddd;border-radius:3px;padding:12px 16px;">
						<table style="border-collapse:collapse;font-size:13px;width:100%;">
							<thead>
								<tr>
									<th style="padding:3px 14px 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'Record found', 'archiviomd' ); ?></th>
									<th style="padding:3px 14px 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'Cert matches', 'archiviomd' ); ?></th>
									<th style="padding:3px 0 6px 0;color:#646970;font-weight:600;text-align:left;"><?php esc_html_e( 'DNSSEC (AD)', 'archiviomd' ); ?></th>
								</tr>
							</thead>
							<tbody id="dane-tlsa-rows">
								<tr><td colspan="3" style="color:#646970;"><?php esc_html_e( 'Run the check to see results.', 'archiviomd' ); ?></td></tr>
							</tbody>
						</table>
						<div id="dane-tlsa-errors" style="margin-top:8px;font-size:12px;color:#7a4e00;"></div>
					</div>
				</div>

				<!-- TLSA enable toggle -->
				<label style="display:flex;align-items:center;gap:8px;cursor:<?php echo ( ! $dane_status['mode_enabled'] || ! $dane_status['prereq_met'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="tlsa-mode-toggle"
					       name="tlsa_enabled"
					       value="true"
					       <?php checked( $dane_status['tlsa_enabled'], true ); ?>
					       <?php disabled( ! $dane_status['mode_enabled'] || ! $dane_status['prereq_met'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable TLSA Corroboration', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Includes this TLSA record in the discovery endpoint and activates the TLSA health check.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>

				<?php else : ?>
				<div style="background:#fff8e5;padding:10px 12px;border-left:3px solid #dba617;border-radius:3px;font-size:13px;">
					<?php esc_html_e( 'TLSA requires an ECDSA certificate. Configure ECDSA Enterprise Signing and upload or set ARCHIVIOMD_ECDSA_CERTIFICATE_PEM.', 'archiviomd' ); ?>
				</div>
				<?php endif; ?>
			</div><!-- /tlsa panel -->

			<!-- Enable toggle + save -->
			<form id="archivio-dane-form">
				<label style="display:flex;align-items:center;gap:10px;cursor:<?php echo ( ! $dane_status['prereq_met'] ) ? 'not-allowed' : 'pointer'; ?>;">
					<input type="checkbox"
					       id="dane-mode-toggle"
					       name="dane_enabled"
					       value="true"
					       <?php checked( $dane_status['mode_enabled'], true ); ?>
					       <?php disabled( ! $dane_status['prereq_met'], true ); ?>>
					<span>
						<strong><?php esc_html_e( 'Enable DANE DNS Corroboration', 'archiviomd' ); ?></strong>
						<span style="font-size:12px;color:#646970;display:block;">
							<?php esc_html_e( 'Augments /.well-known/ed25519-pubkey.txt with a dns-record: hint and activates the DNS health check panel.', 'archiviomd' ); ?>
						</span>
					</span>
				</label>
				<div style="margin-top:14px;display:flex;align-items:center;gap:12px;">
					<button type="submit" class="button button-primary" id="save-dane-btn"
					        <?php disabled( ! $dane_status['prereq_met'], true ); ?>>
						<?php esc_html_e( 'Save DANE Settings', 'archiviomd' ); ?>
					</button>
					<span class="archivio-dane-status" style="font-size:13px;"></span>
				</div>
			</form>

		</div><!-- /dane card -->

	</div><!-- end extended tab content -->

	<?php elseif ( $active_tab === 'help' ) : ?>
	<!-- ================================================================
	     HELP TAB
	     ================================================================ -->
	<div class="archivio-post-tab-content">
		<h2><?php esc_html_e( 'Help & Documentation', 'archiviomd' ); ?></h2>

		<div class="archivio-post-help-section" style="background:#fff8e5;padding:20px;border-left:4px solid #dba617;border-radius:4px;margin-bottom:30px;">
			<h3 style="margin-top:0;border:none;"><?php esc_html_e( '⚠️ Important: This is NOT PGP/GPG Signing', 'archiviomd' ); ?></h3>
			<p><strong><?php esc_html_e( 'This feature uses cryptographic hashing ONLY.', 'archiviomd' ); ?></strong></p>
			<p><?php esc_html_e( 'It does NOT use PGP, GPG, or any asymmetric cryptographic signing. HMAC mode adds a shared-secret keyed integrity check — it is not a digital signature and does not involve public/private key pairs.', 'archiviomd' ); ?></p>
		</div>

		<div class="archivio-post-help-section">
			<h3><?php esc_html_e( 'HMAC Integrity Mode', 'archiviomd' ); ?></h3>
			<p><?php esc_html_e( 'HMAC (Hash-based Message Authentication Code) binds a secret key to the hash. This means only someone with the ARCHIVIOMD_HMAC_KEY secret can produce or verify the hash — a standard hash can be independently computed by anyone.', 'archiviomd' ); ?></p>
			<h4><?php esc_html_e( 'Setup', 'archiviomd' ); ?></h4>
			<pre style="background:#f5f5f5;padding:15px;border-radius:4px;overflow-x:auto;"><code>// In wp-config.php, before "stop editing":
define( '<?php echo esc_html( MDSM_Hash_Helper::HMAC_KEY_CONSTANT ); ?>', 'your-random-secret-at-least-32-chars' );

// Generate a strong key on the command line:
openssl rand -base64 48</code></pre>
			<p><?php esc_html_e( 'The key is never stored in the database. Only the boolean toggle (on/off) is saved as a WordPress option.', 'archiviomd' ); ?></p>
		</div>

		<div class="archivio-post-help-section">
			<h3><?php esc_html_e( 'Choosing an Algorithm', 'archiviomd' ); ?></h3>
			<h4 style="margin-top:15px;margin-bottom:10px;font-size:13px;font-weight:600;"><?php esc_html_e( 'Standard Algorithms (Recommended for Production)', 'archiviomd' ); ?></h4>
			<ul style="line-height:2;">
				<li><strong>SHA-256</strong> – <?php esc_html_e( 'Default. 256-bit digest, 64 hex chars. Universally supported.', 'archiviomd' ); ?></li>
				<li><strong>SHA-512</strong> – <?php esc_html_e( '512-bit digest, 128 hex chars. Stronger collision resistance.', 'archiviomd' ); ?></li>
				<li><strong>SHA3-256</strong> – <?php esc_html_e( '256-bit SHA-3 (Keccak sponge), 64 hex chars. PHP 7.1+.', 'archiviomd' ); ?></li>
				<li><strong>SHA3-512</strong> – <?php esc_html_e( '512-bit SHA-3 (Keccak sponge), 128 hex chars. PHP 7.1+.', 'archiviomd' ); ?></li>
				<li><strong>BLAKE2b</strong> – <?php esc_html_e( '512-bit digest, 128 hex chars. Modern, fast. PHP 7.2+ with OpenSSL ≥ 1.1.1.', 'archiviomd' ); ?></li>
			</ul>
			<h4 style="margin-top:15px;margin-bottom:10px;font-size:13px;font-weight:600;"><?php esc_html_e( 'Experimental / Advanced Algorithms', 'archiviomd' ); ?></h4>
			<p style="background:#fff8e5;padding:10px;border-left:3px solid #dba617;border-radius:3px;font-size:12px;">
				<strong><?php esc_html_e( 'Warning:', 'archiviomd' ); ?></strong>
				<?php esc_html_e( 'These algorithms may not be available on all PHP builds and will automatically fall back to SHA-256 or BLAKE2b if unavailable.', 'archiviomd' ); ?>
			</p>
			<ul style="line-height:2;">
				<li><strong>BLAKE3</strong> – <?php esc_html_e( '256-bit output. Extremely fast, parallel hashing. PHP 8.1+ or pure-PHP fallback.', 'archiviomd' ); ?></li>
				<li><strong>SHAKE128</strong> – <?php esc_html_e( 'SHA-3 XOF with 256-bit output. Variable-length output. PHP 7.1+ native or fallback.', 'archiviomd' ); ?></li>
				<li><strong>SHAKE256</strong> – <?php esc_html_e( 'SHA-3 XOF with 512-bit output. Variable-length output. PHP 7.1+ native or fallback.', 'archiviomd' ); ?></li>
			</ul>
			<p><?php esc_html_e( 'Changing the algorithm only affects new hashes. Old hashes verify with the algorithm used when they were created.', 'archiviomd' ); ?></p>
		</div>

		<div class="archivio-post-help-section">
			<h3><?php esc_html_e( 'Shortcode Usage', 'archiviomd' ); ?></h3>
			<pre style="background:#f5f5f5;padding:15px;border-radius:4px;overflow-x:auto;"><code>[hash_verify]
[hash_verify post_id="42"]</code></pre>
		</div>

		<div class="archivio-post-help-section">
			<h3><?php esc_html_e( 'Offline Verification', 'archiviomd' ); ?></h3>
			<p><?php esc_html_e( 'Standard mode – run the command for the algorithm shown in the verification file:', 'archiviomd' ); ?></p>
			<pre style="background:#f5f5f5;padding:15px;border-radius:4px;overflow-x:auto;"><code># SHA-256
echo -n "post_id:123\nauthor_id:1\ncontent:\nYour content" | sha256sum

# SHA-512
echo -n "..." | sha512sum

# SHA3-256
echo -n "..." | openssl dgst -sha3-256

# SHA3-512
echo -n "..." | openssl dgst -sha3-512

# BLAKE2b
echo -n "..." | b2sum -l 512</code></pre>
			<p><?php esc_html_e( 'HMAC mode – the verification file includes the openssl hmac command with a placeholder for your secret key:', 'archiviomd' ); ?></p>
			<pre style="background:#f5f5f5;padding:15px;border-radius:4px;overflow-x:auto;"><code>echo -n "..." | openssl dgst -sha256 -hmac "YOUR_SECRET_KEY"</code></pre>
		</div>

		<div class="archivio-post-help-section">
			<h3><?php esc_html_e( 'Badge Status Meanings', 'archiviomd' ); ?></h3>
			<ul style="line-height:2;">
				<li><strong style="color:#0a7537;"><?php esc_html_e( 'Verified:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'Current content matches the stored hash.', 'archiviomd' ); ?></li>
				<li><strong style="color:#d73a49;"><?php esc_html_e( 'Unverified:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'Content has changed since hash generation.', 'archiviomd' ); ?></li>
				<li><strong style="color:#6a737d;"><?php esc_html_e( 'Not Signed:', 'archiviomd' ); ?></strong>
					<?php esc_html_e( 'No hash generated yet.', 'archiviomd' ); ?></li>
			</ul>
		</div>

		<div class="archivio-post-help-section">
			<h3><?php esc_html_e( 'Backward Compatibility', 'archiviomd' ); ?></h3>
			<p><?php esc_html_e( 'Hashes generated before v1.3.0 are stored as plain SHA-256 hex strings. Hashes from v1.3.0 are stored as "algo:hex". Hashes from v1.4.0 HMAC mode are stored as "hmac-algo:hex". All three formats coexist and verify correctly without any migration.', 'archiviomd' ); ?></p>
		</div>

		<div class="archivio-post-help-section" style="background:#e7f3ff;padding:20px;border-left:4px solid #2271b1;border-radius:4px;">
			<h3><?php esc_html_e( 'Need More Help?', 'archiviomd' ); ?></h3>
			<p><a href="https://mountainviewprovisions.com/ArchivioMD" target="_blank" rel="noopener">https://mountainviewprovisions.com/ArchivioMD</a></p>
		</div>
	</div>
	<?php endif; ?>

	</div><!-- .archivio-post-content -->
</div><!-- .wrap -->

<?php wp_add_inline_style( 'archivio-post-admin', '.archivio-post-admin .archivio-post-content { margin-top: 20px; }\n.archivio-post-tab-content {\n\tbackground: #fff;\n\tpadding: 20px;\n\tborder: 1px solid #ccd0d4;\n\tborder-radius: 4px;\n}\n.archivio-post-help-section { margin-bottom: 30px; }\n.archivio-post-help-section h3 {\n\tmargin-top: 0;\n\tpadding-bottom: 10px;\n\tborder-bottom: 2px solid #2271b1;\n}\n.archivio-post-help-section h4 { margin-top: 20px; color: #2271b1; }\n\n#audit-log-table { width: 100%; border-collapse: collapse; margin-top: 20px; }\n#audit-log-table th,\n#audit-log-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n#audit-log-table th { background: #f9f9f9; font-weight: 600; color: #1d2327; }\n#audit-log-table tr:hover { background: #f9f9f9; }\n\n.audit-log-event-generated { color: #0a7537; }\n.audit-log-event-verified   { color: #2271b1; }\n.audit-log-event-unverified { color: #d73a49; }\n.audit-log-hash  { font-family: monospace; font-size: 12px; word-break: break-all; }\n.audit-log-algo  { font-family: monospace; font-size: 11px; }\n.audit-log-mode-hmac     { color: #7c3aed; font-weight: 600; }\n.audit-log-mode-standard { color: #646970; }\n#audit-log-pagination button { margin: 0 5px; }\n.audit-log-type-post  { color: #2271b1; font-size: 11px; font-weight: 600; }\n.audit-log-type-page  { color: #7c3aed; font-size: 11px; font-weight: 600; }' ); ?>

<?php
ob_start();
?>
jQuery(document).ready(function($) {

	// ── Force checkbox states to match stored values ────────────────────
	// Fix for issue where checkboxes appear checked but aren't actually checked
	var checkboxStates = {
		'auto-generate': archivioPostData.checkboxStates['auto-generate'],
		'show-badge': archivioPostData.checkboxStates['show-badge'],
		'show-badge-posts': archivioPostData.checkboxStates['show-badge-posts'],
		'show-badge-pages': archivioPostData.checkboxStates['show-badge-pages']
	};
	
	$.each(checkboxStates, function(id, shouldBeChecked) {
		var $checkbox = $('#' + id);
		if ($checkbox.length) {
			var isChecked = $checkbox.prop('checked');
			if (isChecked !== shouldBeChecked) {
				$checkbox.prop('checked', shouldBeChecked);
			}
		}
	});

	// ── HMAC form ────────────────────────────────────────────────────
	$('#archivio-hmac-form').on('submit', function(e) {
		e.preventDefault();

		var $btn    = $('#save-hmac-btn');
		var $status = $('.archivio-hmac-status');
		var enabled = $('#hmac-mode-toggle').is(':checked');

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:    'archivio_post_save_hmac_settings',
				nonce:     archivioPostData.nonce,
				hmac_mode: enabled ? 'true' : 'false'
			},
			success: function(response) {
				if (response.success) {
					var msg = '<span style="color:#0a7537;">✓ ' + response.data.message + '</span>';
					if (response.data.notice_level === 'warning') {
						msg += '<br><span style="color:#dba617;">⚠ ' + response.data.notice_message + '</span>';
					}
					$status.html(msg);
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">✗ ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});


	// ── RSA: PEM file uploads ────────────────────────────────────────────
	function rsaUpload( inputId, btnId, statusId, ajaxAction, fileField ) {
		$('#' + btnId).on('click', function() {
			var file = document.getElementById(inputId) ? document.getElementById(inputId).files[0] : null;
			if (!file) { $('#' + statusId).html('<span style="color:#dc3232;"><?php echo esc_js( __( 'Select a .pem file first.', 'archiviomd' ) ); ?></span>'); return; }
			var $btn = $(this).prop('disabled', true).text('<?php echo esc_js( __( 'Uploading…', 'archiviomd' ) ); ?>');
			var fd = new FormData();
			fd.append('action', ajaxAction);
			fd.append('nonce', archivioPostData.nonce);
			fd.append(fileField, file);
			$.ajax({ url: archivioPostData.ajaxUrl, type: 'POST', data: fd, processData: false, contentType: false,
				success: function(r) {
					if (r.success) { $('#' + statusId).html('<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>'); setTimeout(function(){ location.reload(); }, 1200); }
					else { $('#' + statusId).html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>'); $btn.prop('disabled',false).text('<?php echo esc_js(__('Upload','archiviomd')); ?>'); }
				},
				error: function() { $('#'+statusId).html('<span style="color:#dc3232;"><?php echo esc_js(__('Upload failed.','archiviomd')); ?></span>'); $btn.prop('disabled',false).text('<?php echo esc_js(__('Upload','archiviomd')); ?>'); }
			});
		});
	}
	rsaUpload('rsa-key-upload',  'rsa-key-upload-btn',  'rsa-key-status',  'archivio_rsa_upload_key',  'rsa_key_pem');
	rsaUpload('rsa-cert-upload', 'rsa-cert-upload-btn', 'rsa-cert-status', 'archivio_rsa_upload_cert', 'rsa_cert_pem');

	$('.rsa-clear-btn').on('click', function() {
		var action = $(this).data('action');
		var $btn = $(this).prop('disabled', true);
		$.post(archivioPostData.ajaxUrl, { action: action, nonce: archivioPostData.nonce }, function(r) {
			if (r.success) { location.reload(); } else { $btn.prop('disabled', false); alert(r.data.message); }
		});
	});

	// ── RSA form ─────────────────────────────────────────────────────────
	$('#archivio-rsa-form').on('submit', function(e) {
		e.preventDefault();
		var $btn    = $('#save-rsa-btn');
		var $status = $('.archivio-rsa-status');
		var enabled = $('#rsa-mode-toggle').is(':checked');
		var scheme  = $('input[name="rsa_scheme"]:checked').val() || 'rsa-pss-sha256';
		$btn.prop('disabled', true);
		$status.html('<?php echo esc_js(__('Saving…','archiviomd')); ?>');
		$.post(archivioPostData.ajaxUrl, {
			action:      'archivio_rsa_save_settings',
			nonce:       archivioPostData.nonce,
			rsa_enabled: enabled ? 'true' : 'false',
			rsa_scheme:  scheme
		}, function(r) {
			$btn.prop('disabled', false);
			if (r.success) {
				var msg = '<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>';
				if (r.data.notice) { msg += '<br><span style="color:#646970;font-size:12px;">' + r.data.notice + '</span>'; }
				$status.html(msg);
				setTimeout(function(){ $status.fadeOut(function(){ $(this).html('').show(); }); }, 5000);
			} else {
				$status.html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>');
			}
		}).fail(function(){ $btn.prop('disabled',false); $status.html('<span style="color:#dc3232;"><?php echo esc_js(__('Request failed.','archiviomd')); ?></span>'); });
	});

	// ── CMS form ──────────────────────────────────────────────────────────
	$('#archivio-cms-form').on('submit', function(e) {
		e.preventDefault();
		var $btn    = $('#save-cms-btn');
		var $status = $('.archivio-cms-status');
		var enabled = $('#cms-mode-toggle').is(':checked');
		$btn.prop('disabled', true);
		$status.html('<?php echo esc_js(__('Saving…','archiviomd')); ?>');
		$.post(archivioPostData.ajaxUrl, {
			action:      'archivio_cms_save_settings',
			nonce:       archivioPostData.nonce,
			cms_enabled: enabled ? 'true' : 'false'
		}, function(r) {
			$btn.prop('disabled', false);
			if (r.success) {
				var msg = '<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>';
				if (r.data.notice) { msg += '<br><span style="color:#646970;font-size:12px;">' + r.data.notice + '</span>'; }
				$status.html(msg);
				setTimeout(function(){ $status.fadeOut(function(){ $(this).html('').show(); }); }, 5000);
			} else {
				$status.html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>');
			}
		}).fail(function(){ $btn.prop('disabled',false); $status.html('<span style="color:#dc3232;"><?php echo esc_js(__('Request failed.','archiviomd')); ?></span>'); });
	});

	// ── JSON-LD form ──────────────────────────────────────────────────────
	$('#archivio-jsonld-form').on('submit', function(e) {
		e.preventDefault();
		var $btn    = $('#save-jsonld-btn');
		var $status = $('.archivio-jsonld-status');
		var enabled = $('#jsonld-mode-toggle').is(':checked');
		$btn.prop('disabled', true);
		$status.html('<?php echo esc_js(__('Saving…','archiviomd')); ?>');
		$.post(archivioPostData.ajaxUrl, {
			action:         'archivio_jsonld_save_settings',
			nonce:          archivioPostData.nonce,
			jsonld_enabled: enabled ? 'true' : 'false'
		}, function(r) {
			$btn.prop('disabled', false);
			if (r.success) {
				var msg = '<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>';
				if (r.data.suites) { msg += '<br><span style="color:#646970;font-size:12px;"><?php echo esc_js(__('Active suites:','archiviomd')); ?> ' + r.data.suites + '</span>'; }
				$status.html(msg);
				setTimeout(function(){ $status.fadeOut(function(){ $(this).html('').show(); }); }, 5000);
			} else {
				$status.html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>');
			}
		}).fail(function(){ $btn.prop('disabled',false); $status.html('<span style="color:#dc3232;"><?php echo esc_js(__('Request failed.','archiviomd')); ?></span>'); });
	});

	// ── Ed25519 form ─────────────────────────────────────────────────
	$('#archivio-ed25519-form').on('submit', function(e) {
		e.preventDefault();

		var $btn    = $('#save-ed25519-btn');
		var $status = $('.archivio-ed25519-status');
		var enabled = $('#ed25519-mode-toggle').is(':checked');

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:          'archivio_post_save_ed25519_settings',
				nonce:           archivioPostData.nonce,
				ed25519_enabled: enabled ? 'true' : 'false'
			},
			success: function(response) {
				if (response.success) {
					var msg = '<span style="color:#0a7537;">✓ ' + response.data.message + '</span>';
					if (response.data.notice_level === 'warning') {
						msg += '<br><span style="color:#dba617;">⚠ ' + response.data.notice_message + '</span>';
					}
					$status.html(msg);
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">✗ ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});

	// ── Ed25519 in-browser keypair generator ─────────────────────────
	$('#ed25519-keygen-btn').on('click', function() {
		var $btn = $(this);
		$btn.prop('disabled', true).text('Generating\u2026');

		function bytesToHex(bytes) {
			return Array.from(new Uint8Array(bytes))
				.map(function(b) { return b.toString(16).padStart(2, '0'); })
				.join('');
		}

		if (!window.crypto || !window.crypto.subtle) {
			alert('window.crypto.subtle is not available. Use the PHP CLI method shown above.');
			$btn.prop('disabled', false).text('Generate Keypair in Browser');
			return;
		}

		window.crypto.subtle.generateKey(
			{ name: 'Ed25519' },
			true,
			['sign', 'verify']
		).then(function(kp) {
			return Promise.all([
				window.crypto.subtle.exportKey('raw',   kp.publicKey),
				window.crypto.subtle.exportKey('pkcs8', kp.privateKey)
			]);
		}).then(function(results) {
			var pubHex  = bytesToHex(results[0]);
			var pkcs8   = new Uint8Array(results[1]);
			var seed    = pkcs8.slice(pkcs8.length - 32);
			var privHex = bytesToHex(seed) + pubHex;

			$('#ed25519-privkey-out').val(privHex);
			$('#ed25519-pubkey-out').val(pubHex);
			$('#ed25519-keygen-output').show();
			$btn.prop('disabled', false).text('Regenerate Keypair');
		}).catch(function(err) {
			alert('Browser Ed25519 generation failed (' + err.message + '). Use the PHP CLI method shown above.');
			$btn.prop('disabled', false).text('Generate Keypair in Browser');
		});
	});

	// ── DSSE form ────────────────────────────────────────────────────
	$('#archivio-dsse-form').on('submit', function(e) {
		e.preventDefault();

		var $btn     = $('#save-dsse-btn');
		var $status  = $('.archivio-dsse-status');
		var dsseon   = $('#dsse-mode-toggle').is(':checked');
		// Ed25519 master toggle must be on for DSSE to be meaningful.
		var ed25519on = $('#ed25519-mode-toggle').is(':checked');

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:          'archivio_post_save_ed25519_settings',
				nonce:           archivioPostData.nonce,
				ed25519_enabled: ed25519on ? 'true' : 'false',
				dsse_enabled:    dsseon    ? 'true' : 'false'
			},
			success: function(response) {
				if (response.success) {
					var saved = response.data.dsse_enabled;
					var msg   = saved
						? '<span style="color:#0a7537;">✓ DSSE Envelope Mode enabled. New signatures will include a DSSE envelope.</span>'
						: '<span style="color:#646970;">✓ DSSE Envelope Mode disabled.</span>';
					if (response.data.notice_level === 'error') {
						msg = '<span style="color:#d73a49;">✗ ' + response.data.notice_message + '</span>';
					}
					$status.html(msg);
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">✗ ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});

	// ── Algorithm form ───────────────────────────────────────────────
	$('#archivio-algorithm-form').on('submit', function(e) {
		e.preventDefault();

		var $btn    = $('#save-algorithm-btn');
		var $status = $('.archivio-algorithm-status');
		var algo    = $('input[name="algorithm"]:checked').val();

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:    'archivio_post_save_algorithm',
				nonce:     archivioPostData.nonce,
				algorithm: algo
			},
			success: function(response) {
				if (response.success) {
					var msg = '<span style="color:#0a7537;">✓ ' + response.data.message + '</span>';
					if (response.data.warning) {
						msg += '<br><span style="color:#d73a49;">⚠ ' + response.data.warning + '</span>';
					}
					$status.html(msg);
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">✗ ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});

	// ── Settings form ────────────────────────────────────────────────
	$('#archivio-post-settings-form').on('submit', function(e) {
		e.preventDefault();

		var $btn    = $('#save-settings-btn');
		var $status = $('.archivio-post-save-status');
		
		var autoGenChecked = $('#auto-generate').is(':checked');

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');
		
		var postData = {
			action:           'archivio_post_save_settings',
			nonce:            archivioPostData.nonce,
			auto_generate:    autoGenChecked ? 'true' : 'false',
			show_badge:       $('#show-badge').is(':checked')       ? 'true' : 'false',
			show_badge_posts: $('#show-badge-posts').is(':checked') ? 'true' : 'false',
			show_badge_pages: $('#show-badge-pages').is(':checked') ? 'true' : 'false'
		};

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: postData,
			success: function(response) {
				if (response.success) {
					$status.html('<span style="color:#0a7537;">✓ ' + response.data.message + '</span>');
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function(xhr, status, error) {
				$status.html('<span style="color:#d73a49;">✗ ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 3000);
			}
		});
	});


	// Audit log functions are in archivio-post-admin.js

	// ── CSV Export ───────────────────────────────────────────────────
	$('#export-audit-csv').on('click', function() {
		var $btn         = $(this);
		var originalHtml = $btn.html();

		$btn.prop('disabled', true).html(
			'<span class="spinner is-active" style="float:none;margin:0 5px 0 0;"></span>Exporting...');

		var form = $('<form>', { method: 'POST', action: archivioPostData.ajaxUrl });
		form.append($('<input>', { type: 'hidden', name: 'action', value: 'archivio_post_export_audit_csv' }));
		form.append($('<input>', { type: 'hidden', name: 'nonce',  value: archivioPostData.nonce }));
		$('body').append(form);
		form.submit();
		form.remove();

		setTimeout(function() { $btn.prop('disabled', false).html(originalHtml); }, 2000);
	});

	// ── Fix Settings Button ────────────────────────────────────────
	$('#fix-settings-btn').on('click', function() {
		var $btn = $(this);
		var $status = $('.fix-settings-status');

		if (!confirm('This will enable Auto-Generate and all badge settings. Continue?')) {
			return;
		}

		$btn.prop('disabled', true).text('Enabling...');
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action: 'archivio_post_fix_settings',
				nonce:  archivioPostData.nonce
			},
			success: function(response) {
				if (response.success) {
					$status.html('<span style="color:#0a7537;">✓ ' + response.data.message + '</span>');
					// Force update the checkboxes
					$('#auto-generate').prop('checked', true);
					$('#show-badge').prop('checked', true);
					$('#show-badge-posts').prop('checked', true);
					$('#show-badge-pages').prop('checked', true);
					// Reload page after 2 seconds
					setTimeout(function() {
						location.reload();
					}, 2000);
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || 'Error') + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">✗ Error occurred</span>');
			},
			complete: function() {
				$btn.prop('disabled', false).text('Enable All Settings');
			}
		});
	});

	// ── Recreate table ───────────────────────────────────────────────
	$('#recreate-table-btn').on('click', function() {
		var $btn    = $(this);
		var $status = $('.recreate-table-status');

		if (!confirm('Recreate the audit log table? Existing entries will be preserved.')) { return; }

		$btn.prop('disabled', true).text('Recreating...');
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action: 'archivio_post_recreate_table',
				nonce:  archivioPostData.nonce
			},
			success: function(response) {
				if (response.success) {
					$status.html('<span style="color:#0a7537;">✓ ' + response.data.message + '</span>');
				} else {
					$status.html('<span style="color:#d73a49;">✗ ' + (response.data.message || 'Error') + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">✗ Error occurred</span>');
			},
			complete: function() {
				$btn.prop('disabled', false).text('Recreate Database Table');
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});

	// ── SLH-DSA: keypair generator ───────────────────────────────────
	$('#slhdsa-keygen-btn').on('click', function() {
		var $btn     = $(this);
		var $spinner = $('#slhdsa-keygen-spinner');
		var param    = $('#slhdsa-param-select').val() || 'SLH-DSA-SHA2-128s';

		$btn.prop('disabled', true);
		$spinner.show();

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:        'archivio_slhdsa_generate_keypair',
				nonce:         archivioPostData.nonce,
				slhdsa_param:  param
			},
			timeout: 120000,  // pure-PHP keygen can take a few seconds
			success: function(response) {
				if (response.success) {
					$('#slhdsa-privkey-out').val(response.data.private_key);
					$('#slhdsa-pubkey-out').val(response.data.public_key);
					$('#slhdsa-wpconfig-out').val(response.data.wp_config);
					$('#slhdsa-keygen-output').show();
					$btn.text('Regenerate Keypair');
				} else {
					alert('Keypair generation failed: ' + (response.data.message || 'Unknown error'));
				}
			},
			error: function(xhr, status) {
				alert('Request failed (' + status + '). The server may have timed out — try again or generate offline.');
			},
			complete: function() {
				$btn.prop('disabled', false);
				$spinner.hide();
			}
		});
	});

	// ── SLH-DSA: enable/disable form ─────────────────────────────────
	$('#archivio-slhdsa-form').on('submit', function(e) {
		e.preventDefault();

		var $btn    = $('#save-slhdsa-btn');
		var $status = $('.archivio-slhdsa-status');
		var enabled = $('#slhdsa-mode-toggle').is(':checked');
		var param   = $('#slhdsa-param-select').val() || 'SLH-DSA-SHA2-128s';

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:         'archivio_slhdsa_save_settings',
				nonce:          archivioPostData.nonce,
				slhdsa_enabled: enabled ? 'true' : 'false',
				slhdsa_param:   param
			},
			success: function(response) {
				if (response.success) {
					var msg = '<span style="color:#0a7537;">\u2713 ' + response.data.message + '</span>';
					if (response.data.notice_level === 'warning') {
						msg += '<br><span style="color:#dba617;">\u26a0 ' + response.data.notice_message + '</span>';
					}
					$status.html(msg);
					// Enable the DSSE toggle if signing is now on.
					$('#slhdsa-dsse-mode-toggle').prop('disabled', !enabled);
					$('#save-slhdsa-dsse-btn').prop('disabled', !enabled);
				} else {
					$status.html('<span style="color:#d73a49;">\u2717 ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">\u2717 ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});

	// ── SLH-DSA: DSSE sub-toggle ──────────────────────────────────────
	$('#archivio-slhdsa-dsse-form').on('submit', function(e) {
		e.preventDefault();

		var $btn    = $('#save-slhdsa-dsse-btn');
		var $status = $('.archivio-slhdsa-dsse-status');
		var dsseon  = $('#slhdsa-dsse-mode-toggle').is(':checked');
		var signon  = $('#slhdsa-mode-toggle').is(':checked');

		$btn.prop('disabled', true);
		$status.html('<span class="spinner is-active" style="float:none;"></span>');

		$.ajax({
			url:  archivioPostData.ajaxUrl,
			type: 'POST',
			data: {
				action:               'archivio_slhdsa_save_settings',
				nonce:                archivioPostData.nonce,
				slhdsa_enabled:       signon  ? 'true' : 'false',
				slhdsa_dsse_enabled:  dsseon  ? 'true' : 'false'
			},
			success: function(response) {
				if (response.success) {
					var saved = response.data.dsse_enabled;
					var msg   = saved
						? '<span style="color:#0a7537;">\u2713 SLH-DSA DSSE Envelope Mode enabled.</span>'
						: '<span style="color:#646970;">\u2713 SLH-DSA DSSE Envelope Mode disabled.</span>';
					if (response.data.notice_level === 'error') {
						msg = '<span style="color:#d73a49;">\u2717 ' + response.data.notice_message + '</span>';
					}
					$status.html(msg);
				} else {
					$status.html('<span style="color:#d73a49;">\u2717 ' + (response.data.message || archivioPostData.strings.error) + '</span>');
				}
			},
			error: function() {
				$status.html('<span style="color:#d73a49;">\u2717 ' + archivioPostData.strings.error + '</span>');
			},
			complete: function() {
				$btn.prop('disabled', false);
				setTimeout(function() {
					$status.fadeOut(function() { $(this).html('').show(); });
				}, 5000);
			}
		});
	});

	// ── ECDSA: PEM file uploads ──────────────────────────────────────────
	function ecdsaUpload( inputId, btnId, statusId, ajaxAction, fileField ) {
		$('#' + btnId).on('click', function() {
			var file = document.getElementById(inputId) ? document.getElementById(inputId).files[0] : null;
			if (!file) { $('#' + statusId).html('<span style="color:#dc3232;"><?php echo esc_js( __( 'Select a .pem file first.', 'archiviomd' ) ); ?></span>'); return; }
			var $btn = $(this).prop('disabled', true).text('<?php echo esc_js( __( 'Uploading…', 'archiviomd' ) ); ?>');
			var fd = new FormData();
			fd.append('action', ajaxAction);
			fd.append('nonce', archivioPostData.nonce);
			fd.append(fileField, file);
			$.ajax({ url: archivioPostData.ajaxUrl, type: 'POST', data: fd, processData: false, contentType: false,
				success: function(r) {
					if (r.success) { $('#' + statusId).html('<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>'); setTimeout(function(){ location.reload(); }, 1200); }
					else { $('#' + statusId).html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>'); $btn.prop('disabled',false).text('<?php echo esc_js(__('Upload','archiviomd')); ?>'); }
				},
				error: function() { $('#'+statusId).html('<span style="color:#dc3232;"><?php echo esc_js(__('Upload failed.','archiviomd')); ?></span>'); $btn.prop('disabled',false).text('<?php echo esc_js(__('Upload','archiviomd')); ?>'); }
			});
		});
	}
	ecdsaUpload('ecdsa-key-upload',  'ecdsa-key-upload-btn',  'ecdsa-key-status',  'archivio_ecdsa_upload_key',  'ecdsa_key_pem');
	ecdsaUpload('ecdsa-cert-upload', 'ecdsa-cert-upload-btn', 'ecdsa-cert-status', 'archivio_ecdsa_upload_cert', 'ecdsa_cert_pem');
	ecdsaUpload('ecdsa-ca-upload',   'ecdsa-ca-upload-btn',   'ecdsa-ca-status',   'archivio_ecdsa_upload_ca',   'ecdsa_ca_pem');

	$('.ecdsa-clear-btn').on('click', function() {
		var action = $(this).data('action');
		var $btn = $(this).prop('disabled', true);
		$.post(archivioPostData.ajaxUrl, { action: action, nonce: archivioPostData.nonce }, function(r) {
			if (r.success) { location.reload(); } else { $btn.prop('disabled', false); alert(r.data.message); }
		});
	});

	$('#archivio-ecdsa-form').on('submit', function(e) {
		e.preventDefault();
		var $btn = $('#save-ecdsa-btn'), $status = $('.archivio-ecdsa-status');
		var enabled = $('#ecdsa-mode-toggle').is(':checked');
		$btn.prop('disabled', true); $status.html('<?php echo esc_js(__('Saving…','archiviomd')); ?>');
		$.post(archivioPostData.ajaxUrl, { action:'archivio_ecdsa_save_settings', nonce:archivioPostData.nonce, ecdsa_enabled: enabled?'true':'false' }, function(r) {
			$btn.prop('disabled', false);
			if (r.success) {
				$status.html('<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>');
				$('#ecdsa-dsse-mode-toggle').prop('disabled', !enabled); $('#save-ecdsa-dsse-btn').prop('disabled', !enabled);
				setTimeout(function(){ $status.fadeOut(function(){ $(this).html('').show(); }); }, 4000);
			} else { $status.html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>'); }
		}).fail(function(){ $btn.prop('disabled',false); $status.html('<span style="color:#dc3232;"><?php echo esc_js(__('Request failed.','archiviomd')); ?></span>'); });
	});

	$('#archivio-ecdsa-dsse-form').on('submit', function(e) {
		e.preventDefault();
		var $btn = $('#save-ecdsa-dsse-btn'), $status = $('.archivio-ecdsa-dsse-status');
		var dsseon = $('#ecdsa-dsse-mode-toggle').is(':checked'), signon = $('#ecdsa-mode-toggle').is(':checked');
		$btn.prop('disabled', true); $status.html('<?php echo esc_js(__('Saving…','archiviomd')); ?>');
		$.post(archivioPostData.ajaxUrl, { action:'archivio_ecdsa_save_settings', nonce:archivioPostData.nonce, ecdsa_enabled:signon?'true':'false', dsse_enabled:dsseon?'true':'false' }, function(r) {
			$btn.prop('disabled', false);
			if (r.success) {
				$status.html(r.data.dsse_enabled ? '<span style="color:#0a7537;">&#10003; <?php echo esc_js(__('ECDSA DSSE Envelope Mode enabled.','archiviomd')); ?></span>' : '<span style="color:#646970;">&#10003; <?php echo esc_js(__('ECDSA DSSE Envelope Mode disabled.','archiviomd')); ?></span>');
				setTimeout(function(){ $status.fadeOut(function(){ $(this).html('').show(); }); }, 4000);
			} else { $status.html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>'); }
		}).fail(function(){ $btn.prop('disabled',false); $status.html('<span style="color:#dc3232;"><?php echo esc_js(__('Request failed.','archiviomd')); ?></span>'); });
	});


	// ── DANE / DNS Key Corroboration ────────────────────────────────────────

	// Copy-to-clipboard for DNS TXT values.
	$(document).on('click', '.archiviomd-copy-btn', function() {
		var $btn = $(this);
		var text = $btn.data('copy');
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(function() {
				var orig = $btn.text();
				$btn.text('<?php echo esc_js( __( 'Copied!', 'archiviomd' ) ); ?>').prop('disabled', true);
				setTimeout(function(){ $btn.text(orig).prop('disabled', false); }, 2000);
			}).catch(function() {
				prompt('<?php echo esc_js( __( 'Copy the value below:', 'archiviomd' ) ); ?>', text);
			});
		} else {
			prompt('<?php echo esc_js( __( 'Copy the value below:', 'archiviomd' ) ); ?>', text);
		}
	});

	$('#archivio-dane-form').on('submit', function(e) {
		e.preventDefault();
		var $btn = $('#save-dane-btn'), $status = $('.archivio-dane-status');
		var enabled = $('#dane-mode-toggle').is(':checked');
		var tlsaEnabled = $('#tlsa-mode-toggle').is(':checked');
		$btn.prop('disabled', true); $status.html('<?php echo esc_js( __( 'Saving\u2026', 'archiviomd' ) ); ?>');
		$.post(archivioPostData.ajaxUrl, { action: 'archivio_dane_save_settings', nonce: archivioPostData.nonce, dane_enabled: enabled ? 'true' : 'false', tlsa_enabled: tlsaEnabled ? 'true' : 'false' }, function(r) {
			$btn.prop('disabled', false);
			if (r.success) {
				$status.html('<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>');
				// Show/hide the TLSA health check panel based on the returned state.
				if (r.data.tlsa_enabled) {
					$('#dane-tlsa-check-wrap').show();
				} else {
					$('#dane-tlsa-check-wrap').hide();
				}
				setTimeout(function(){ $status.fadeOut(function(){ $(this).html('').show(); }); }, 4000);
			} else { $status.html('<span style="color:#dc3232;">&#10007; ' + r.data.message + '</span>'); }
		}).fail(function(){ $btn.prop('disabled', false); $status.html('<span style="color:#dc3232;"><?php echo esc_js( __( 'Request failed.', 'archiviomd' ) ); ?></span>'); });
	});

	// TLSA health check.
	$('#dane-tlsa-check-btn').on('click', function() {
		var $btn = $(this).prop('disabled', true);
		var $spinner = $('#dane-tlsa-spinner').css('visibility', 'visible');
		$('#dane-tlsa-result').show();
		$('#dane-tlsa-rows').html('<tr><td colspan="3" style="color:#646970;"><?php echo esc_js( __( 'Checking…', 'archiviomd' ) ); ?></td></tr>');
		$('#dane-tlsa-errors').html('');
		$.post(archivioPostData.ajaxUrl, { action: 'archivio_dane_tlsa_check', nonce: archivioPostData.nonce }, function(r) {
			$btn.prop('disabled', false); $spinner.css('visibility', 'hidden');
			if (r.success) {
				var d    = r.data;
				var yes  = '<span style="color:#0a7537;">✓ <?php echo esc_js( __( 'Yes', 'archiviomd' ) ); ?></span>';
				var no   = '<span style="color:#dc3232;">✗ <?php echo esc_js( __( 'No', 'archiviomd' ) ); ?></span>';
				var warn = '<span style="color:#b45309;">⚠ <?php echo esc_js( __( 'Not validated', 'archiviomd' ) ); ?></span>';
				var skip = '<span style="color:#646970;">— <?php echo esc_js( __( 'Not checked', 'archiviomd' ) ); ?></span>';
				var dnssecCell = d.dnssec_checked ? (d.dnssec_ad ? yes : warn) : skip;
				var row = '<tr>';
				row += '<td style="padding:3px 14px 3px 0;">' + (d.found ? yes : no) + '</td>';
				row += '<td style="padding:3px 14px 3px 0;">' + (d.cert_match ? yes : no) + '</td>';
				row += '<td style="padding:3px 0 3px 0;">' + dnssecCell + '</td>';
				row += '</tr>';
				$('#dane-tlsa-rows').html(row);
				$('#dane-tlsa-errors').html(d.error ? '▶ ' + d.error : '');
			} else {
				$('#dane-tlsa-rows').html('<tr><td colspan="3" style="color:#dc3232;"><?php echo esc_js( __( 'TLSA check failed.', 'archiviomd' ) ); ?></td></tr>');
				if (r.data && r.data.message) { $('#dane-tlsa-errors').html(r.data.message); }
			}
		}).fail(function(){ $btn.prop('disabled', false); $spinner.css('visibility', 'hidden'); alert('<?php echo esc_js( __( 'TLSA check request failed.', 'archiviomd' ) ); ?>'); });
	});


	$('#dane-start-rotation-btn').on('click', function() {
		var $btn = $(this).prop('disabled', true), $s = $('#dane-rotation-status').html('<?php echo esc_js( __( 'Starting…', 'archiviomd' ) ); ?>');
		$.post(archivioPostData.ajaxUrl, { action: 'archivio_dane_start_rotation', nonce: archivioPostData.nonce }, function(r) {
			$btn.prop('disabled', false);
			if (r.success) { $s.html('<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>'); setTimeout(function(){ location.reload(); }, 2000); }
			else { $s.html('<span style="color:#dc3232;">&#10007; ' + (r.data ? r.data.message : '') + '</span>'); }
		}).fail(function(){ $btn.prop('disabled', false); $s.html('<span style="color:#dc3232;"><?php echo esc_js( __( 'Request failed.', 'archiviomd' ) ); ?></span>'); });
	});

	$('#dane-finish-rotation-btn').on('click', function() {
		var $btn = $(this).prop('disabled', true), $s = $('#dane-rotation-status').html('<?php echo esc_js( __( 'Finishing…', 'archiviomd' ) ); ?>');
		$.post(archivioPostData.ajaxUrl, { action: 'archivio_dane_finish_rotation', nonce: archivioPostData.nonce }, function(r) {
			$btn.prop('disabled', false);
			if (r.success) { $s.html('<span style="color:#0a7537;">&#10003; ' + r.data.message + '</span>'); setTimeout(function(){ location.reload(); }, 2000); }
			else { $s.html('<span style="color:#dc3232;">&#10007; ' + (r.data ? r.data.message : '') + '</span>'); }
		}).fail(function(){ $btn.prop('disabled', false); $s.html('<span style="color:#dc3232;"><?php echo esc_js( __( 'Request failed.', 'archiviomd' ) ); ?></span>'); });
	});

	$('#dane-health-check-btn').on('click', function() {
		var $btn = $(this).prop('disabled', true);
		var $spinner = $('#dane-health-spinner').css('visibility', 'visible');
		$('#dane-health-result').show();
		$('#dane-health-rows').html('<tr><td colspan="4" style="color:#646970;"><?php echo esc_js( __( 'Checking…', 'archiviomd' ) ); ?></td></tr>');
		$('#dane-health-errors').html('');

		$.post(archivioPostData.ajaxUrl, { action: 'archivio_dane_health_check', nonce: archivioPostData.nonce }, function(r) {
			$btn.prop('disabled', false); $spinner.css('visibility', 'hidden');
			if (r.success) {
				var rows = '', errors = '';
				var yes  = '<span style="color:#0a7537;">✓ <?php echo esc_js( __( 'Yes', 'archiviomd' ) ); ?></span>';
				var no   = '<span style="color:#dc3232;">✗ <?php echo esc_js( __( 'No', 'archiviomd' ) ); ?></span>';
				var warn = '<span style="color:#b45309;">⚠ <?php echo esc_js( __( 'Not validated', 'archiviomd' ) ); ?></span>';
				var skip = '<span style="color:#646970;">— <?php echo esc_js( __( 'Not checked', 'archiviomd' ) ); ?></span>';
				$.each(r.data, function(algo, d) {
					// Only show a meaningful DNSSEC result when the DoH response was
					// actually parsed. If dnssec_checked is absent/false the record was
					// not found at all, so we show "—" rather than a misleading "✗ No".
					var dnssecCell = d.dnssec_checked ? (d.dnssec_ad ? yes : warn) : skip;
					rows += '<tr>';
					rows += '<td style="padding:3px 14px 3px 0;font-weight:600;text-transform:uppercase;font-size:11px;color:#0e7490;">' + algo + '</td>';
					rows += '<td style="padding:3px 14px 3px 0;">' + (d.found ? yes : no) + '</td>';
					rows += '<td style="padding:3px 14px 3px 0;">' + (d.key_match ? yes : no) + '</td>';
					rows += '<td style="padding:3px 0 3px 0;">' + dnssecCell + '</td>';
					rows += '</tr>';
					if (d.error) { errors += '<div>▶ <strong>' + algo.toUpperCase() + ':</strong> ' + d.error + '</div>'; }
				});
				$('#dane-health-rows').html(rows || '<tr><td colspan="4" style="color:#646970;"><?php echo esc_js( __( 'No active algorithms found.', 'archiviomd' ) ); ?></td></tr>');
				$('#dane-health-errors').html(errors);
			} else {
				$('#dane-health-rows').html('<tr><td colspan="4" style="color:#dc3232;"><?php echo esc_js( __( 'Health check failed.', 'archiviomd' ) ); ?></td></tr>');
				if (r.data && r.data.message) { $('#dane-health-errors').html(r.data.message); }
			}
		}).fail(function(){ $btn.prop('disabled', false); $spinner.css('visibility', 'hidden'); alert('<?php echo esc_js( __( 'Health check request failed.', 'archiviomd' ) ); ?>'); });
	});
});
<?php
$_archivio_inline_js = ob_get_clean();
wp_add_inline_script( 'archivio-post-admin', $_archivio_inline_js );
?>
