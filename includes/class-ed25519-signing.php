<?php
/**
 * Ed25519 Document Signing — ArchivioMD
 *
 * Architecture mirrors HMAC Integrity Mode exactly:
 *  - Private key lives in wp-config.php as ARCHIVIOMD_ED25519_PRIVATE_KEY
 *  - Public  key lives in wp-config.php as ARCHIVIOMD_ED25519_PUBLIC_KEY
 *  - When enabled, posts/pages/media are signed automatically on save
 *  - Public key is published at /.well-known/ed25519-pubkey.txt
 *  - status() method returns a structured array consumed by the admin UI
 *
 * Key format: both constants are hex strings.
 *   Private key: 128 hex chars (64-byte NaCl keypair = 32-byte seed + 32-byte pubkey)
 *   Public  key:  64 hex chars (32-byte Ed25519 public key)
 *
 * Generating a keypair (PHP CLI, sodium must be available):
 *   $kp  = sodium_crypto_sign_keypair();
 *   $priv = bin2hex( sodium_crypto_sign_secretkey( $kp ) );  // 128 hex chars → wp-config
 *   $pub  = bin2hex( sodium_crypto_sign_publickey( $kp ) );  //  64 hex chars → wp-config
 *
 * Signing message format (posts/pages/CPTs):
 *   mdsm-ed25519-v1\n{post_id}\n{post_title}\n{post_slug}\n{stripped_content}\n{post_date_gmt}
 *
 * Signing message format (media attachments):
 *   mdsm-ed25519-media-v1\n{id}\n{filename}\n{filesize}\n{mime_type}\n{author_id}\n{date_gmt}
 *
 * Signatures are stored in post meta:
 *   _mdsm_ed25519_sig       — 128-char lowercase hex  (legacy bare sig, always written)
 *   _mdsm_ed25519_dsse      — JSON DSSE envelope       (written only when DSSE mode on)
 *   _mdsm_ed25519_signed_at — Unix timestamp
 *
 * ── DSSE Envelope Mode ───────────────────────────────────────────────────────
 *
 * When DSSE mode is enabled the plugin additionally signs a Pre-Authentication
 * Encoding (PAE) string per the Dead Simple Signing Envelope specification
 * (https://github.com/secure-systems-lab/dsse) and stores the result as a
 * structured JSON envelope in _mdsm_ed25519_dsse:
 *
 *   PAE  = "DSSEv1 " + len(payloadType) + " " + payloadType
 *                    + " " + len(payload)     + " " + payload
 *
 *   envelope = {
 *     "payload":     base64( payload ),
 *     "payloadType": "application/vnd.archiviomd.document",
 *     "signatures":  [ { "keyid": sha256_hex(pubkey_bytes), "sig": base64(sig_bytes) } ]
 *   }
 *
 * The bare-hex sig in _mdsm_ed25519_sig is ALWAYS written alongside so
 * existing verifiers and backward-compat paths continue to work.
 *
 * DSSE mode is a sub-option of Ed25519 mode; it is meaningless unless
 * Ed25519 mode is also enabled.
 * Toggle wp_option: archiviomd_ed25519_dsse_enabled
 *
 * @package ArchivioMD
 * @since   1.6.6
 * @updated 1.6.8 — Added DSSE Envelope Mode
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_Ed25519_Signing {

	const PRIVATE_KEY_CONSTANT  = 'ARCHIVIOMD_ED25519_PRIVATE_KEY';
	const PUBLIC_KEY_CONSTANT   = 'ARCHIVIOMD_ED25519_PUBLIC_KEY';
	const OPTION_MODE_ENABLED   = 'archiviomd_ed25519_enabled';
	const OPTION_DSSE_ENABLED   = 'archiviomd_ed25519_dsse_enabled';
	const OPTION_POST_TYPES     = 'archiviomd_ed25519_post_types';
	const WELL_KNOWN_SLUG       = 'ed25519-pubkey.txt';

	const DSSE_PAYLOAD_TYPE_POST  = 'application/vnd.archiviomd.document';
	const DSSE_PAYLOAD_TYPE_MEDIA = 'application/vnd.archiviomd.media';
	const DSSE_META_KEY           = '_mdsm_ed25519_dsse';

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Auto-sign on post save when enabled.
		add_action( 'save_post', array( $this, 'maybe_sign_post' ), 20, 2 );

		// Auto-sign media on upload when enabled.
		add_action( 'add_attachment', array( $this, 'maybe_sign_media' ) );

		// AJAX: save settings toggle.
		add_action( 'wp_ajax_archivio_post_save_ed25519_settings', array( $this, 'ajax_save_settings' ) );
	}

	// ── Constant / key helpers ─────────────────────────────────────────────

	public static function is_private_key_defined(): bool {
		return defined( self::PRIVATE_KEY_CONSTANT )
			&& is_string( constant( self::PRIVATE_KEY_CONSTANT ) )
			&& preg_match( '/^[0-9a-f]{128}$/i', constant( self::PRIVATE_KEY_CONSTANT ) );
	}

	public static function is_public_key_defined(): bool {
		return defined( self::PUBLIC_KEY_CONSTANT )
			&& is_string( constant( self::PUBLIC_KEY_CONSTANT ) )
			&& preg_match( '/^[0-9a-f]{64}$/i', constant( self::PUBLIC_KEY_CONSTANT ) );
	}

	public static function is_sodium_available(): bool {
		return function_exists( 'sodium_crypto_sign_detached' );
	}

	public static function is_mode_enabled(): bool {
		return (bool) get_option( self::OPTION_MODE_ENABLED, false );
	}

	public static function set_mode( bool $enabled ): void {
		update_option( self::OPTION_MODE_ENABLED, $enabled );
	}

	public static function is_dsse_enabled(): bool {
		return (bool) get_option( self::OPTION_DSSE_ENABLED, false );
	}

	public static function set_dsse_mode( bool $enabled ): void {
		update_option( self::OPTION_DSSE_ENABLED, $enabled );
	}

	/**
	 * SHA-256 fingerprint of the raw public key bytes (hex-encoded).
	 * Used as the `keyid` field in DSSE envelopes so verifiers can
	 * identify which key produced a signature without embedding the
	 * full 32-byte public key in the envelope.
	 *
	 * @return string  64-char hex fingerprint, or empty string if key not defined.
	 */
	public static function public_key_fingerprint(): string {
		if ( ! self::is_public_key_defined() ) {
			return '';
		}
		return hash( 'sha256', hex2bin( constant( self::PUBLIC_KEY_CONSTANT ) ) );
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

	// ── Status array (mirrors MDSM_Hash_Helper::hmac_status exactly) ──────

	/**
	 * @return array{
	 *   mode_enabled: bool,
	 *   private_key_defined: bool,
	 *   public_key_defined: bool,
	 *   sodium_available: bool,
	 *   ready: bool,
	 *   notice_level: string,
	 *   notice_message: string
	 * }
	 */
	public static function status(): array {
		$mode_enabled        = self::is_mode_enabled();
		$private_key_defined = self::is_private_key_defined();
		$public_key_defined  = self::is_public_key_defined();
		$sodium_available    = self::is_sodium_available();
		$ready               = $mode_enabled && $private_key_defined && $public_key_defined && $sodium_available;

		$notice_level   = 'ok';
		$notice_message = '';

		if ( $mode_enabled ) {
			if ( ! $sodium_available ) {
				$notice_level   = 'error';
				$notice_message = __( 'ext-sodium is not available on this PHP build. Disable Ed25519 signing or ask your host to enable the sodium extension.', 'archiviomd' );
			} elseif ( ! $private_key_defined ) {
				$notice_level   = 'error';
				$notice_message = sprintf(
					/* translators: %s: constant name */
					__( 'Ed25519 signing is enabled but %s is not defined in wp-config.php. Signing is paused until the key is added.', 'archiviomd' ),
					'<code>' . esc_html( self::PRIVATE_KEY_CONSTANT ) . '</code>'
				);
			} elseif ( ! $public_key_defined ) {
				$notice_level   = 'warning';
				$notice_message = sprintf(
					/* translators: %s: constant name */
					__( 'Ed25519 signing is active but %s is not defined — the public key endpoint will return a 404 until it is added.', 'archiviomd' ),
					'<code>' . esc_html( self::PUBLIC_KEY_CONSTANT ) . '</code>'
				);
			} else {
				$notice_message = __( 'Ed25519 Document Signing is active. Posts, pages, and media are signed automatically on save.', 'archiviomd' );
			}
		}

		return array(
			'mode_enabled'        => $mode_enabled,
			'private_key_defined' => $private_key_defined,
			'public_key_defined'  => $public_key_defined,
			'sodium_available'    => $sodium_available,
			'ready'               => $ready,
			'dsse_enabled'        => self::is_dsse_enabled(),
			'notice_level'        => $notice_level,
			'notice_message'      => $notice_message,
		);
	}

	// ── Canonical message builders ─────────────────────────────────────────

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

	// ── Core sign function ─────────────────────────────────────────────────

	/**
	 * Sign a message with the configured private key.
	 * Returns lowercase hex signature, or WP_Error on failure.
	 *
	 * @param string $message
	 * @return string|WP_Error
	 */
	public static function sign( string $message ) {
		if ( ! self::is_sodium_available() ) {
			return new WP_Error( 'no_sodium', __( 'ext-sodium is not available.', 'archiviomd' ) );
		}
		if ( ! self::is_private_key_defined() ) {
			return new WP_Error( 'no_key', __( 'Private key constant is not defined in wp-config.php.', 'archiviomd' ) );
		}

		$key_hex  = constant( self::PRIVATE_KEY_CONSTANT );
		$key_bin  = hex2bin( $key_hex );

		if ( strlen( $key_bin ) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES ) {
			return new WP_Error( 'bad_key_len', __( 'Private key byte length is incorrect. Expected 64 bytes (128 hex chars).', 'archiviomd' ) );
		}

		$sig_bin = sodium_crypto_sign_detached( $message, $key_bin );
		return bin2hex( $sig_bin );
	}

	// ── DSSE methods ───────────────────────────────────────────────────────

	/**
	 * Build a DSSE envelope for the given payload string.
	 *
	 * The Pre-Authentication Encoding (PAE) prevents cross-protocol
	 * confusion: the signature is over the PAE string, not the raw
	 * payload, so a signature produced here cannot be replayed against
	 * a different protocol that happens to sign the same bytes.
	 *
	 * PAE = "DSSEv1 " + len(payloadType) + " " + payloadType
	 *                 + " " + len(payload)     + " " + payload
	 *
	 * Lengths are byte lengths expressed as decimal ASCII integers.
	 *
	 * @param  string $payload      The message to sign (raw canonical string).
	 * @param  string $payload_type MIME-style payload type URI.
	 * @return array|WP_Error       DSSE envelope array, or WP_Error on failure.
	 */
	public static function sign_dsse( string $payload, string $payload_type = self::DSSE_PAYLOAD_TYPE_POST ) {
		if ( ! self::is_sodium_available() ) {
			return new WP_Error( 'no_sodium', __( 'ext-sodium is not available.', 'archiviomd' ) );
		}
		if ( ! self::is_private_key_defined() ) {
			return new WP_Error( 'no_key', __( 'Private key constant is not defined in wp-config.php.', 'archiviomd' ) );
		}

		// Build PAE string per DSSE spec §3.
		$pae = 'DSSEv1 '
			. strlen( $payload_type ) . ' ' . $payload_type
			. ' '
			. strlen( $payload ) . ' ' . $payload;

		$sig_hex = self::sign( $pae );
		if ( is_wp_error( $sig_hex ) ) {
			return $sig_hex;
		}

		return array(
			'payload'     => base64_encode( $payload ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			'payloadType' => $payload_type,
			'signatures'  => array(
				array(
					'keyid' => self::public_key_fingerprint(),
					'sig'   => base64_encode( hex2bin( $sig_hex ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				),
			),
		);
	}

	/**
	 * Verify a DSSE envelope array.
	 *
	 * Reconstructs the PAE from the decoded payload and payloadType,
	 * then verifies the first signature using the configured public key.
	 *
	 * @param  array $envelope  Associative array matching the DSSE structure.
	 * @return array|WP_Error   ['valid' => bool, 'payload' => string, 'payload_type' => string]
	 *                          or WP_Error on a structural / key problem.
	 */
	public static function verify_dsse( array $envelope ) {
		if ( ! self::is_sodium_available() ) {
			return new WP_Error( 'no_sodium', __( 'ext-sodium is not available.', 'archiviomd' ) );
		}
		if ( ! self::is_public_key_defined() ) {
			return new WP_Error( 'no_pubkey', __( 'Public key constant is not defined in wp-config.php.', 'archiviomd' ) );
		}

		// Structural validation.
		if ( empty( $envelope['payload'] ) || empty( $envelope['payloadType'] ) || empty( $envelope['signatures'] ) ) {
			return new WP_Error( 'bad_envelope', __( 'DSSE envelope is missing required fields.', 'archiviomd' ) );
		}

		$payload_b64 = $envelope['payload'];
		$payload_type = $envelope['payloadType'];

		// Decode payload — base64_decode can fail on corrupt input.
		$payload = base64_decode( $payload_b64, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $payload ) {
			return new WP_Error( 'bad_payload', __( 'DSSE payload is not valid base64.', 'archiviomd' ) );
		}

		// Rebuild PAE.
		$pae = 'DSSEv1 '
			. strlen( $payload_type ) . ' ' . $payload_type
			. ' '
			. strlen( $payload ) . ' ' . $payload;

		$pub_bin = hex2bin( constant( self::PUBLIC_KEY_CONSTANT ) );

		// Verify all signatures; the envelope is valid if any one passes.
		$valid = false;
		foreach ( (array) $envelope['signatures'] as $sig_entry ) {
			if ( empty( $sig_entry['sig'] ) ) {
				continue;
			}
			$sig_raw = base64_decode( $sig_entry['sig'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $sig_raw || strlen( $sig_raw ) !== SODIUM_CRYPTO_SIGN_BYTES ) {
				continue;
			}
			if ( sodium_crypto_sign_verify_detached( $sig_raw, $pae, $pub_bin ) ) {
				$valid = true;
				break;
			}
		}

		return array(
			'valid'        => $valid,
			'payload'      => $payload,
			'payload_type' => $payload_type,
		);
	}

	/**
	 * Verify the DSSE envelope stored in post meta for a given post.
	 *
	 * @param  int    $post_id
	 * @return array|WP_Error  Same shape as verify_dsse(), plus 'post_id' and 'signed_at'.
	 */
	public static function verify_post_dsse( int $post_id ) {
		$raw = get_post_meta( $post_id, self::DSSE_META_KEY, true );
		if ( ! $raw ) {
			return new WP_Error( 'no_dsse', __( 'No DSSE envelope stored for this post.', 'archiviomd' ) );
		}

		$envelope = json_decode( $raw, true );
		if ( ! is_array( $envelope ) ) {
			return new WP_Error( 'bad_dsse_json', __( 'Stored DSSE envelope is not valid JSON.', 'archiviomd' ) );
		}

		$result = self::verify_dsse( $envelope );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$result['post_id']   = $post_id;
		$result['signed_at'] = (int) get_post_meta( $post_id, '_mdsm_ed25519_signed_at', true );
		return $result;
	}

	/**
	 * Verify a stored signature for a post server-side.
	 *
	 * @param  int    $post_id
	 * @param  string $type  'post' or 'media'
	 * @return array|WP_Error
	 */
	public static function verify( int $post_id, string $type = 'post' ) {
		if ( ! self::is_sodium_available() ) {
			return new WP_Error( 'no_sodium', __( 'ext-sodium is not available.', 'archiviomd' ) );
		}
		if ( ! self::is_public_key_defined() ) {
			return new WP_Error( 'no_pubkey', __( 'Public key constant is not defined in wp-config.php.', 'archiviomd' ) );
		}

		$sig_hex = get_post_meta( $post_id, '_mdsm_ed25519_sig', true );
		if ( ! $sig_hex ) {
			return new WP_Error( 'no_sig', __( 'No Ed25519 signature stored for this content.', 'archiviomd' ) );
		}
		if ( ! preg_match( '/^[0-9a-f]{128}$/i', $sig_hex ) ) {
			return new WP_Error( 'bad_sig', __( 'Stored signature format is invalid.', 'archiviomd' ) );
		}

		$pub_bin  = hex2bin( constant( self::PUBLIC_KEY_CONSTANT ) );
		$sig_bin  = hex2bin( $sig_hex );
		$message  = ( $type === 'media' )
			? self::canonical_message_media( $post_id )
			: self::canonical_message_post( $post_id );

		$valid = sodium_crypto_sign_verify_detached( $sig_bin, $message, $pub_bin );

		return array(
			'valid'     => $valid,
			'post_id'   => $post_id,
			'signed_at' => (int) get_post_meta( $post_id, '_mdsm_ed25519_signed_at', true ),
			'method'    => 'php-sodium',
		);
	}

	// ── Auto-sign hooks ────────────────────────────────────────────────────

	public function maybe_sign_post( int $post_id, \WP_Post $post ): void {
		// Bail on autosave, revisions, or if signing is not ready.
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}
		if ( wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( ! self::is_mode_enabled() || ! self::is_private_key_defined() || ! self::is_sodium_available() ) {
			return;
		}

		$post_types = self::get_configured_post_types();
		if ( ! in_array( $post->post_type, $post_types, true ) ) {
			return;
		}
		if ( ! in_array( $post->post_status, array( 'publish', 'private' ), true ) ) {
			return;
		}

		$message = self::canonical_message_post( $post_id );
		$sig     = self::sign( $message );

		if ( is_wp_error( $sig ) ) {
			return; // Silent fail — do not block the save.
		}

		update_post_meta( $post_id, '_mdsm_ed25519_sig',       $sig );
		update_post_meta( $post_id, '_mdsm_ed25519_signed_at', time() );

		// When DSSE mode is on, also store a full envelope alongside the bare sig.
		if ( self::is_dsse_enabled() ) {
			$envelope = self::sign_dsse( $message, self::DSSE_PAYLOAD_TYPE_POST );
			if ( ! is_wp_error( $envelope ) ) {
				update_post_meta(
					$post_id,
					self::DSSE_META_KEY,
					wp_json_encode( $envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
				);
			}
		}
	}

	public function maybe_sign_media( int $attachment_id ): void {
		if ( ! self::is_mode_enabled() || ! self::is_private_key_defined() || ! self::is_sodium_available() ) {
			return;
		}

		$message = self::canonical_message_media( $attachment_id );
		$sig     = self::sign( $message );

		if ( is_wp_error( $sig ) ) {
			return;
		}

		update_post_meta( $attachment_id, '_mdsm_ed25519_sig',       $sig );
		update_post_meta( $attachment_id, '_mdsm_ed25519_signed_at', time() );

		// When DSSE mode is on, also store a full envelope alongside the bare sig.
		if ( self::is_dsse_enabled() ) {
			$envelope = self::sign_dsse( $message, self::DSSE_PAYLOAD_TYPE_MEDIA );
			if ( ! is_wp_error( $envelope ) ) {
				update_post_meta(
					$attachment_id,
					self::DSSE_META_KEY,
					wp_json_encode( $envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
				);
			}
		}
	}

	// ── Public key well-known endpoint ─────────────────────────────────────

	/**
	 * Return the public key as plain text for /.well-known/ed25519-pubkey.txt
	 * Called by the main plugin's serve_files() when the slug matches.
	 */
	public static function serve_public_key(): void {
		if ( ! self::is_public_key_defined() ) {
			status_header( 404 );
			exit;
		}

		$pubkey  = strtolower( constant( self::PUBLIC_KEY_CONSTANT ) );
		$site    = get_bloginfo( 'url' );
		$name    = get_bloginfo( 'name' );
		$output  = "# Ed25519 public key for {$name}\n";
		$output .= "# Site: {$site}\n";
		$output .= "# Algorithm: Ed25519 (RFC 8032)\n";
		$output .= "# Generated by ArchivioMD\n";
		$output .= "\n";
		$output .= $pubkey . "\n";

		// Append dns-record hint when DANE corroboration is enabled so external
		// verifiers know exactly which DNS TXT record to query.
		if ( class_exists( 'MDSM_DANE_Corroboration' ) && MDSM_DANE_Corroboration::is_enabled() ) {
			$output .= "\n";
			$output .= "# dns-record: " . MDSM_DANE_Corroboration::dns_record_name( 'ed25519' ) . "\n";
			$output .= "# discovery:  " . home_url( '/.well-known/' . MDSM_DANE_Corroboration::JSON_SLUG ) . "\n";
		}

		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
		nocache_headers();
		echo $output; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	// ── AJAX: save settings ────────────────────────────────────────────────

	public function ajax_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$enable = isset( $_POST['ed25519_enabled'] )
			&& sanitize_text_field( wp_unslash( $_POST['ed25519_enabled'] ) ) === 'true';

		if ( $enable && ! self::is_private_key_defined() ) {
			wp_send_json_error( array(
				'message' => sprintf(
					/* translators: %s: constant name */
					esc_html__( 'Cannot enable Ed25519 signing: %s is not defined in wp-config.php.', 'archiviomd' ),
					esc_html( self::PRIVATE_KEY_CONSTANT )
				),
			) );
		}

		if ( $enable && ! self::is_sodium_available() ) {
			wp_send_json_error( array(
				'message' => esc_html__( 'Cannot enable Ed25519 signing: ext-sodium is not available on this server.', 'archiviomd' ),
			) );
		}

		self::set_mode( $enable );

		// Handle the DSSE sub-toggle.  It is only meaningful when Ed25519 is on;
		// silently disable it if the parent mode is being turned off.
		if ( isset( $_POST['dsse_enabled'] ) ) {
			$dsse_enable = sanitize_text_field( wp_unslash( $_POST['dsse_enabled'] ) ) === 'true';
			self::set_dsse_mode( $enable && $dsse_enable );
		} elseif ( ! $enable ) {
			// Parent mode turned off — keep dsse option but don't auto-disable;
			// re-enabling Ed25519 later will restore whatever the user last chose.
		}

		$status = self::status();

		wp_send_json_success( array(
			'message'        => $enable
				? esc_html__( 'Ed25519 Document Signing enabled. Posts, pages, and media will be signed on save.', 'archiviomd' )
				: esc_html__( 'Ed25519 Document Signing disabled.', 'archiviomd' ),
			'notice_level'   => $status['notice_level'],
			'notice_message' => wp_strip_all_tags( $status['notice_message'] ),
			'dsse_enabled'   => $status['dsse_enabled'],
		) );
	}
}
