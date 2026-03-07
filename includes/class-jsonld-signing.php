<?php
/**
 * JSON-LD / W3C Data Integrity — ArchivioMD
 *
 * ── What this does ────────────────────────────────────────────────────────────
 *
 * 1. Publishes a DID document at /.well-known/did.json using the did:web method,
 *    listing the site's public keys as verification methods.
 * 2. Produces a W3C Data Integrity Proof block for each post, using the
 *    eddsa-rdfc-2022 cryptosuite for Ed25519 and ecdsa-rdfc-2019 for ECDSA P-256.
 * 3. Serves a per-post JSON-LD endpoint at /?p={id}&format=json-ld.
 *
 * ── Post meta keys ───────────────────────────────────────────────────────────
 *
 *   _mdsm_jsonld_proof      JSON-encoded W3C Data Integrity proof block (or proof set array)
 *   _mdsm_jsonld_signed_at  Unix timestamp of proof creation
 *   _mdsm_jsonld_suite      Cryptosuite(s) used: 'eddsa-rdfc-2022' / 'ecdsa-rdfc-2019'
 *
 * ── Standards ────────────────────────────────────────────────────────────────
 *
 *   W3C Data Integrity 1.0   https://www.w3.org/TR/vc-data-integrity/
 *   W3C DID Core 1.0         https://www.w3.org/TR/did-core/
 *   eddsa-rdfc-2022          https://www.w3.org/TR/vc-di-eddsa/
 *   ecdsa-rdfc-2019          https://www.w3.org/TR/vc-di-ecdsa/
 *
 * @package ArchivioMD
 * @since   1.16.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MDSM_JSONLD_Signing {

	// ── Post meta keys ───────────────────────────────────────────────────────
	const META_PROOF            = '_mdsm_jsonld_proof';
	const META_SIGNED_AT        = '_mdsm_jsonld_signed_at';
	const META_SUITE            = '_mdsm_jsonld_suite';

	// ── Cryptosuite identifiers ──────────────────────────────────────────────
	const SUITE_EDDSA           = 'eddsa-rdfc-2022';
	const SUITE_ECDSA           = 'ecdsa-rdfc-2019';

	// ── Well-known slug for DID document ────────────────────────────────────
	const WELL_KNOWN_DID        = 'did.json';

	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'save_post',      array( $this, 'maybe_sign_post' ),  45, 2 );
		add_action( 'add_attachment', array( $this, 'maybe_sign_media' ), 45    );
	}

	// ── Prerequisite checks ──────────────────────────────────────────────────

	public static function is_mode_enabled(): bool {
		return (bool) get_option( 'archiviomd_jsonld_enabled', false );
	}

	/**
	 * True when at least one supported signing algorithm (Ed25519 or ECDSA P-256)
	 * is active and ready to produce proofs.
	 */
	public static function is_signer_available(): bool {
		if ( class_exists( 'MDSM_Ed25519_Signing' )
			&& MDSM_Ed25519_Signing::is_mode_enabled()
			&& MDSM_Ed25519_Signing::is_private_key_defined()
			&& MDSM_Ed25519_Signing::is_sodium_available() ) {
			return true;
		}
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::status()['ready'] ) {
			return true;
		}
		return false;
	}

	/**
	 * Returns the active cryptosuite(s) as an array.
	 *
	 * @return string[]  e.g. ['eddsa-rdfc-2022', 'ecdsa-rdfc-2019']
	 */
	public static function get_active_suites(): array {
		$suites = array();
		if ( class_exists( 'MDSM_Ed25519_Signing' )
			&& MDSM_Ed25519_Signing::is_mode_enabled()
			&& MDSM_Ed25519_Signing::is_private_key_defined()
			&& MDSM_Ed25519_Signing::is_sodium_available() ) {
			$suites[] = self::SUITE_EDDSA;
		}
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::status()['ready'] ) {
			$suites[] = self::SUITE_ECDSA;
		}
		return $suites;
	}

	// ── Status ───────────────────────────────────────────────────────────────

	public static function status(): array {
		$mode_enabled     = self::is_mode_enabled();
		$signer_available = self::is_signer_available();
		$active_suites    = self::get_active_suites();
		$ready            = $mode_enabled && $signer_available;

		$notice_level   = 'ok';
		$notice_message = sprintf(
			/* translators: %s: comma-separated cryptosuite names */
			__( 'JSON-LD / W3C Data Integrity is active. Suites: %s', 'archiviomd' ),
			implode( ', ', $active_suites ) ?: __( 'none', 'archiviomd' )
		);

		if ( $mode_enabled && ! $signer_available ) {
			$notice_level   = 'error';
			$notice_message = __( 'JSON-LD mode is enabled but no compatible signing algorithm is active. Enable Ed25519 or ECDSA P-256 signing first.', 'archiviomd' );
		}

		return array(
			'mode_enabled'     => $mode_enabled,
			'signer_available' => $signer_available,
			'active_suites'    => $active_suites,
			'ready'            => $ready,
			'did_url'          => trailingslashit( get_site_url() ) . '.well-known/did.json',
			'notice_level'     => $notice_level,
			'notice_message'   => $notice_message,
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
	 * Produce a W3C Data Integrity proof (or proof set) for a canonical message.
	 *
	 * Returns an array of proof objects (one per active cryptosuite),
	 * or WP_Error if no signers are available.
	 *
	 * @param  string $message  Canonical message.
	 * @param  string $suite    Specific cryptosuite, or empty string for all active suites.
	 * @return array|WP_Error   Array of proof objects, or WP_Error on failure.
	 */
	public static function sign( string $message, string $suite = '' ) {
		if ( ! self::is_signer_available() ) {
			return new WP_Error( 'jsonld_no_signer', __( 'No compatible signing algorithm is active for JSON-LD proof production.', 'archiviomd' ) );
		}

		$suites_to_use = $suite ? array( $suite ) : self::get_active_suites();
		if ( empty( $suites_to_use ) ) {
			return new WP_Error( 'jsonld_no_suite', __( 'No active cryptosuites available.', 'archiviomd' ) );
		}

		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );
		$did  = 'did:web:' . $host;
		$now  = gmdate( 'Y-m-d\TH:i:s\Z' );
		$proofs = array();

		foreach ( $suites_to_use as $suite_id ) {
			$proof = self::build_proof( $message, $suite_id, $did, $now );
			if ( is_wp_error( $proof ) ) {
				continue; // Skip failed suites silently; produce whatever we can.
			}
			$proofs[] = $proof;
		}

		if ( empty( $proofs ) ) {
			return new WP_Error( 'jsonld_all_suites_failed', __( 'All active cryptosuites failed to produce a proof.', 'archiviomd' ) );
		}

		return $proofs;
	}

	/**
	 * Build a single W3C Data Integrity proof object for a given cryptosuite.
	 *
	 * @param  string $message   Canonical message to sign.
	 * @param  string $suite_id  'eddsa-rdfc-2022' or 'ecdsa-rdfc-2019'.
	 * @param  string $did       Issuer DID (e.g. 'did:web:example.com').
	 * @param  string $created   ISO 8601 timestamp string.
	 * @return array|WP_Error    Proof array, or WP_Error.
	 */
	private static function build_proof( string $message, string $suite_id, string $did, string $created ) {
		switch ( $suite_id ) {
			case self::SUITE_EDDSA:
				return self::build_eddsa_proof( $message, $did, $created );
			case self::SUITE_ECDSA:
				return self::build_ecdsa_proof( $message, $did, $created );
			default:
				return new WP_Error( 'jsonld_unknown_suite', sprintf( 'Unknown cryptosuite: %s', $suite_id ) );
		}
	}

	/**
	 * Build an eddsa-rdfc-2022 proof using the configured Ed25519 key.
	 */
	private static function build_eddsa_proof( string $message, string $did, string $created ) {
		if ( ! class_exists( 'MDSM_Ed25519_Signing' )
			|| ! MDSM_Ed25519_Signing::is_private_key_defined()
			|| ! MDSM_Ed25519_Signing::is_sodium_available() ) {
			return new WP_Error( 'jsonld_ed25519_unavailable', __( 'Ed25519 signing is not available.', 'archiviomd' ) );
		}

		// The proof options document is hashed alongside the message per the spec.
		// We produce a simplified proof-options hash and prepend it to the message
		// to align with the eddsa-rdfc-2022 transformation algorithm intent.
		$vm_id   = $did . '#ed25519-key-1';
		$proof_options_hash = hash( 'sha256', wp_json_encode( array(
			'type'               => 'DataIntegrityProof',
			'cryptosuite'        => self::SUITE_EDDSA,
			'verificationMethod' => $vm_id,
			'created'            => $created,
			'proofPurpose'       => 'assertionMethod',
		) ) );

		$signing_input = $proof_options_hash . $message;
		$sig = MDSM_Ed25519_Signing::sign( $signing_input );

		if ( is_wp_error( $sig ) ) {
			return $sig;
		}

		// Encode the hex signature as multibase (base58btc, prefix 'z').
		$sig_bytes        = hex2bin( $sig );
		$proof_value      = 'z' . self::base58_encode( $sig_bytes );

		return array(
			'type'               => 'DataIntegrityProof',
			'cryptosuite'        => self::SUITE_EDDSA,
			'created'            => $created,
			'verificationMethod' => $vm_id,
			'proofPurpose'       => 'assertionMethod',
			'proofValue'         => $proof_value,
		);
	}

	/**
	 * Build an ecdsa-rdfc-2019 proof using the configured ECDSA P-256 key.
	 */
	private static function build_ecdsa_proof( string $message, string $did, string $created ) {
		if ( ! class_exists( 'MDSM_ECDSA_Signing' ) || ! MDSM_ECDSA_Signing::status()['ready'] ) {
			return new WP_Error( 'jsonld_ecdsa_unavailable', __( 'ECDSA signing is not available.', 'archiviomd' ) );
		}

		$vm_id = $did . '#ecdsa-key-1';
		$proof_options_hash = hash( 'sha256', wp_json_encode( array(
			'type'               => 'DataIntegrityProof',
			'cryptosuite'        => self::SUITE_ECDSA,
			'verificationMethod' => $vm_id,
			'created'            => $created,
			'proofPurpose'       => 'assertionMethod',
		) ) );

		$signing_input = $proof_options_hash . $message;
		$sig_hex = MDSM_ECDSA_Signing::sign( $signing_input );

		if ( is_wp_error( $sig_hex ) ) {
			return $sig_hex;
		}

		$sig_bytes   = hex2bin( $sig_hex );
		$proof_value = 'z' . self::base58_encode( $sig_bytes );

		return array(
			'type'               => 'DataIntegrityProof',
			'cryptosuite'        => self::SUITE_ECDSA,
			'created'            => $created,
			'verificationMethod' => $vm_id,
			'proofPurpose'       => 'assertionMethod',
			'proofValue'         => $proof_value,
		);
	}

	// ── Verify ───────────────────────────────────────────────────────────────

	/**
	 * Verify the stored JSON-LD proof (set) for a post.
	 *
	 * @param  int    $post_id
	 * @param  string $type    'post' or 'media'
	 * @return array|WP_Error  Array with 'valid' bool and 'suites' array, or WP_Error.
	 */
	public static function verify( int $post_id, string $type = 'post' ) {
		$proof_json = get_post_meta( $post_id, self::META_PROOF, true );
		if ( ! $proof_json ) {
			return new WP_Error( 'jsonld_no_proof', __( 'No JSON-LD proof stored for this post.', 'archiviomd' ) );
		}

		$proofs = json_decode( $proof_json, true );
		if ( ! is_array( $proofs ) ) {
			return new WP_Error( 'jsonld_bad_proof_json', __( 'Stored JSON-LD proof is not valid JSON.', 'archiviomd' ) );
		}

		// Support both a single proof object and a proof set (array of proofs).
		if ( isset( $proofs['type'] ) ) {
			$proofs = array( $proofs );
		}

		$message = ( $type === 'media' )
			? self::canonical_message_media( $post_id )
			: self::canonical_message_post( $post_id );

		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );
		$did  = 'did:web:' . $host;

		$results = array();
		$all_valid = true;

		foreach ( $proofs as $proof ) {
			if ( empty( $proof['cryptosuite'] ) || empty( $proof['proofValue'] ) ) {
				$results[] = array( 'valid' => false, 'error' => 'Missing cryptosuite or proofValue' );
				$all_valid = false;
				continue;
			}

			$suite_id           = $proof['cryptosuite'];
			$proof_options_hash = hash( 'sha256', wp_json_encode( array(
				'type'               => 'DataIntegrityProof',
				'cryptosuite'        => $suite_id,
				'verificationMethod' => $proof['verificationMethod'] ?? '',
				'created'            => $proof['created'] ?? '',
				'proofPurpose'       => $proof['proofPurpose'] ?? 'assertionMethod',
			) ) );

			$signing_input = $proof_options_hash . $message;

			// Decode multibase proof value (prefix 'z' = base58btc).
			$pv = $proof['proofValue'];
			if ( str_starts_with( $pv, 'z' ) ) {
				$sig_bytes = self::base58_decode( substr( $pv, 1 ) );
			} else {
				$sig_bytes = base64_decode( $pv, true );
			}

			$valid = false;
			$error = '';

			switch ( $suite_id ) {
				case self::SUITE_EDDSA:
					if ( class_exists( 'MDSM_Ed25519_Signing' )
						&& MDSM_Ed25519_Signing::is_public_key_defined()
						&& MDSM_Ed25519_Signing::is_sodium_available() ) {
						$pub_bin = hex2bin( constant( MDSM_Ed25519_Signing::PUBLIC_KEY_CONSTANT ) );
						$valid   = sodium_crypto_sign_verify_detached( $sig_bytes, $signing_input, $pub_bin );
					} else {
						$error = 'Ed25519 public key unavailable';
					}
					break;

				case self::SUITE_ECDSA:
					if ( class_exists( 'MDSM_ECDSA_Signing' ) ) {
						$cert_pem = MDSM_ECDSA_Signing::load_certificate_pem();
						if ( $cert_pem ) {
							$pubkey = openssl_pkey_get_public( $cert_pem );
							$res    = openssl_verify( $signing_input, $sig_bytes, $pubkey, OPENSSL_ALGO_SHA256 );
							$valid  = ( 1 === $res );
						} else {
							$error = 'ECDSA certificate unavailable';
						}
					}
					break;

				default:
					$error = 'Unknown cryptosuite: ' . $suite_id;
			}

			$result_entry = array( 'valid' => $valid, 'suite' => $suite_id );
			if ( $error ) {
				$result_entry['error'] = $error;
			}
			$results[] = $result_entry;
			if ( ! $valid ) {
				$all_valid = false;
			}
		}

		return array(
			'valid'     => $all_valid && ! empty( $results ),
			'post_id'   => $post_id,
			'signed_at' => (int) get_post_meta( $post_id, self::META_SIGNED_AT, true ),
			'proofs'    => $results,
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
		if ( ! self::is_mode_enabled() || ! self::is_signer_available() ) {
			return;
		}
		if ( ! in_array( $post->post_status, array( 'publish', 'private' ), true ) ) {
			return;
		}

		$message = self::canonical_message_post( $post_id );
		$proofs  = self::sign( $message );

		if ( is_wp_error( $proofs ) ) {
			return;
		}

		$suites = array_column( $proofs, 'cryptosuite' );

		update_post_meta( $post_id, self::META_PROOF,     wp_json_encode( $proofs, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
		update_post_meta( $post_id, self::META_SUITE,     implode( ',', $suites ) );
		update_post_meta( $post_id, self::META_SIGNED_AT, time() );
	}

	public function maybe_sign_media( int $attachment_id ): void {
		if ( ! self::is_mode_enabled() || ! self::is_signer_available() ) {
			return;
		}

		$message = self::canonical_message_media( $attachment_id );
		$proofs  = self::sign( $message );

		if ( is_wp_error( $proofs ) ) {
			return;
		}

		$suites = array_column( $proofs, 'cryptosuite' );

		update_post_meta( $attachment_id, self::META_PROOF,     wp_json_encode( $proofs, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
		update_post_meta( $attachment_id, self::META_SUITE,     implode( ',', $suites ) );
		update_post_meta( $attachment_id, self::META_SIGNED_AT, time() );
	}

	// ── Serve DID document at /.well-known/did.json ──────────────────────────

	/**
	 * Serve the site's DID document as application/did+json.
	 * Populates verification methods from all configured and active keys.
	 */
	public static function serve_did_document(): void {
		$host = wp_parse_url( get_site_url(), PHP_URL_HOST );
		$did  = 'did:web:' . $host;

		$document = array(
			'@context'           => array(
				'https://www.w3.org/ns/did/v1',
				'https://w3id.org/security/suites/ed25519-2020/v1',
				'https://w3id.org/security/suites/ecdsa-2019/v1',
			),
			'id'                 => $did,
			'verificationMethod' => array(),
			'authentication'     => array(),
			'assertionMethod'    => array(),
		);

		// ── Ed25519 key ───────────────────────────────────────────────────
		if ( class_exists( 'MDSM_Ed25519_Signing' )
			&& MDSM_Ed25519_Signing::is_mode_enabled()
			&& MDSM_Ed25519_Signing::is_public_key_defined() ) {

			$pubkey_hex = defined( MDSM_Ed25519_Signing::PUBLIC_KEY_CONSTANT )
				? constant( MDSM_Ed25519_Signing::PUBLIC_KEY_CONSTANT )
				: '';

			if ( $pubkey_hex ) {
				$pubkey_bytes = hex2bin( $pubkey_hex );
				$vm_id        = $did . '#ed25519-key-1';

				$vm = array(
					'id'                 => $vm_id,
					'type'               => 'Ed25519VerificationKey2020',
					'controller'         => $did,
					'publicKeyMultibase' => 'z' . self::base58_encode( $pubkey_bytes ),
				);

				$document['verificationMethod'][] = $vm;
				$document['authentication'][]      = $vm_id;
				$document['assertionMethod'][]     = $vm_id;
			}
		}

		// ── ECDSA P-256 key ───────────────────────────────────────────────
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::status()['ready'] ) {
			$cert_pem = MDSM_ECDSA_Signing::load_certificate_pem();
			if ( $cert_pem ) {
				$cert_res = openssl_x509_read( $cert_pem );
				if ( $cert_res ) {
					$pub     = openssl_pkey_get_public( $cert_res );
					$details = openssl_pkey_get_details( $pub );

					if ( $details && isset( $details['ec'] ) ) {
						// Express ECDSA P-256 public key as JWK.
						$x_b64 = rtrim( strtr( base64_encode( $details['ec']['x'] ), '+/', '-_' ), '=' );
						$y_b64 = rtrim( strtr( base64_encode( $details['ec']['y'] ), '+/', '-_' ), '=' );

						$vm_id = $did . '#ecdsa-key-1';
						$vm    = array(
							'id'           => $vm_id,
							'type'         => 'JsonWebKey2020',
							'controller'   => $did,
							'publicKeyJwk' => array(
								'kty' => 'EC',
								'crv' => 'P-256',
								'x'   => $x_b64,
								'y'   => $y_b64,
							),
						);

						$document['verificationMethod'][] = $vm;
						$document['authentication'][]      = $vm_id;
						$document['assertionMethod'][]     = $vm_id;
					}
				}
			}
		}

		// ── DANE DNS corroboration service endpoints ────────────────────────
		// When DANE is active, advertise each algorithm's DNS record name as a
		// DID service so resolvers can discover corroboration without needing
		// to know the _archiviomd._domainkey naming convention.
		if ( class_exists( 'MDSM_DANE_Corroboration' ) && MDSM_DANE_Corroboration::is_enabled() ) {
			if ( ! isset( $document['service'] ) ) {
				$document['service'] = array();
			}
			foreach ( MDSM_DANE_Corroboration::active_algorithms() as $algo ) {
				$document['service'][] = array(
					'id'              => $did . '#dane-' . $algo,
					'type'            => 'DnsCorroboration',
					'serviceEndpoint' => array(
						'dnsName'   => MDSM_DANE_Corroboration::dns_record_name( $algo ),
						'algorithm' => $algo,
						'keyId'     => MDSM_DANE_Corroboration::key_fingerprint( $algo ),
						'discovery' => home_url( '/.well-known/' . MDSM_DANE_Corroboration::JSON_SLUG ),
					),
				);
			}
		}

		header( 'Content-Type: application/did+json; charset=utf-8' );
		header( 'Cache-Control: public, max-age=3600' );
		echo wp_json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	// ── Serve per-post JSON-LD ────────────────────────────────────────────────

	/**
	 * Build and return the JSON-LD document for a post, including any stored proofs.
	 *
	 * @param  int   $post_id
	 * @return array JSON-LD document array.
	 */
	public static function build_post_jsonld( int $post_id ): array {
		$post = get_post( $post_id );
		if ( ! $post ) {
			return array();
		}

		$host        = wp_parse_url( get_site_url(), PHP_URL_HOST );
		$did         = 'did:web:' . $host;
		$post_url    = get_permalink( $post_id );
		$proof_json  = get_post_meta( $post_id, self::META_PROOF, true );

		$document = array(
			'@context' => array(
				'https://schema.org/',
				'https://www.w3.org/ns/credentials/v2',
				'https://w3id.org/security/data-integrity/v2',
			),
			'@type'          => 'Article',
			'@id'            => $post_url,
			'name'           => $post->post_title,
			'url'            => $post_url,
			'datePublished'  => $post->post_date_gmt,
			'dateModified'   => $post->post_modified_gmt,
			'issuer'         => $did,
		);

		if ( $proof_json ) {
			$proofs = json_decode( $proof_json, true );
			if ( is_array( $proofs ) ) {
				// Single proof vs proof set.
				$document['proof'] = isset( $proofs[0]['type'] ) ? $proofs : $proofs;
			}
		}

		return $document;
	}

	// ── Base58 encode/decode (Bitcoin alphabet) ──────────────────────────────
	// Required for multibase encoding of public keys and proof values per the W3C spec.

	private static $base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

	public static function base58_encode( string $data ): string {
		$chars = self::$base58_chars;
		$hex   = bin2hex( $data );

		$bigint  = gmp_init( $hex, 16 );
		$base    = gmp_init( 58 );
		$result  = '';

		while ( gmp_cmp( $bigint, 0 ) > 0 ) {
			list( $bigint, $remainder ) = gmp_div_qr( $bigint, $base );
			$result = $chars[ gmp_intval( $remainder ) ] . $result;
		}

		// Preserve leading zero bytes.
		for ( $i = 0; $i < strlen( $data ) && $data[ $i ] === "\0"; $i++ ) {
			$result = '1' . $result;
		}

		return $result;
	}

	public static function base58_decode( string $data ): string {
		$chars  = self::$base58_chars;
		$bigint = gmp_init( 0 );
		$base   = gmp_init( 58 );

		for ( $i = 0; $i < strlen( $data ); $i++ ) {
			$pos    = strpos( $chars, $data[ $i ] );
			$bigint = gmp_add( gmp_mul( $bigint, $base ), gmp_init( $pos ) );
		}

		$hex = gmp_strval( $bigint, 16 );
		if ( strlen( $hex ) % 2 ) {
			$hex = '0' . $hex;
		}

		$result = hex2bin( $hex );

		// Restore leading zero bytes.
		for ( $i = 0; $i < strlen( $data ) && $data[ $i ] === '1'; $i++ ) {
			$result = "\0" . $result;
		}

		return $result;
	}

}
