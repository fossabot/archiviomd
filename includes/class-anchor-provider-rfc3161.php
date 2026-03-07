<?php
/**
 * RFC 3161 Trusted Timestamping Provider
 *
 * Implements MDSM_Anchor_Provider_Interface for RFC 3161 TSAs.
 * Supported providers:
 *   - freetsa   FreeTSA.org          (free, no credentials required)
 *   - digicert  DigiCert TSA         (requires TSA credentials in URL)
 *   - globalsign GlobalSign TSA      (requires HTTP Basic auth)
 *   - sectigo   Sectigo/Comodo TSA   (free endpoint, no credentials)
 *
 * How RFC 3161 works in this implementation:
 *   1. Build a TimeStampReq: hash the anchor JSON with SHA-256, wrap in ASN.1 DER.
 *   2. POST it (Content-Type: application/timestamp-query) to the TSA endpoint.
 *   3. Receive a TimeStampResp (DER binary). Verify the response is not an error.
 *   4. Base64-encode the response token and store it alongside the original record
 *      in the plugin's meta-docs directory as a .tsr file. The anchor URL returned
 *      to the log is the public URL where the .tsr can be retrieved.
 *
 * The .tsr file is a standard RFC 3161 TimeStampToken and can be verified offline
 * with OpenSSL: openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa.crt
 *
 * PHP ASN.1 note: We build the TimeStampReq manually in pure PHP so there are
 * zero external library dependencies. The structure follows RFC 3161 §2.4.1.
 *
 * @package ArchivioMD
 * @since   1.6.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ── Known TSA endpoints ────────────────────────────────────────────────────────

/**
 * Registry of built-in TSA profiles.
 * Each profile carries default endpoint, auth type, and help notes.
 */
class MDSM_TSA_Profiles {

	/**
	 * Return all known profiles.
	 *
	 * @return array  Keyed by provider slug.
	 */
	public static function all() {
		return array(
			'freetsa' => array(
				'label'       => 'FreeTSA.org (Free)',
				'url'         => 'https://freetsa.org/tsr',
				'auth'        => 'none',
				'cert_url'    => 'https://freetsa.org/files/tsa.crt',
				'policy_oid'  => '1.2.3.4.1',
				'verify_via'  => 'manual_cert',
				'notes'       => 'Free, no account required. Rate-limited to ~1 req/sec. TSA cert must be downloaded separately for offline verification — cert_url above. HTTPS transport.',
			),
			'digicert' => array(
				'label'       => 'DigiCert TSA',
				'url'         => 'http://timestamp.digicert.com',
				'auth'        => 'none',
				'cert_url'    => '',
				'policy_oid'  => '2.16.840.1.114412.7.1',
				'verify_via'  => 'system_trust_store',
				'notes'       => 'DigiCert public endpoint. No account required. High throughput. HTTP only (DigiCert\'s official documentation — the TSR itself is cryptographically signed so transport encryption is not required for integrity). DigiCert root is in every major OS/browser trust store; no cert download needed for verification.',
			),
			'globalsign' => array(
				'label'       => 'GlobalSign TSA',
				'url'         => 'http://timestamp.globalsign.com/tsa/r6advanced1',
				'auth'        => 'none',
				'cert_url'    => '',
				'policy_oid'  => '',
				'verify_via'  => 'system_trust_store',
				'notes'       => 'GlobalSign public endpoint. No account required. HTTP only (same rationale as DigiCert — TSR is self-authenticating). GlobalSign root is in every major OS/browser trust store; no cert download needed for verification.',
			),
			'sectigo' => array(
				'label'       => 'Sectigo TSA',
				'url'         => 'https://timestamp.sectigo.com',
				'auth'        => 'none',
				'cert_url'    => '',
				'policy_oid'  => '',
				'verify_via'  => 'system_trust_store',
				'notes'       => 'Sectigo (formerly Comodo) public endpoint. No account required. HTTPS transport available and used. Throttled — add 15+ second delays between requests if batching. Sectigo root is in every major OS/browser trust store; no cert download needed for verification.',
			),
			'custom' => array(
				'label'       => 'Custom TSA',
				'url'         => '',
				'auth'        => 'none',
				'cert_url'    => '',
				'policy_oid'  => '',
				'notes'       => 'Enter your own RFC 3161-compliant TSA endpoint.',
			),
		);
	}

	/**
	 * Return a single profile by slug, or null if unknown.
	 *
	 * @param string $slug
	 * @return array|null
	 */
	public static function get( $slug ) {
		$all = self::all();
		return isset( $all[ $slug ] ) ? $all[ $slug ] : null;
	}
}

// ── RFC 3161 provider ──────────────────────────────────────────────────────────

/**
 * MDSM_Anchor_Provider_RFC3161
 *
 * Sends anchor records to an RFC 3161 Trusted Timestamping Authority.
 * The provider is entirely stateless — all configuration comes from $settings.
 */
class MDSM_Anchor_Provider_RFC3161 implements MDSM_Anchor_Provider_Interface {

	// Storage sub-folder inside meta-docs upload dir.
	const TSR_FOLDER = 'tsr-timestamps';

	// ── Interface: push ────────────────────────────────────────────────────────

	/**
	 * Timestamp an anchor record.
	 *
	 * @param array $record   Anchor record (document_id, hash_value, etc.)
	 * @param array $settings Provider settings from get_settings().
	 * @return array          { success, url } or { success, error, retry, rate_limited }
	 */
	public function push( array $record, array $settings ) {
		$endpoint = $this->resolve_endpoint( $settings );
		if ( empty( $endpoint ) ) {
			return array(
				'success'      => false,
				'error'        => 'No TSA endpoint configured.',
				'retry'        => false,
				'rate_limited' => false,
				'http_status'  => 0,
			);
		}

		// Build the RFC 3161 message imprint from the content hash directly.
		//
		// RFC 3161 intent: the MessageImprint SHOULD be the hash of the content
		// being attested — so the TSR directly proves "this content hash existed
		// at this time" without needing to reconstruct any wrapper JSON.
		//
		// If the content hash is SHA-256 (32 bytes), use its raw bytes directly
		// as the imprint — the TSR message data will then equal the content hash.
		// For other algorithms (SHA-512, BLAKE2b, etc.), SHA-256-hash the hex
		// string of the content hash; this is deterministic and always 32 bytes.
		// Either way, the imprint is recorded in the manifest for verification.
		$content_hash_hex = isset( $record['hash_value'] ) ? $record['hash_value'] : '';
		$content_algorithm = isset( $record['hash_algorithm'] ) ? strtolower( $record['hash_algorithm'] ) : 'sha256';

		if ( $content_algorithm === 'sha256' && strlen( $content_hash_hex ) === 64 ) {
			// SHA-256 content hash: use raw bytes directly as the imprint.
			$message_hash    = hex2bin( $content_hash_hex );
			$imprint_method  = 'direct'; // TSR message data == content hash
		} else {
			// Other algorithm: SHA-256-hash the hex string — deterministic, auditable.
			$message_hash    = hash( 'sha256', $content_hash_hex, true );
			$imprint_method  = 'sha256_of_hex'; // TSR message data == sha256(content_hash_hex)
		}

		// Build RFC 3161 TimeStampReq DER.
		$tsq_der = $this->build_timestamp_request( $message_hash );

		// POST to TSA.
		$response = $this->post_to_tsa( $endpoint, $tsq_der, $settings );

		if ( is_wp_error( $response ) ) {
			return array(
				'success'      => false,
				'error'        => $response->get_error_message(),
				'retry'        => true,
				'rate_limited' => false,
				'http_status'  => 0,
			);
		}

		$http_code = wp_remote_retrieve_response_code( $response );
		$body      = wp_remote_retrieve_body( $response );

		if ( $http_code !== 200 || empty( $body ) ) {
			$retryable = in_array( $http_code, array( 429, 500, 502, 503, 504 ), true );
			return array(
				'success'      => false,
				'error'        => "TSA returned HTTP {$http_code}.",
				'retry'        => $retryable,
				'rate_limited' => ( 429 === $http_code ),
				'http_status'  => $http_code,
			);
		}

		// Validate the TSA response: must start with a valid TimeStampResp status.
		$validation = $this->validate_tsr( $body );
		if ( ! $validation['valid'] ) {
			return array(
				'success'      => false,
				'error'        => 'Invalid TSA response: ' . $validation['reason'],
				'retry'        => false,
				'rate_limited' => false,
				'http_status'  => $http_code,
			);
		}

		// Store the .tsr token and the original request .tsq file.
		$stored = $this->store_tsr( $record, $tsq_der, $body, $settings );

		$tsr_url = $stored['success'] ? $stored['url'] : '';

		// Enrich the log entry with timestamping metadata.
		$record['rfc3161_tsa']        = $endpoint;
		$record['rfc3161_serial']     = $validation['serial'];
		$record['rfc3161_timestamp']  = $validation['gen_time'];
		$record['rfc3161_tsr_url']    = $tsr_url;

		return array(
			'success'     => true,
			'url'         => $tsr_url,
			'http_status' => $http_code,
		);
	}

	// ── Interface: test_connection ─────────────────────────────────────────────

	/**
	 * Send a minimal test request to the TSA to verify connectivity.
	 *
	 * @param array $settings
	 * @return array { success, message }
	 */
	public function test_connection( array $settings ) {
		$endpoint = $this->resolve_endpoint( $settings );
		if ( empty( $endpoint ) ) {
			return array( 'success' => false, 'message' => __( 'No TSA endpoint configured.', 'archiviomd' ) );
		}

		// Test payload: SHA-256 of a known string.
		$test_hash = hash( 'sha256', 'archiviomd-connection-test-' . time(), true );
		$tsq_der   = $this->build_timestamp_request( $test_hash );

		$response = $this->post_to_tsa( $endpoint, $tsq_der, $settings );

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: error message */
					__( 'Could not reach TSA: %s', 'archiviomd' ),
					$response->get_error_message()
				),
			);
		}

		$http_code = wp_remote_retrieve_response_code( $response );
		$body      = wp_remote_retrieve_body( $response );

		if ( $http_code !== 200 || empty( $body ) ) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %d: HTTP status code */
					__( 'TSA returned HTTP %d. Check the endpoint URL and your network.', 'archiviomd' ),
					$http_code
				),
			);
		}

		$validation = $this->validate_tsr( $body );
		if ( ! $validation['valid'] ) {
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: validation reason */
					__( 'TSA responded but the token is invalid: %s', 'archiviomd' ),
					$validation['reason']
				),
			);
		}

		$profile   = MDSM_TSA_Profiles::get( $settings['rfc3161_provider'] ?? 'custom' );
		$tsa_label = $profile ? $profile['label'] : $endpoint;

		return array(
			'success' => true,
			'message' => sprintf(
				/* translators: 1: TSA label, 2: serial number */
				__( 'Connection successful. %1$s responded with a valid timestamp token (serial: %2$s).', 'archiviomd' ),
				$tsa_label,
				$validation['serial']
			),
		);
	}

	// ── ASN.1 / RFC 3161 helpers ───────────────────────────────────────────────

	/**
	 * Build a minimal RFC 3161 TimeStampReq in DER encoding.
	 *
	 * Structure (RFC 3161 §2.4.1):
	 *   TimeStampReq ::= SEQUENCE {
	 *     version       INTEGER { v1(1) },
	 *     messageImprint MessageImprint,
	 *     nonce         INTEGER OPTIONAL,
	 *     certReq       BOOLEAN DEFAULT FALSE
	 *   }
	 *   MessageImprint ::= SEQUENCE {
	 *     hashAlgorithm AlgorithmIdentifier,  -- OID for SHA-256
	 *     hashedMessage OCTET STRING
	 *   }
	 *
	 * @param string $hash_bytes Raw binary SHA-256 digest (32 bytes).
	 * @return string DER-encoded TimeStampReq.
	 */
	private function build_timestamp_request( $hash_bytes ) {
		// version INTEGER { v1(1) }  →  02 01 01
		$version = "\x02\x01\x01";

		// SHA-256 AlgorithmIdentifier
		// OID 2.16.840.1.101.3.4.2.1 → 60 86 48 01 65 03 04 02 01
		$sha256_oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
		// AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
		$algo_id = $this->asn1_sequence( $sha256_oid . "\x05\x00" ); // OID + NULL

		// hashedMessage OCTET STRING
		$hashed_msg = $this->asn1_octet_string( $hash_bytes );

		// MessageImprint SEQUENCE
		$msg_imprint = $this->asn1_sequence( $algo_id . $hashed_msg );

		// nonce INTEGER (random 64-bit, prevents replay)
		$nonce_bytes = random_bytes( 8 );
		// Force positive: clear sign bit on first byte.
		$nonce_bytes[0] = chr( ord( $nonce_bytes[0] ) & 0x7F );
		$nonce = $this->asn1_integer( $nonce_bytes );

		// certReq BOOLEAN TRUE  →  01 01 FF
		$cert_req = "\x01\x01\xFF";

		// Outer TimeStampReq SEQUENCE
		return $this->asn1_sequence( $version . $msg_imprint . $nonce . $cert_req );
	}

	/**
	 * Validate a raw DER TimeStampResp body.
	 *
	 * We do a lightweight structural check: confirm the PKIStatus integer is 0
	 * (granted) and extract the serial number and genTime for logging.
	 *
	 * @param string $der_body Raw binary TSA response body.
	 * @return array { valid: bool, reason: string, serial: string, gen_time: string }
	 */
	private function validate_tsr( $der_body ) {
		$result = array(
			'valid'    => false,
			'reason'   => '',
			'serial'   => '',
			'gen_time' => '',
		);

		if ( strlen( $der_body ) < 10 ) {
			$result['reason'] = 'Response too short.';
			return $result;
		}

		// Outer byte must be SEQUENCE (0x30).
		if ( ord( $der_body[0] ) !== 0x30 ) {
			$result['reason'] = 'Response is not a DER SEQUENCE.';
			return $result;
		}

		// Skip the outer SEQUENCE tag+length to find PKIStatusInfo SEQUENCE.
		$offset = 0;
		$outer  = $this->asn1_read_tlv( $der_body, $offset );
		if ( ! $outer ) {
			$result['reason'] = 'Could not parse outer SEQUENCE.';
			return $result;
		}

		// PKIStatusInfo is the first child SEQUENCE inside TimeStampResp.
		$inner_offset = $outer['value_offset'];
		$status_info  = $this->asn1_read_tlv( $der_body, $inner_offset );
		if ( ! $status_info || ord( $der_body[ $status_info['value_offset'] ] ) !== 0x02 ) {
			$result['reason'] = 'Could not locate PKIStatusInfo.';
			return $result;
		}

		// PKIStatus INTEGER — must be 0 (granted) or 1 (grantedWithMods).
		$status_tlv = $this->asn1_read_tlv( $der_body, $status_info['value_offset'] );
		if ( ! $status_tlv ) {
			$result['reason'] = 'Could not parse PKIStatus integer.';
			return $result;
		}

		$status_val = $this->asn1_int_value( $der_body, $status_tlv );
		if ( $status_val > 1 ) {
			$result['reason'] = "PKIStatus returned failure code {$status_val}.";
			return $result;
		}

		// Try to extract serial and genTime from the TimeStampToken for logging.
		// We do a simple string scan rather than full ASN.1 traversal — safe enough
		// for read-only diagnostic info; we never trust these values for security.
		$result['serial']   = $this->extract_serial_approximate( $der_body );
		$result['gen_time'] = $this->extract_gen_time_approximate( $der_body );

		$result['valid'] = true;
		return $result;
	}

	// ── TSR file storage ───────────────────────────────────────────────────────

	/**
	 * Store the TSQ and TSR files in the plugin's upload directory.
	 *
	 * Files are stored at:
	 *   {uploads}/meta-docs/tsr-timestamps/{document_id}-{YYYYMMDD-HHiiss}.tsq
	 *   {uploads}/meta-docs/tsr-timestamps/{document_id}-{YYYYMMDD-HHiiss}.tsr
	 *
	 * @param array  $record   Anchor record.
	 * @param string $tsq_der  DER-encoded timestamp request.
	 * @param string $tsr_der  DER-encoded timestamp response.
	 * @return array { success: bool, url: string, path: string }
	 */
	private function store_tsr( array $record, $tsq_der, $tsr_der, array $settings ) {
		$upload_dir = wp_upload_dir();
		$tsr_dir    = trailingslashit( $upload_dir['basedir'] ) . 'meta-docs/' . self::TSR_FOLDER;

		if ( ! file_exists( $tsr_dir ) ) {
			wp_mkdir_p( $tsr_dir );
			// Block all direct HTTP access to this directory.
			// .tsr and .tsq files are served via an authenticated AJAX download handler.
			// Only .manifest.json files may be served directly (no secret data).
			file_put_contents(
				$tsr_dir . '/.htaccess',
				"Options -Indexes\n<FilesMatch \"\\.(tsr|tsq)$\">\n  Require all denied\n</FilesMatch>\n"
			);
		}

		$slug     = sanitize_file_name( $record['document_id'] );
		$stamp    = gmdate( 'Ymd-His' );
		$base     = "{$slug}-{$stamp}";
		$tsq_path      = "{$tsr_dir}/{$base}.tsq";
		$tsr_path      = "{$tsr_dir}/{$base}.tsr";
		$manifest_path = "{$tsr_dir}/{$base}.manifest.json";

		$ok_tsq = file_put_contents( $tsq_path, $tsq_der );
		$ok_tsr = file_put_contents( $tsr_path, $tsr_der );

		if ( false === $ok_tsq || false === $ok_tsr ) {
			return array( 'success' => false, 'url' => '', 'path' => '' );
		}

		$tsr_url = trailingslashit( $upload_dir['baseurl'] ) . 'meta-docs/' . self::TSR_FOLDER . "/{$base}.tsr";

		// Write a human-readable manifest alongside the binary files.
		// This records exactly what was signed and how to verify it offline.
		$content_hex  = isset( $record['hash_value'] )     ? $record['hash_value']     : '';
		$content_algo = isset( $record['hash_algorithm'] ) ? $record['hash_algorithm'] : 'sha256';
		$is_direct    = ( strtolower( $content_algo ) === 'sha256' && strlen( $content_hex ) === 64 );

		// Look up the TSA profile so the manifest can include the right cert/verification info.
		$tsa_profile   = MDSM_TSA_Profiles::get( $settings['provider'] ?? '' );
		$tsa_cert_url  = $tsa_profile ? ( $tsa_profile['cert_url'] ?? '' ) : '';
		$verify_via    = $tsa_profile ? ( $tsa_profile['verify_via'] ?? 'system_trust_store' ) : 'system_trust_store';

		if ( 'manual_cert' === $verify_via && ! empty( $tsa_cert_url ) ) {
			$verify_note    = 'Download the TSA certificate from cert_url, then run the verification command.';
			$verify_command = 'curl -sO ' . $tsa_cert_url . ' && openssl ts -verify -in ' . $base . '.tsr -queryfile ' . $base . '.tsq -CAfile tsa.crt';
		} else {
			$verify_note    = 'TSA root certificate is in the system trust store (no manual download needed).';
			$verify_command = 'openssl ts -verify -in ' . $base . '.tsr -queryfile ' . $base . '.tsq -CAfile /etc/ssl/certs/ca-certificates.crt';
		}

		$manifest = array(
			'archiviomd_version'   => defined( 'MDSM_VERSION' ) ? MDSM_VERSION : '',
			'created_utc'          => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'document_id'          => isset( $record['document_id'] ) ? $record['document_id'] : '',
			'post_id'              => isset( $record['post_id'] )     ? $record['post_id']     : '',
			'post_title'           => isset( $record['post_title'] )  ? $record['post_title']  : '',
			'post_url'             => isset( $record['post_url'] )    ? $record['post_url']    : '',
			'site_url'             => isset( $record['site_url'] )    ? $record['site_url']    : '',
			'author'               => isset( $record['author'] )      ? $record['author']      : '',
			'content_hash_algorithm' => $content_algo,
			'content_hash_hex'     => $content_hex,
			'integrity_mode'       => isset( $record['integrity_mode'] ) ? $record['integrity_mode'] : 'Basic',
			'tsr_message_imprint'  => array(
				'algorithm' => 'sha256',
				'method'    => $is_direct ? 'direct' : 'sha256_of_hex',
				'note'      => $is_direct
					? 'TSR message data equals the raw content hash bytes (hex2bin of content_hash_hex).'
					: 'TSR message data = sha256(content_hash_hex as UTF-8 string). Content algorithm is not SHA-256.',
			),
			'tsa_verification'     => array(
				'verify_via'    => $verify_via,
				'cert_url'      => $tsa_cert_url,
				'note'          => $verify_note,
			),
			'files' => array(
				'tsr'      => $base . '.tsr',
				'tsq'      => $base . '.tsq',
				'manifest' => $base . '.manifest.json',
			),
			'verification_command' => $verify_command,
		);

		// Never include HMAC values in the manifest — they contain secret-derived data.
		file_put_contents( $manifest_path, wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );

		return array(
			'success' => true,
			'url'     => $tsr_url,
			'path'    => $tsr_path,
		);
	}

	// ── HTTP ───────────────────────────────────────────────────────────────────

	/**
	 * POST a DER timestamp request to the TSA endpoint.
	 *
	 * @param string $endpoint TSA URL.
	 * @param string $tsq_der  DER binary.
	 * @param array  $settings Provider settings (may include HTTP Basic credentials).
	 * @return array|WP_Error  wp_remote_request result.
	 */
	private function post_to_tsa( $endpoint, $tsq_der, array $settings ) {
		$headers = array(
			'Content-Type' => 'application/timestamp-query',
			'Accept'       => 'application/timestamp-reply',
			'User-Agent'   => 'ArchivioMD/' . MDSM_VERSION,
		);

		// Some commercial TSAs use HTTP Basic auth.
		$username = isset( $settings['rfc3161_username'] ) ? trim( $settings['rfc3161_username'] ) : '';
		$password = isset( $settings['rfc3161_password'] ) ? trim( $settings['rfc3161_password'] ) : '';

		if ( $username !== '' && $password !== '' ) {
			$headers['Authorization'] = 'Basic ' . base64_encode( $username . ':' . $password );
		}

		return wp_remote_request( $endpoint, array(
			'method'      => 'POST',
			'headers'     => $headers,
			'body'        => $tsq_der,
			'timeout'     => 30,
			'data_format' => 'body',
			'sslverify'   => true,
		) );
	}

	/**
	 * Resolve the TSA endpoint URL from settings.
	 *
	 * Priority: custom URL → known profile URL.
	 *
	 * @param array $settings
	 * @return string
	 */
	private function resolve_endpoint( array $settings ) {
		// If a custom URL is explicitly set, use it regardless of provider slug.
		$custom = isset( $settings['rfc3161_custom_url'] ) ? trim( $settings['rfc3161_custom_url'] ) : '';
		if ( $custom !== '' ) {
			// SSRF guard: only allow http:// and https:// schemes, and reject
			// URLs whose hostname resolves to a private or reserved IP range
			// (loopback, link-local, RFC 1918, etc.).
			$parsed = wp_parse_url( $custom );
			if ( empty( $parsed['scheme'] ) || ! in_array( strtolower( $parsed['scheme'] ), array( 'http', 'https' ), true ) ) {
				return ''; // Unsupported scheme — refuse to connect.
			}
			$host = isset( $parsed['host'] ) ? $parsed['host'] : '';
			if ( $host === '' ) {
				return '';
			}
			// Strip IPv6 brackets for filter_var().
			$host_bare = trim( $host, '[]' );
			// If the host is a bare IP, validate it directly.
			if ( filter_var( $host_bare, FILTER_VALIDATE_IP ) ) {
				if ( ! filter_var( $host_bare, FILTER_VALIDATE_IP,
						FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
					return ''; // Private/reserved IP — refuse.
				}
			} else {
				// Hostname: resolve to IP(s) and check every record.
				$records = dns_get_record( $host, DNS_A | DNS_AAAA );
				if ( empty( $records ) ) {
					return ''; // Unresolvable host — refuse.
				}
				foreach ( $records as $rec ) {
					$ip = isset( $rec['ip'] ) ? $rec['ip'] : ( isset( $rec['ipv6'] ) ? $rec['ipv6'] : '' );
					if ( $ip === '' ) {
						continue;
					}
					if ( ! filter_var( $ip, FILTER_VALIDATE_IP,
							FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
						return ''; // At least one record resolves to private range — refuse.
					}
				}
			}
			return $custom;
		}

		$slug    = isset( $settings['rfc3161_provider'] ) ? $settings['rfc3161_provider'] : 'freetsa';
		$profile = MDSM_TSA_Profiles::get( $slug );

		return $profile ? $profile['url'] : '';
	}

	// ── Minimal ASN.1 DER encoding helpers ────────────────────────────────────

	/** Encode a DER SEQUENCE (tag 0x30). */
	private function asn1_sequence( $contents ) {
		return "\x30" . $this->asn1_length( strlen( $contents ) ) . $contents;
	}

	/** Encode a DER OCTET STRING (tag 0x04). */
	private function asn1_octet_string( $data ) {
		return "\x04" . $this->asn1_length( strlen( $data ) ) . $data;
	}

	/** Encode a DER INTEGER (tag 0x02) from raw big-endian bytes. */
	private function asn1_integer( $bytes ) {
		return "\x02" . $this->asn1_length( strlen( $bytes ) ) . $bytes;
	}

	/** Encode DER length in short or long form. */
	private function asn1_length( $len ) {
		if ( $len < 0x80 ) {
			return chr( $len );
		}
		if ( $len < 0x100 ) {
			return "\x81" . chr( $len );
		}
		if ( $len < 0x10000 ) {
			return "\x82" . chr( ( $len >> 8 ) & 0xFF ) . chr( $len & 0xFF );
		}
		// Documents we'll be timestamping will never exceed 64 KB.
		return "\x83"
			. chr( ( $len >> 16 ) & 0xFF )
			. chr( ( $len >> 8 )  & 0xFF )
			. chr( $len & 0xFF );
	}

	// ── Minimal ASN.1 DER decoding helpers ────────────────────────────────────

	/**
	 * Read a TLV (Tag-Length-Value) at a given offset.
	 *
	 * Returns array {
	 *   tag          => int,
	 *   length       => int,
	 *   value_offset => int,   // byte offset where value starts
	 *   next_offset  => int,   // byte offset after this TLV
	 * } or false on error.
	 *
	 * @param string $data
	 * @param int    $offset
	 * @return array|false
	 */
	private function asn1_read_tlv( $data, $offset ) {
		$len = strlen( $data );
		if ( $offset >= $len ) {
			return false;
		}

		$tag = ord( $data[ $offset ] );
		$offset++;

		if ( $offset >= $len ) {
			return false;
		}

		$first_len_byte = ord( $data[ $offset ] );
		$offset++;

		if ( $first_len_byte < 0x80 ) {
			$value_len = $first_len_byte;
		} elseif ( $first_len_byte === 0x81 ) {
			if ( $offset >= $len ) {
				return false;
			}
			$value_len = ord( $data[ $offset++ ] );
		} elseif ( $first_len_byte === 0x82 ) {
			if ( $offset + 1 >= $len ) {
				return false;
			}
			$value_len = ( ord( $data[ $offset ] ) << 8 ) | ord( $data[ $offset + 1 ] );
			$offset   += 2;
		} else {
			// Length > 3 bytes — not expected in a TSA response we'd process.
			return false;
		}

		$value_offset = $offset;
		$next_offset  = $offset + $value_len;

		return array(
			'tag'          => $tag,
			'length'       => $value_len,
			'value_offset' => $value_offset,
			'next_offset'  => $next_offset,
		);
	}

	/**
	 * Interpret the integer value of an ASN.1 INTEGER TLV.
	 *
	 * @param string $data
	 * @param array  $tlv   Result from asn1_read_tlv().
	 * @return int
	 */
	private function asn1_int_value( $data, array $tlv ) {
		$val = 0;
		for ( $i = 0; $i < $tlv['length'] && $i < 4; $i++ ) {
			$val = ( $val << 8 ) | ord( $data[ $tlv['value_offset'] + $i ] );
		}
		return $val;
	}

	// ── Diagnostic extraction (best-effort, not security-critical) ────────────

	/**
	 * Attempt to extract the serial number from the TST (TimeStampToken).
	 * Returns hex string or empty string if not found.
	 *
	 * @param string $der
	 * @return string
	 */
	private function extract_serial_approximate( $der ) {
		// The serial is a DER INTEGER following the version INTEGER (value 0x03)
		// inside the TSTInfo SEQUENCE. We do a simple scan for the pattern
		// 02 01 03 (version v3 INTEGER) followed immediately by another INTEGER.
		// This is heuristic but sufficient for display purposes.
		$pos = strpos( $der, "\x02\x01\x03" );
		if ( false === $pos ) {
			return '';
		}
		$serial_start = $pos + 3;
		if ( $serial_start >= strlen( $der ) ) {
			return '';
		}
		$serial_tlv = $this->asn1_read_tlv( $der, $serial_start );
		if ( ! $serial_tlv || $serial_tlv['tag'] !== 0x02 ) {
			return '';
		}
		$serial_bytes = substr( $der, $serial_tlv['value_offset'], $serial_tlv['length'] );
		return strtoupper( bin2hex( $serial_bytes ) );
	}

	/**
	 * Attempt to extract the genTime GeneralizedTime string.
	 * Returns string like "20250615143022Z" or empty string.
	 *
	 * @param string $der
	 * @return string
	 */
	private function extract_gen_time_approximate( $der ) {
		// GeneralizedTime has tag 0x18. Scan for it.
		$offset = 0;
		$len    = strlen( $der );
		while ( $offset < $len - 2 ) {
			if ( ord( $der[ $offset ] ) === 0x18 ) {
				$tlv = $this->asn1_read_tlv( $der, $offset );
				if ( $tlv && $tlv['length'] >= 14 && $tlv['length'] <= 20 ) {
					$candidate = substr( $der, $tlv['value_offset'], $tlv['length'] );
					// GeneralizedTime looks like "20250615143022Z" — all printable ASCII.
					if ( ctype_print( $candidate ) ) {
						return $candidate;
					}
				}
			}
			$offset++;
		}
		return '';
	}
}
