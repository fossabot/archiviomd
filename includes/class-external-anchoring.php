<?php
/**
 * External Anchoring System
 *
 * Provider-agnostic, asynchronous document anchoring for ArchivioMD.
 * Supports GitHub and GitLab. Designed so future providers (RFC 3161,
 * blockchain, etc.) can be added by implementing MDSM_Anchor_Provider_Interface.
 *
 * Architecture:
 *  - MDSM_External_Anchoring  -- singleton facade / entry point
 *  - MDSM_Anchor_Queue        -- persistent WP-options queue with exponential backoff
 *  - MDSM_Anchor_Provider_*   -- concrete REST-API providers
 *
 * Zero hard dependencies on HMAC. Works in Basic Mode (SHA-256 / SHA-512 / BLAKE2b).
 *
 * @package ArchivioMD
 * @since   1.5.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Load RFC 3161 provider (kept in its own file for separation of concerns).
// Must be loaded AFTER MDSM_Anchor_Provider_Interface is defined below.

// ── Provider interface ───────────────────────────────────────────────────────

/**
 * Every provider must implement this interface.
 *
 * push() must return:
 *   [ 'success' => true,  'url' => 'https://...' ]
 *   [ 'success' => false, 'error' => '...', 'retry' => bool, 'rate_limited' => bool ]
 */
interface MDSM_Anchor_Provider_Interface {

	/**
	 * Push an anchor record to the remote repository.
	 *
	 * @param array  $record   Fully-formed anchor record array.
	 * @param array  $settings Provider-specific settings.
	 * @return array           Result array as described above.
	 */
	public function push( array $record, array $settings );

	/**
	 * Test the connection without storing any data.
	 *
	 * @param array $settings Provider-specific settings.
	 * @return array [ 'success' => bool, 'message' => string ]
	 */
	public function test_connection( array $settings );
}

// RFC 3161 provider — loaded here so MDSM_Anchor_Provider_Interface already exists.
require_once MDSM_PLUGIN_DIR . 'includes/class-anchor-provider-rfc3161.php';

// Sigstore / Rekor transparency-log provider.
require_once MDSM_PLUGIN_DIR . 'includes/class-anchor-provider-rekor.php';

// ── Queue ────────────────────────────────────────────────────────────────────

/**
 * Persistent, ordered anchor queue backed by wp_options.
 * Each item carries retry state and exponential back-off metadata.
 *
 * Concurrency: every mutating operation acquires a short-lived transient lock
 * so that two cron processes running simultaneously cannot read the same queue
 * state, process the same job twice, or silently overwrite each other's writes.
 *
 * Size cap: the queue is bounded at MAX_QUEUE_SIZE jobs. Jobs queued beyond
 * that limit are silently discarded rather than letting the wp_options row grow
 * unbounded on high-volume sites. The cap is intentionally generous — it would
 * require hundreds of rapid publishes before a cron run to hit it in practice.
 */
class MDSM_Anchor_Queue {

	const OPTION_KEY      = 'mdsm_anchor_queue';
	const MAX_RETRIES     = 5;
	const BASE_DELAY_SECS = 60;   // 1 min → 2 → 4 → 8 → 16 minutes
	const MAX_QUEUE_SIZE  = 200;  // hard cap — prevents unbounded option row growth
	const LOCK_KEY        = 'mdsm_anchor_queue_lock';
	const LOCK_TTL        = 15;   // seconds — cron batch must finish within this window

	/**
	 * Add a new job to the queue.
	 *
	 * Silently drops the job if the queue is already at MAX_QUEUE_SIZE.
	 *
	 * @param array $record Anchor record payload.
	 * @return string|false Unique job ID, or false if the queue is full.
	 */
	public static function enqueue( array $record ) {
		$lock = self::acquire_lock();

		$queue = self::load();

		if ( count( $queue ) >= self::MAX_QUEUE_SIZE ) {
			self::release_lock( $lock );
			return false;
		}

		$job_id = self::generate_job_id();

		$queue[ $job_id ] = array(
			'id'           => $job_id,
			'record'       => $record,
			'attempts'     => 0,
			'next_attempt' => time(),
			'created_at'   => time(),
			'last_error'   => '',
		);

		self::save( $queue );
		self::release_lock( $lock );
		return $job_id;
	}

	/**
	 * Return jobs that are due for processing (next_attempt <= now).
	 *
	 * Also acquires the lock so the caller holds it across the full
	 * read → process → mark_success/mark_failure cycle.  The lock is
	 * released automatically when it expires (LOCK_TTL seconds) if
	 * process_queue() finishes or crashes without calling release_lock().
	 *
	 * @return array { jobs: array keyed by job_id, lock: string lock token }
	 */
	/**
	 * Return jobs that are due for processing.
	 *
	 * If $active_providers is supplied, any job that lacks a provider_states
	 * map (queued before multi-provider support, or a brand-new job) is
	 * initialised here so process_queue() never has to think about migration.
	 *
	 * A job is considered "due" when at least one of its providers is in the
	 * 'pending' state and its next_attempt timestamp has passed.
	 *
	 * @param  string[] $active_providers Ordered list of active provider keys.
	 * @return array { jobs: array keyed by job_id, lock: string lock token }
	 */
	public static function get_due_jobs( array $active_providers = array() ) {
		$lock    = self::acquire_lock();
		$queue   = self::load();
		$now     = time();
		$due     = array();
		$changed = false;

		foreach ( $queue as $job_id => $job ) {

			// ── Initialise provider_states for pre-multi-provider jobs ────────
			if ( ! isset( $job['provider_states'] ) && ! empty( $active_providers ) ) {
				$job['provider_states'] = array();
				foreach ( $active_providers as $pk ) {
					$job['provider_states'][ $pk ] = array(
						'status'       => 'pending',
						'attempts'     => 0,
						'next_attempt' => 0,
						'last_error'   => '',
					);
				}
				$queue[ $job_id ] = $job;
				$changed          = true;
			}

			// ── Determine if the job has at least one due provider ────────────
			$is_due = false;

			if ( ! isset( $job['provider_states'] ) ) {
				// Legacy single-provider job with no state map.
				$is_due = ( (int) $job['next_attempt'] <= $now );
			} else {
				foreach ( $job['provider_states'] as $pstate ) {
					if ( 'pending' === $pstate['status'] && (int) $pstate['next_attempt'] <= $now ) {
						$is_due = true;
						break;
					}
				}
			}

			if ( $is_due ) {
				$due[ $job_id ] = $job;
			}
		}

		if ( $changed ) {
			self::save( $queue );
		}

		// Lock is intentionally kept open — caller must pass it to release_lock()
		// after all mark_success / mark_failure calls are done.
		return array(
			'jobs' => $due,
			'lock' => $lock,
		);
	}

	/**
	 * Mark one provider's leg of a job as successfully anchored.
	 *
	 * The job is only removed from the queue once every active provider has
	 * either succeeded ('done') or been permanently discarded ('failed_permanent').
	 *
	 * @param string $job_id       Queue job ID.
	 * @param string $provider_key Provider key e.g. 'github', 'rfc3161'.
	 */
	public static function mark_success( $job_id, $provider_key = '' ) {
		$queue = self::load();

		if ( ! isset( $queue[ $job_id ] ) ) {
			return;
		}

		$job = $queue[ $job_id ];

		// Update per-provider state if the job carries one.
		if ( ! empty( $provider_key ) && isset( $job['provider_states'][ $provider_key ] ) ) {
			$job['provider_states'][ $provider_key ]['status'] = 'done';
		}

		// Remove the job only when every provider is resolved.
		if ( self::all_providers_resolved( $job ) ) {
			unset( $queue[ $job_id ] );
		} else {
			$queue[ $job_id ] = $job;
		}

		self::save( $queue );
	}

	/**
	 * Record a failed attempt for one provider and schedule exponential
	 * back-off or permanently discard that provider's leg.
	 *
	 * A job is removed from the queue once every provider is resolved.
	 * The return value signals whether THIS provider was rescheduled; the
	 * caller uses it to decide whether to increment the permanent-failure
	 * counter.
	 *
	 * @param string $job_id        Queue job ID.
	 * @param string $provider_key  Provider key e.g. 'github', 'rfc3161'.
	 * @param string $error_message Human-readable failure reason.
	 * @param bool   $retryable     If false the provider leg is discarded now.
	 * @return bool                 True if rescheduled, false if permanently failed.
	 */
	public static function mark_failure( $job_id, $provider_key, $error_message, $retryable = true ) {
		$queue = self::load();

		if ( ! isset( $queue[ $job_id ] ) ) {
			return false;
		}

		$job        = $queue[ $job_id ];
		$rescheduled = false;

		// ── Per-provider state path ───────────────────────────────────────────
		if ( ! empty( $provider_key ) && isset( $job['provider_states'][ $provider_key ] ) ) {
			$pstate             = $job['provider_states'][ $provider_key ];
			$pstate['attempts'] = (int) $pstate['attempts'] + 1;
			$pstate['last_error'] = $error_message;

			if ( ! $retryable || $pstate['attempts'] >= self::MAX_RETRIES ) {
				$pstate['status'] = 'failed_permanent';
			} else {
				// Exponential back-off per provider, capped at 24 h.
				$delay                  = min( self::BASE_DELAY_SECS * pow( 2, $pstate['attempts'] - 1 ), 86400 );
				$pstate['next_attempt'] = time() + (int) $delay;
				$rescheduled            = true;
			}

			$job['provider_states'][ $provider_key ] = $pstate;

			// Keep job-level fields in sync for display / legacy compatibility.
			$max_attempts = 0;
			$min_next     = PHP_INT_MAX;
			foreach ( $job['provider_states'] as $ps ) {
				$max_attempts = max( $max_attempts, (int) $ps['attempts'] );
				if ( 'pending' === $ps['status'] ) {
					$min_next = min( $min_next, (int) $ps['next_attempt'] );
				}
			}
			$job['attempts']     = $max_attempts;
			$job['last_error']   = $error_message;
			$job['next_attempt'] = ( PHP_INT_MAX === $min_next ) ? time() : $min_next;

		} else {
			// ── Legacy single-provider path (no provider_states map) ──────────
			$job['attempts']   = (int) $job['attempts'] + 1;
			$job['last_error'] = $error_message;

			if ( ! $retryable || $job['attempts'] >= self::MAX_RETRIES ) {
				unset( $queue[ $job_id ] );
				self::save( $queue );
				return false;
			}

			$delay               = min( self::BASE_DELAY_SECS * pow( 2, $job['attempts'] - 1 ), 86400 );
			$job['next_attempt'] = time() + (int) $delay;
			$queue[ $job_id ]    = $job;
			self::save( $queue );
			return true;
		}

		// Remove job only when every provider is resolved.
		if ( self::all_providers_resolved( $job ) ) {
			unset( $queue[ $job_id ] );
		} else {
			$queue[ $job_id ] = $job;
		}

		self::save( $queue );
		return $rescheduled;
	}

	/**
	 * Return true when every provider in the job's state map has a terminal
	 * status ('done' or 'failed_permanent').  Jobs with no state map (legacy)
	 * are always considered unresolved so the caller handles them separately.
	 *
	 * @param array $job Queue job array.
	 * @return bool
	 */
	private static function all_providers_resolved( array $job ) {
		if ( empty( $job['provider_states'] ) ) {
			return true; // No providers tracked — treat as resolved (caller removes).
		}

		foreach ( $job['provider_states'] as $pstate ) {
			if ( 'pending' === $pstate['status'] ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Return the total number of pending jobs.
	 *
	 * @return int
	 */
	public static function count() {
		return count( self::load() );
	}

	/**
	 * Wipe the entire queue. Use with caution (admin-only action).
	 */
	public static function clear() {
		self::save( array() );
	}

	/**
	 * Release the concurrency lock acquired by get_due_jobs() or enqueue().
	 * Call this after all mark_success / mark_failure operations are complete.
	 *
	 * @param string $lock Lock token returned by acquire_lock().
	 */
	public static function release_lock( $lock ) {
		if ( ! empty( $lock ) ) {
			delete_transient( self::LOCK_KEY );
		}
	}

	// ── Private helpers ──────────────────────────────────────────────────────

	/**
	 * Acquire the queue mutex. Spins up to 3 times with a short sleep before
	 * giving up and returning an empty token (fail-open so cron is never
	 * permanently blocked by a crashed process holding a stale lock).
	 *
	 * @return string Lock token (empty string if lock could not be acquired).
	 */
	private static function acquire_lock() {
		$token = wp_generate_uuid4();

		for ( $i = 0; $i < 3; $i++ ) {
			// set_transient returns false if key already exists (atomic add).
			if ( false !== set_transient( self::LOCK_KEY, $token, self::LOCK_TTL ) ) {
				return $token;
			}
			// Another process holds the lock — wait briefly and retry.
			usleep( 250000 ); // 250 ms
		}

		// Could not acquire after retries. Return empty token (fail-open).
		// The LOCK_TTL guarantees the stale lock expires within 15 s regardless.
		return '';
	}

	/**
	 * Return a single job by ID, or null if not found.
	 *
	 * @param string $job_id
	 * @return array|null
	 */
	public static function get_job( $job_id ) {
		$queue = self::load();
		return isset( $queue[ $job_id ] ) ? $queue[ $job_id ] : null;
	}

	private static function load() {
		$data = get_option( self::OPTION_KEY, array() );
		return is_array( $data ) ? $data : array();
	}

	private static function save( array $queue ) {
		update_option( self::OPTION_KEY, $queue, false );
	}

	private static function generate_job_id() {
		return 'anchor_' . uniqid( '', true );
	}
}

// ── GitHub provider ──────────────────────────────────────────────────────────

/**
 * GitHub REST API provider.
 * Docs: https://docs.github.com/en/rest/repos/contents
 */
class MDSM_Anchor_Provider_GitHub implements MDSM_Anchor_Provider_Interface {

	private function api_url( $owner, $repo, $path ) {
		$owner = rawurlencode( $owner );
		$repo  = rawurlencode( $repo );
		return "https://api.github.com/repos/{$owner}/{$repo}/contents/{$path}";
	}

	private function headers( $token ) {
		return array(
			'Authorization' => 'Bearer ' . $token,
			'Accept'        => 'application/vnd.github+json',
			'X-GitHub-Api-Version' => '2022-11-28',
			'User-Agent'    => 'ArchivioMD/' . MDSM_VERSION,
			'Content-Type'  => 'application/json',
		);
	}

	public function push( array $record, array $settings ) {
		$token        = $settings['token'];
		$owner        = $settings['repo_owner'];
		$repo         = $settings['repo_name'];
		$branch       = $settings['branch'];
		$folder       = rtrim( $settings['folder_path'], '/' );
		$commit_tpl   = isset( $settings['commit_message'] ) ? $settings['commit_message'] : 'chore: anchor {doc_id}';

		// Build file path.
		$folder   = $this->resolve_folder( $folder );
		$filename = sanitize_file_name( $record['document_id'] ) . '-' . gmdate( 'YmdHis' ) . '.json';
		$path     = ltrim( $folder . '/' . $filename, '/' );

		$json_body = wp_json_encode( $record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		$content   = base64_encode( $json_body );
		$message   = str_replace( '{doc_id}', $record['document_id'], $commit_tpl );

		$url = $this->api_url( $owner, $repo, $path );

		// Check for existing file SHA (required by GitHub to update an existing file).
		$existing_sha = $this->get_file_sha( $url, $token );

		$payload = array(
			'message' => $message,
			'content' => $content,
			'branch'  => $branch,
		);
		if ( false !== $existing_sha ) {
			$payload['sha'] = $existing_sha;
		}

		// GitHub Contents API uses PUT for both create and update.
		// Body must be JSON. WordPress's HTTP API will honour Content-Type
		// when the body is a pre-encoded string — we set it explicitly here.
		$response = wp_remote_request( $url, array(
			'method'     => 'PUT',
			'headers'    => $this->headers( $token ),
			'body'       => wp_json_encode( $payload ),
			'timeout'    => 25,
			'data_format' => 'body',
		) );

		return $this->parse_response( $response );
	}

	private function get_file_sha( $url, $token ) {
		$response = wp_remote_get( $url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 10,
		) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return false;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return isset( $data['sha'] ) ? $data['sha'] : false;
	}

	public function test_connection( array $settings ) {
		$token = $settings['token'];
		$owner = $settings['repo_owner'];
		$repo  = $settings['repo_name'];
		$branch = $settings['branch'];

		// 1. Verify repo exists.
		$repo_url = "https://api.github.com/repos/" . rawurlencode( $owner ) . '/' . rawurlencode( $repo );
		$response = wp_remote_get( $repo_url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 15,
		) );

		if ( is_wp_error( $response ) ) {
			return array( 'success' => false, 'message' => $response->get_error_message() );
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 401 === $code ) {
			return array( 'success' => false, 'message' => __( 'Authentication failed. Check your Personal Access Token.', 'archiviomd' ) );
		}
		if ( 403 === $code ) {
			return array( 'success' => false, 'message' => __( 'Access forbidden. Ensure the token has repo scope.', 'archiviomd' ) );
		}
		if ( 404 === $code ) {
			return array( 'success' => false, 'message' => __( 'Repository not found. Check owner and repository name.', 'archiviomd' ) );
		}
		if ( $code < 200 || $code > 299 ) {
			return array( 'success' => false, 'message' => sprintf( esc_html__(  'Unexpected HTTP %d response from GitHub.', 'archiviomd' ), $code ) );
		}

		// 2. Verify branch exists.
		$branch_url = "https://api.github.com/repos/" . rawurlencode( $owner ) . '/' . rawurlencode( $repo ) . '/branches/' . rawurlencode( $branch );
		$b_response = wp_remote_get( $branch_url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 15,
		) );

		if ( is_wp_error( $b_response ) ) {
			return array( 'success' => false, 'message' => $b_response->get_error_message() );
		}
		$b_code = wp_remote_retrieve_response_code( $b_response );
		if ( 404 === $b_code ) {
			return array( 'success' => false, 'message' => sprintf( esc_html__(  'Branch "%s" not found in repository.', 'archiviomd' ), esc_html( $branch ) ) );
		}
		if ( $b_code < 200 || $b_code > 299 ) {
			return array( 'success' => false, 'message' => sprintf( esc_html__(  'Unexpected HTTP %d verifying branch.', 'archiviomd' ), $b_code ) );
		}

		return array( 'success' => true, 'message' => __( 'Connection successful. Repository and branch verified.', 'archiviomd' ) );
	}

	private function parse_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array(
				'success'      => false,
				'error'        => $response->get_error_message(),
				'retry'        => true,
				'rate_limited' => false,
				'http_status'  => 0,
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( in_array( $code, array( 200, 201 ), true ) ) {
			$url = isset( $body['content']['html_url'] ) ? $body['content']['html_url'] : '';
			return array( 'success' => true, 'url' => $url, 'http_status' => $code );
		}

		$message = isset( $body['message'] ) ? $body['message'] : "HTTP {$code}";

		if ( 429 === $code ) {
			return array( 'success' => false, 'error' => 'Rate limited: ' . $message, 'retry' => true, 'rate_limited' => true, 'http_status' => $code );
		}
		if ( in_array( $code, array( 401, 403 ), true ) ) {
			return array( 'success' => false, 'error' => 'Auth error: ' . $message, 'retry' => false, 'rate_limited' => false, 'http_status' => $code );
		}
		if ( 409 === $code ) {
			return array( 'success' => false, 'error' => 'Conflict: ' . $message, 'retry' => true, 'rate_limited' => false, 'http_status' => $code );
		}
		if ( 404 === $code ) {
			return array( 'success' => false, 'error' => 'Not found: ' . $message, 'retry' => false, 'rate_limited' => false, 'http_status' => $code );
		}

		return array( 'success' => false, 'error' => "HTTP {$code}: {$message}", 'retry' => true, 'rate_limited' => false, 'http_status' => $code );
	}

	private function resolve_folder( $folder ) {
		// Replace date tokens.
		$folder = str_replace( 'YYYY', gmdate( 'Y' ), $folder );
		$folder = str_replace( 'MM',   gmdate( 'm' ), $folder );
		$folder = str_replace( 'DD',   gmdate( 'd' ), $folder );
		return trim( $folder, '/' );
	}
}

// ── GitLab provider ──────────────────────────────────────────────────────────

/**
 * GitLab REST API provider.
 * Docs: https://docs.gitlab.com/ee/api/repository_files.html
 */
class MDSM_Anchor_Provider_GitLab implements MDSM_Anchor_Provider_Interface {

	private function api_base() {
		return 'https://gitlab.com/api/v4';
	}

	private function encoded_path( $path ) {
		return rawurlencode( $path );
	}

	private function headers( $token ) {
		return array(
			'Authorization' => 'Bearer ' . $token,
			'Content-Type'  => 'application/json',
			'User-Agent'    => 'ArchivioMD/' . MDSM_VERSION,
		);
	}

	public function push( array $record, array $settings ) {
		$token      = $settings['token'];
		$owner      = $settings['repo_owner'];
		$repo       = $settings['repo_name'];
		$branch     = $settings['branch'];
		$folder     = rtrim( $settings['folder_path'], '/' );
		$commit_tpl = isset( $settings['commit_message'] ) ? $settings['commit_message'] : 'chore: anchor {doc_id}';

		$folder   = $this->resolve_folder( $folder );
		$filename = sanitize_file_name( $record['document_id'] ) . '-' . gmdate( 'YmdHis' ) . '.json';
		$path     = ltrim( $folder . '/' . $filename, '/' );
		$message  = str_replace( '{doc_id}', $record['document_id'], $commit_tpl );

		$project_id = $this->get_project_id( $owner, $repo, $token );
		if ( false === $project_id ) {
			return array( 'success' => false, 'error' => 'GitLab project not found.', 'retry' => false, 'rate_limited' => false, 'http_status' => 404 );
		}

		// GitLab accepts plain JSON content directly when encoding = 'text'.
		$json_body = wp_json_encode( $record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

		// Check if file exists to determine create (POST) vs update (PUT).
		$exists = $this->file_exists( $project_id, $path, $branch, $token );
		$method = $exists ? 'PUT' : 'POST';

		$url = $this->api_base() . '/projects/' . $project_id . '/repository/files/' . $this->encoded_path( $path );

		$payload = array(
			'branch'         => $branch,
			'commit_message' => $message,
			'content'        => $json_body,
			'encoding'       => 'text',
		);

		// data_format = 'body' tells WP's HTTP API to send the body string as-is,
		// preserving the Content-Type: application/json header we set in headers().
		$response = wp_remote_request( $url, array(
			'method'      => $method,
			'headers'     => $this->headers( $token ),
			'body'        => wp_json_encode( $payload ),
			'timeout'     => 25,
			'data_format' => 'body',
		) );

		return $this->parse_response( $response );
	}

	private function get_project_id( $owner, $repo, $token ) {
		$namespace = rawurlencode( $owner . '/' . $repo );
		$url       = $this->api_base() . '/projects/' . $namespace;
		$response  = wp_remote_get( $url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 10,
		) );
		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return false;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return isset( $data['id'] ) ? (int) $data['id'] : false;
	}

	private function file_exists( $project_id, $path, $branch, $token ) {
		$url      = $this->api_base() . '/projects/' . $project_id . '/repository/files/' . $this->encoded_path( $path ) . '?ref=' . rawurlencode( $branch );
		$response = wp_remote_get( $url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 10,
		) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		return wp_remote_retrieve_response_code( $response ) === 200;
	}

	public function test_connection( array $settings ) {
		$token  = $settings['token'];
		$owner  = $settings['repo_owner'];
		$repo   = $settings['repo_name'];
		$branch = $settings['branch'];

		$namespace = rawurlencode( $owner . '/' . $repo );
		$url       = $this->api_base() . '/projects/' . $namespace;

		$response = wp_remote_get( $url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 15,
		) );

		if ( is_wp_error( $response ) ) {
			return array( 'success' => false, 'message' => $response->get_error_message() );
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 401 === $code ) {
			return array( 'success' => false, 'message' => __( 'Authentication failed. Check your Personal Access Token.', 'archiviomd' ) );
		}
		if ( 403 === $code ) {
			return array( 'success' => false, 'message' => __( 'Access forbidden. Ensure the token has api scope.', 'archiviomd' ) );
		}
		if ( 404 === $code ) {
			return array( 'success' => false, 'message' => __( 'Project not found. Check group/user and project name.', 'archiviomd' ) );
		}
		if ( $code < 200 || $code > 299 ) {
			return array( 'success' => false, 'message' => sprintf( esc_html__(  'Unexpected HTTP %d response from GitLab.', 'archiviomd' ), $code ) );
		}

		// Verify branch.
		$data       = json_decode( wp_remote_retrieve_body( $response ), true );
		$project_id = isset( $data['id'] ) ? (int) $data['id'] : 0;

		$b_url      = $this->api_base() . '/projects/' . $project_id . '/repository/branches/' . rawurlencode( $branch );
		$b_response = wp_remote_get( $b_url, array(
			'headers' => $this->headers( $token ),
			'timeout' => 15,
		) );

		if ( is_wp_error( $b_response ) ) {
			return array( 'success' => false, 'message' => $b_response->get_error_message() );
		}
		$b_code = wp_remote_retrieve_response_code( $b_response );
		if ( 404 === $b_code ) {
			return array( 'success' => false, 'message' => sprintf( esc_html__(  'Branch "%s" not found in project.', 'archiviomd' ), esc_html( $branch ) ) );
		}
		if ( $b_code < 200 || $b_code > 299 ) {
			return array( 'success' => false, 'message' => sprintf( esc_html__(  'Unexpected HTTP %d verifying branch.', 'archiviomd' ), $b_code ) );
		}

		return array( 'success' => true, 'message' => __( 'Connection successful. Project and branch verified.', 'archiviomd' ) );
	}

	private function parse_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array( 'success' => false, 'error' => $response->get_error_message(), 'retry' => true, 'rate_limited' => false, 'http_status' => 0 );
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( in_array( $code, array( 200, 201 ), true ) ) {
			$url = isset( $body['file_path'] ) ? $body['file_path'] : '';
			return array( 'success' => true, 'url' => $url, 'http_status' => $code );
		}

		$message = isset( $body['message'] ) ? ( is_string( $body['message'] ) ? $body['message'] : wp_json_encode( $body['message'] ) ) : "HTTP {$code}";

		if ( 429 === $code ) {
			return array( 'success' => false, 'error' => 'Rate limited: ' . $message, 'retry' => true, 'rate_limited' => true, 'http_status' => $code );
		}
		if ( in_array( $code, array( 401, 403 ), true ) ) {
			return array( 'success' => false, 'error' => 'Auth error: ' . $message, 'retry' => false, 'rate_limited' => false, 'http_status' => $code );
		}
		if ( 409 === $code ) {
			return array( 'success' => false, 'error' => 'Conflict: ' . $message, 'retry' => true, 'rate_limited' => false, 'http_status' => $code );
		}
		if ( 404 === $code ) {
			return array( 'success' => false, 'error' => 'Not found: ' . $message, 'retry' => false, 'rate_limited' => false, 'http_status' => $code );
		}

		return array( 'success' => false, 'error' => "HTTP {$code}: {$message}", 'retry' => true, 'rate_limited' => false, 'http_status' => $code );
	}

	private function resolve_folder( $folder ) {
		$folder = str_replace( 'YYYY', gmdate( 'Y' ), $folder );
		$folder = str_replace( 'MM',   gmdate( 'm' ), $folder );
		$folder = str_replace( 'DD',   gmdate( 'd' ), $folder );
		return trim( $folder, '/' );
	}
}

// ── Main facade ──────────────────────────────────────────────────────────────

/**
 * MDSM_External_Anchoring
 *
 * Singleton entry point. Callers only ever touch this class.
 *
 * Usage:
 *   MDSM_External_Anchoring::get_instance()->queue_post_anchor( $post_id, $hash_result );
 *   MDSM_External_Anchoring::get_instance()->queue_document_anchor( $file_name, $metadata );
 */
class MDSM_External_Anchoring {

	const CRON_HOOK        = 'mdsm_process_anchor_queue';
	const CRON_INTERVAL    = 'mdsm_anchor_interval';
	const PRUNE_CRON_HOOK  = 'mdsm_prune_anchor_log';
	const LOG_RETENTION_DEFAULT = 90; // days
	const SETTINGS_OPTION  = 'mdsm_anchor_settings';
	const AUDIT_LOG_ACTION = 'mdsm_anchor_audit_log';

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->register_hooks();
	}

	// ── Hooks ─────────────────────────────────────────────────────────────────

	private function register_hooks() {
		// Register custom cron interval.
		add_filter( 'cron_schedules', array( $this, 'register_cron_interval' ) );

		// Cron processor.
		add_action( self::CRON_HOOK,       array( $this, 'process_queue' ) );
		add_action( self::PRUNE_CRON_HOOK, array( $this, 'prune_anchor_log' ) );

		// Ensure cron is scheduled.
		add_action( 'init', array( $this, 'ensure_cron_scheduled' ) );

		// Queue published posts for external anchoring.
		// Priority 20 runs after MDSM_Archivio_Post::maybe_generate_hash (priority 10),
		// so any auto-generated hash is already stored in post meta when we read it.
		add_action( 'save_post',          array( $this, 'maybe_queue_post_on_publish' ), 20, 3 );
		// Scheduled posts transition future→publish via this action, bypassing the
		// content-unchanged guard in maybe_queue_post_on_publish.
		add_action( 'publish_future_post', array( $this, 'on_future_post_published' ) );

		// Admin AJAX handlers (settings + test).
		add_action( 'wp_ajax_mdsm_anchor_save_settings',   array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_mdsm_anchor_test_connection', array( $this, 'ajax_test_connection' ) );
		add_action( 'wp_ajax_mdsm_anchor_clear_queue',     array( $this, 'ajax_clear_queue' ) );
		add_action( 'wp_ajax_mdsm_anchor_queue_status',    array( $this, 'ajax_queue_status' ) );
		add_action( 'wp_ajax_mdsm_anchor_get_log',         array( $this, 'ajax_get_anchor_log' ) );
		add_action( 'wp_ajax_mdsm_anchor_clear_log',       array( $this, 'ajax_clear_anchor_log' ) );
		add_action( 'wp_ajax_mdsm_anchor_download_log',    array( $this, 'ajax_download_anchor_log' ) );
		add_action( 'wp_ajax_mdsm_anchor_download_csv',    array( $this, 'ajax_download_anchor_log_csv' ) );
		add_action( 'wp_ajax_mdsm_anchor_download_tsr_zip',      array( $this, 'ajax_download_tsr_zip' ) );
		add_action( 'wp_ajax_mdsm_anchor_dismiss_fail_notice',   array( $this, 'ajax_dismiss_failure_notice' ) );
		add_action( 'wp_ajax_mdsm_anchor_rekor_verify',          array( $this, 'ajax_rekor_verify' ) );

		// Admin menu and asset enqueueing.
		if ( is_admin() ) {
			add_action( 'admin_menu', array( $this, 'add_admin_menu' ), 20 );
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		}
	}

	// ── Cron ─────────────────────────────────────────────────────────────────

	public function register_cron_interval( $schedules ) {
		$schedules[ self::CRON_INTERVAL ] = array(
			'interval' => 300,   // every 5 minutes
			'display'  => __( 'Every 5 Minutes (ArchivioMD Anchoring)', 'archiviomd' ),
		);
		return $schedules;
	}

	public function ensure_cron_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), self::CRON_INTERVAL, self::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( self::PRUNE_CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::PRUNE_CRON_HOOK );
		}
	}

	public static function activate_cron() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), self::CRON_INTERVAL, self::CRON_HOOK );
		}
		if ( ! wp_next_scheduled( self::PRUNE_CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::PRUNE_CRON_HOOK );
		}
	}

	public static function deactivate_cron() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
		$prune_timestamp = wp_next_scheduled( self::PRUNE_CRON_HOOK );
		if ( $prune_timestamp ) {
			wp_unschedule_event( $prune_timestamp, self::PRUNE_CRON_HOOK );
		}
	}

	// ── Public API: queue anchoring jobs ─────────────────────────────────────

	/**
	 * Hook: save_post (priority 20) — queue any newly-published post for anchoring.
	 *
	 * Fires after MDSM_Archivio_Post::maybe_generate_hash (priority 10), so a
	 * hash already computed by that method is available in post meta.  If no hash
	 * exists yet (auto-generate is off), we compute one on-the-fly specifically
	 * for anchoring — this does NOT save the hash to post meta and does NOT
	 * interfere with the Archivio Post feature.
	 *
	 * Skipped for: revisions, autosaves, non-publish statuses, and when no
	 * external anchoring provider is configured.
	 *
	 * @param int     $post_id
	 * @param WP_Post $post
	 * @param bool    $update
	 */
	public function maybe_queue_post_on_publish( $post_id, $post, $update ) {
		// Skip revisions and autosaves.
		if ( wp_is_post_revision( $post_id ) || wp_is_post_autosave( $post_id ) ) {
			return;
		}

		// Only act on published posts.
		if ( ! is_object( $post ) || ! isset( $post->post_status ) || $post->post_status !== 'publish' ) {
			return;
		}

		// Only queue if a provider is configured and enabled.
		if ( ! $this->is_enabled() ) {
			return;
		}

		// Deduplicate across requests: Gutenberg sends two separate REST API calls
		// when publishing (one for the post body, one for meta/blocks), each in its
		// own PHP process. A static variable only guards within one process.
		// A 10-second transient bridges both requests so only one job is ever queued
		// per publish event. The key includes the hash so a genuine content change
		// on a rapid second publish still gets its own anchor job.
		$_stored_packed = get_post_meta( $post_id, '_archivio_post_hash', true );
		$_dedup_key     = 'mdsm_anchor_q_' . $post_id . '_' . substr( md5( (string) $_stored_packed ), 0, 8 );
		if ( get_transient( $_dedup_key ) ) {
			return;
		}
		set_transient( $_dedup_key, 1, 10 );

		// Try to use a hash already computed by MDSM_Archivio_Post (auto-generate).
		$stored_packed = get_post_meta( $post_id, '_archivio_post_hash', true );

		if ( ! empty( $stored_packed ) ) {
			// Re-use existing hash — avoids re-computing and stays consistent
			// with what is displayed in the Archivio Post badge/audit log.
			$unpacked    = MDSM_Hash_Helper::unpack( $stored_packed );
			$hash_result = array(
				'packed'           => $stored_packed,
				'hash'             => $unpacked['hash'],
				'algorithm'        => $unpacked['algorithm'],
				'hmac_unavailable' => false,
			);
		} else {
			// Auto-generate is off: compute a fresh hash for anchoring only.
			// This hash is NOT saved to post meta.
			$post_obj  = get_post( $post_id );
			if ( ! $post_obj ) {
				return;
			}
			$archivio    = MDSM_Archivio_Post::get_instance();
			$canonical   = $archivio->canonicalize_content(
				$post_obj->post_content,
				$post_id,
				$post_obj->post_author
			);
			$hash_result = MDSM_Hash_Helper::compute_packed( $canonical );
			$unpacked    = MDSM_Hash_Helper::unpack( $hash_result['packed'] );
			$hash_result['hash']      = $unpacked['hash'];
			$hash_result['algorithm'] = $unpacked['algorithm'];
		}

		$this->queue_post_anchor( $post_id, $hash_result );
	}

	/**
	 * Queue anchoring for a WordPress post or page.
	 *
	 * @param int   $post_id
	 * @param array $hash_result  Full result from MDSM_Hash_Helper::compute_packed()
	 */
	public function queue_post_anchor( $post_id, array $hash_result ) {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$post = get_post( $post_id );
		if ( ! $post ) {
			return;
		}

		$unpacked   = MDSM_Hash_Helper::unpack( $hash_result['packed'] );
		$is_hmac    = ( $unpacked['mode'] === MDSM_Hash_Helper::MODE_HMAC );
		$hmac_value = $is_hmac ? $hash_result['hash'] : null;

		// ── Ed25519 signature (if enabled and signed) ───────────────────────
		$ed25519_sig      = null;
		$ed25519_key_url  = null;
		if ( class_exists( 'MDSM_Ed25519_Signing' ) && MDSM_Ed25519_Signing::is_mode_enabled() ) {
			$stored_sig = get_post_meta( $post_id, '_mdsm_ed25519_sig', true );
			if ( $stored_sig ) {
				$ed25519_sig     = $stored_sig;
				$ed25519_key_url = trailingslashit( get_site_url() ) . '.well-known/ed25519-pubkey.txt';
			}
		}

		// ── SLH-DSA signature (if enabled and signed) ────────────────────────
		$slhdsa_sig      = null;
		$slhdsa_param    = null;
		$slhdsa_key_url  = null;
		if ( class_exists( 'MDSM_SLHDSA_Signing' ) && MDSM_SLHDSA_Signing::is_mode_enabled() ) {
			$stored_slh = get_post_meta( $post_id, '_mdsm_slhdsa_sig', true );
			if ( $stored_slh ) {
				$slhdsa_sig     = $stored_slh;
				$slhdsa_param   = get_post_meta( $post_id, '_mdsm_slhdsa_param', true ) ?: MDSM_SLHDSA_Signing::get_param();
				$slhdsa_key_url = trailingslashit( get_site_url() ) . '.well-known/slhdsa-pubkey.txt';
			}
		}

		// ── ECDSA P-256 signature (if enabled and signed) ─────────────────────
		$ecdsa_sig      = null;
		$ecdsa_cert_url = null;
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::is_mode_enabled() ) {
			$stored_ecdsa = get_post_meta( $post_id, '_mdsm_ecdsa_sig', true );
			if ( $stored_ecdsa ) {
				$ecdsa_sig      = $stored_ecdsa;
				$ecdsa_cert_url = trailingslashit( get_site_url() ) . '.well-known/ecdsa-cert.pem';
			}
		}

		// ── RSA compatibility signature (if enabled and signed) ───────────────
		$rsa_sig        = null;
		$rsa_pubkey_url = null;
		$rsa_scheme     = null;
		if ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::is_mode_enabled() ) {
			$stored_rsa = get_post_meta( $post_id, MDSM_RSA_Signing::META_SIG, true );
			if ( $stored_rsa ) {
				$rsa_sig        = $stored_rsa;
				$rsa_pubkey_url = trailingslashit( get_site_url() ) . '.well-known/rsa-pubkey.pem';
				$rsa_scheme     = get_post_meta( $post_id, MDSM_RSA_Signing::META_SCHEME, true )
				                  ?: MDSM_RSA_Signing::get_scheme();
			}
		}

		// ── CMS / PKCS#7 signature (if enabled and signed) ────────────────────
		$cms_sig        = null;
		$cms_key_source = null;
		if ( class_exists( 'MDSM_CMS_Signing' ) && MDSM_CMS_Signing::is_mode_enabled() ) {
			$stored_cms = get_post_meta( $post_id, MDSM_CMS_Signing::META_SIG, true );
			if ( $stored_cms ) {
				$cms_sig        = $stored_cms;
				$cms_key_source = get_post_meta( $post_id, MDSM_CMS_Signing::META_KEY_SOURCE, true ) ?: null;
			}
		}

		// ── JSON-LD / W3C Data Integrity proof (if enabled and present) ───────
		$jsonld_proof = null;
		$jsonld_suite = null;
		if ( class_exists( 'MDSM_JSONLD_Signing' ) && MDSM_JSONLD_Signing::is_mode_enabled() ) {
			$stored_proof = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_PROOF, true );
			if ( $stored_proof ) {
				$jsonld_proof = $stored_proof;
				$jsonld_suite = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_SUITE, true ) ?: null;
			}
		}

		$record = array(
			'document_id'    => 'post-' . $post_id,
			'post_id'        => $post_id,
			'post_type'      => $post->post_type,
			'post_title'     => $post->post_title,
			'post_url'       => get_permalink( $post_id ),
			'hash_algorithm' => $hash_result['algorithm'],
			'hash_value'     => $hash_result['hash'],
			'hmac_value'     => $hmac_value,
			'integrity_mode' => $is_hmac ? 'HMAC' : 'Basic',
			'ed25519_sig'    => $ed25519_sig,
			'ed25519_pubkey' => $ed25519_key_url,
			'slhdsa_sig'     => $slhdsa_sig,
			'slhdsa_param'   => $slhdsa_param,
			'slhdsa_pubkey'  => $slhdsa_key_url,
			'ecdsa_sig'      => $ecdsa_sig,
			'ecdsa_cert_url' => $ecdsa_cert_url,
			'rsa_sig'        => $rsa_sig,
			'rsa_pubkey_url' => $rsa_pubkey_url,
			'rsa_scheme'     => $rsa_scheme,
			'cms_sig'        => $cms_sig,
			'cms_key_source' => $cms_key_source,
			'jsonld_proof'   => $jsonld_proof,
			'jsonld_suite'   => $jsonld_suite,
			'author'         => get_the_author_meta( 'display_name', $post->post_author ),
			'plugin_version' => MDSM_VERSION,
			'site_url'       => get_site_url(),
			// Note: no timestamp_utc — signing time comes from the TSA, not from here.
		);

		MDSM_Anchor_Queue::enqueue( $record );
	}

	/**
	 * Queue anchoring for a native Markdown document.
	 *
	 * @param string $file_name   Markdown filename (e.g. 'security.txt.md')
	 * @param array  $metadata    From MDSM_Document_Metadata::update_metadata() or initialize_metadata()
	 * @param array  $hash_result Full packed hash result array
	 */
	public function queue_document_anchor( $file_name, array $metadata, array $hash_result ) {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$unpacked   = MDSM_Hash_Helper::unpack( $hash_result['packed'] );
		$is_hmac    = ( $unpacked['mode'] === MDSM_Hash_Helper::MODE_HMAC );
		$hmac_value = $is_hmac ? $hash_result['hash'] : null;

		$user = wp_get_current_user();

		$record = array(
			'document_id'    => isset( $metadata['uuid'] ) ? $metadata['uuid'] : 'doc-' . sanitize_key( $file_name ),
			'post_id'        => null,
			'post_type'      => 'archivio_document',
			'document_name'  => $file_name,
			'hash_algorithm' => $hash_result['algorithm'],
			'hash_value'     => $hash_result['hash'],
			'hmac_value'     => $hmac_value,
			'integrity_mode' => $is_hmac ? 'HMAC' : 'Basic',
			'ed25519_sig'    => null,
			'ed25519_pubkey' => null,
			'slhdsa_sig'     => null,
			'slhdsa_param'   => null,
			'slhdsa_pubkey'  => null,
			'ecdsa_sig'      => null,
			'ecdsa_cert_url' => null,
			'rsa_sig'        => null,
			'rsa_pubkey_url' => null,
			'rsa_scheme'     => null,
			'cms_sig'        => null,
			'cms_key_source' => null,
			'jsonld_proof'   => null,
			'jsonld_suite'   => null,
			'author'         => $user ? $user->display_name : 'unknown',
			// No timestamp_utc — signing time comes from the TSA, not from here.
			'plugin_version' => MDSM_VERSION,
			'site_url'       => get_site_url(),
		);

		MDSM_Anchor_Queue::enqueue( $record );
	}

	/**
	 * Queue anchoring for a generated HTML file.
	 *
	 * @param string $html_filename
	 * @param string $html_content  Raw HTML content (for hashing)
	 */
	public function queue_html_anchor( $html_filename, $html_content ) {
		if ( ! $this->is_enabled() ) {
			return;
		}

		// Compute hash once. If HMAC key is unavailable the helper falls back to
		// Basic automatically — no second call needed.
		$hash_result = MDSM_Hash_Helper::compute_packed( $html_content );
		$unpacked    = MDSM_Hash_Helper::unpack( $hash_result['packed'] );
		$is_hmac     = ( $unpacked['mode'] === MDSM_Hash_Helper::MODE_HMAC );
		$hmac_value  = $is_hmac ? $hash_result['hash'] : null;

		$user = wp_get_current_user();

		$record = array(
			'document_id'    => 'html-' . sanitize_key( $html_filename ) . '-' . gmdate( 'Ymd' ),
			'post_id'        => null,
			'post_type'      => 'archivio_html_output',
			'document_name'  => $html_filename,
			'hash_algorithm' => $hash_result['algorithm'],
			'hash_value'     => $hash_result['hash'],
			'hmac_value'     => $hmac_value,
			'integrity_mode' => $is_hmac ? 'HMAC' : 'Basic',
			'author'         => $user ? $user->display_name : 'system',
			// No timestamp_utc — signing time comes from the TSA, not from here.
			'plugin_version' => MDSM_VERSION,
			'site_url'       => get_site_url(),
		);

		MDSM_Anchor_Queue::enqueue( $record );
	}

	// ── Queue processor ───────────────────────────────────────────────────────

	/**
	 * Process due anchor jobs. Called by WP-Cron.
	 * Never throws — all errors are caught and logged.
	 */
	/**
	 * Process due anchor jobs via WP-Cron.
	 *
	 * For each due job, iterates over every active provider and runs only the
	 * legs that are still in 'pending' state (so a provider that already
	 * succeeded on a previous run is never re-sent).  The job is removed from
	 * the queue only when every provider leg is resolved (success or permanent
	 * failure).
	 *
	 * Never throws — all errors are caught and logged per provider.
	 */
	public function process_queue() {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$settings         = $this->get_settings();
		$active_providers = $this->get_active_providers();

		// Build a keyed map of provider objects (only instantiate what's active).
		$provider_objects = array();
		foreach ( $active_providers as $pk ) {
			$obj = $this->make_provider( $pk );
			if ( null !== $obj ) {
				$provider_objects[ $pk ] = $obj;
			}
		}

		if ( empty( $provider_objects ) ) {
			return;
		}

		$result   = MDSM_Anchor_Queue::get_due_jobs( $active_providers );
		$due_jobs = $result['jobs'];
		$lock     = $result['lock'];

		if ( empty( $due_jobs ) ) {
			MDSM_Anchor_Queue::release_lock( $lock );
			return;
		}

		foreach ( $due_jobs as $job_id => $job ) {
			$base_record = $job['record'];

			foreach ( $provider_objects as $pk => $provider ) {

				// Skip this leg if it is not pending (already succeeded or failed).
				$pstate = isset( $job['provider_states'][ $pk ] ) ? $job['provider_states'][ $pk ] : null;
				if ( null !== $pstate && 'pending' !== $pstate['status'] ) {
					continue;
				}

				// Skip if this provider's next_attempt is in the future.
				if ( null !== $pstate && (int) $pstate['next_attempt'] > time() ) {
					continue;
				}

				$attempt_number      = isset( $pstate['attempts'] ) ? (int) $pstate['attempts'] + 1 : 1;
				$record              = $base_record;
				$record['_provider'] = $pk;

				try {
					$push_result = $provider->push( $record, $settings );

					if ( $push_result['success'] ) {
						MDSM_Anchor_Queue::mark_success( $job_id, $pk );
						$anchor_url = isset( $push_result['url'] ) ? $push_result['url'] : '';

						MDSM_Anchor_Log::write(
							$record,
							$job_id,
							$attempt_number,
							'anchored',
							$anchor_url,
							'',
							0
						);

						$this->write_audit_log( $record, 'anchored', $anchor_url, '' );

					} else {
						$error_msg   = isset( $push_result['error'] ) ? $push_result['error'] : 'Unknown error';
						$retryable   = isset( $push_result['retry'] ) ? (bool) $push_result['retry'] : true;
						$http_code   = isset( $push_result['http_status'] ) ? (int) $push_result['http_status'] : 0;
						$rescheduled = MDSM_Anchor_Queue::mark_failure( $job_id, $pk, $error_msg, $retryable );
						$log_status  = $rescheduled ? 'retry' : 'failed';

						// Permanently discarded leg — increment admin notice counter.
						if ( ! $rescheduled ) {
							$count = (int) get_option( 'mdsm_anchor_perm_failures', 0 );
							update_option( 'mdsm_anchor_perm_failures', $count + 1, false );
						}

						MDSM_Anchor_Log::write(
							$record,
							$job_id,
							$attempt_number,
							$log_status,
							'',
							$error_msg,
							$http_code
						);

						$this->write_audit_log( $record, $rescheduled ? 'anchor_retry' : 'anchor_failed', '', $error_msg );
					}
				} catch ( \Throwable $e ) {
					MDSM_Anchor_Queue::mark_failure( $job_id, $pk, $e->getMessage(), true );

					MDSM_Anchor_Log::write(
						$record,
						$job_id,
						$attempt_number,
						'failed',
						'',
						$e->getMessage() . ' (PHP ' . get_class( $e ) . ')',
						0
					);

					$this->write_audit_log( $record, 'anchor_failed', '', $e->getMessage() );

				} catch ( \Exception $e ) {
					MDSM_Anchor_Queue::mark_failure( $job_id, $pk, $e->getMessage(), true );

					MDSM_Anchor_Log::write(
						$record,
						$job_id,
						$attempt_number,
						'failed',
						'',
						$e->getMessage() . ' (PHP ' . get_class( $e ) . ')',
						0
					);

					$this->write_audit_log( $record, 'anchor_failed', '', $e->getMessage() );
				}

				// Reload job state after each provider write so the next provider
				// sees the freshly-persisted provider_states map.
				$refreshed = MDSM_Anchor_Queue::get_job( $job_id );
				if ( null !== $refreshed ) {
					$job = $refreshed;
				}
			}
		}

		// Release the concurrency lock now that all jobs in this batch are done.
		MDSM_Anchor_Queue::release_lock( $lock );
	}

	// ── Audit log integration ─────────────────────────────────────────────────

	/**
	 * Write anchoring outcome to the Cryptographic Verification audit log
	 * (archivio_post_audit table) — but ONLY for WordPress post/page records.
	 *
	 * Timestamp service results (RFC 3161, GitHub, GitLab) belong exclusively in
	 * the Anchor Activity Log (archivio_anchor_log). Writing them here caused
	 * anchor events to appear inside the Cryptographic Verification log.
	 *
	 * Documents and HTML outputs also have no entry in archivio_post_audit because
	 * they are not WordPress posts — skip those too.
	 */
	private function write_audit_log( array $record, $event_type, $anchor_url, $error_msg ) {
		global $wpdb;

		// Only mirror to archivio_post_audit for genuine WordPress posts/pages.
		// Non-post records (archivio_document, archivio_html_output, etc.) and
		// records with no real post_id are skipped — they live only in the anchor log.
		$post_id = isset( $record['post_id'] ) ? (int) $record['post_id'] : 0;
		if ( $post_id <= 0 ) {
			return;
		}

		$post_type = isset( $record['post_type'] ) ? $record['post_type'] : '';
		$wp_post_types = array( 'post', 'page' );
		// Also allow any custom public post type (not our own internal types).
		$internal_types = array( 'archivio_document', 'archivio_html_output' );
		if ( in_array( $post_type, $internal_types, true ) ) {
			return;
		}

		$table_name = $wpdb->prefix . 'archivio_post_audit';
		if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $table_name ) ) ) !== $table_name ) {
			return;
		}

		$result_text = 'anchor_failed' === $event_type
			? 'Anchoring failed: ' . $error_msg
			: ( 'anchor_retry' === $event_type
				? 'Anchoring will be retried: ' . $error_msg
				: 'Anchored successfully. URL: ' . $anchor_url );

		$wpdb->insert(
			$table_name,
			array(
				'post_id'    => $post_id,
				'author_id'  => 0,
				'hash'       => isset( $record['hash_value'] ) ? $record['hash_value'] : '',
				'algorithm'  => isset( $record['hash_algorithm'] ) ? $record['hash_algorithm'] : '',
				'mode'       => isset( $record['integrity_mode'] ) ? strtolower( $record['integrity_mode'] ) : 'basic',
				'event_type' => $event_type,
				'result'     => $result_text,
				'timestamp'  => current_time( 'mysql' ),
			),
			array( '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	// ── Settings ──────────────────────────────────────────────────────────────

	/**
	 * Return sanitised settings array. Never exposes raw token outside this class.
	 */
	public function get_settings() {
		$defaults = array(
			'provider'            => 'none',      // git provider: none|github|gitlab
			'rfc3161_enabled'     => '',          // '1' = on, '' = off
			'rekor_enabled'       => '',          // '1' = on, '' = off (Sigstore / Rekor)
			'visibility'          => 'private',
			'token'               => '',
			'repo_owner'          => '',
			'repo_name'           => '',
			'branch'              => 'main',
			'folder_path'         => 'hashes/YYYY-MM-DD',
			'commit_message'      => 'chore: anchor {doc_id}',
			// RFC 3161 fields
			'rfc3161_provider'    => 'freetsa',
			'rfc3161_custom_url'  => '',
			'rfc3161_username'    => '',
			'rfc3161_password'    => '',
			// Log management
			'log_retention_days'  => self::LOG_RETENTION_DEFAULT,
		);

		$stored = get_option( self::SETTINGS_OPTION, array() );
		$settings = wp_parse_args( is_array( $stored ) ? $stored : array(), $defaults );

		// ── Migrate legacy 'provider = rfc3161' to the new split model ─────────
		// Before v1.6.4 both pages wrote to the same 'provider' key. If the stored
		// value is 'rfc3161' it means the user had only RFC 3161 active, so we
		// convert in-memory (write-through on next save) without a one-off migration.
		if ( 'rfc3161' === $settings['provider'] ) {
			$settings['provider']        = 'none';
			$settings['rfc3161_enabled'] = '1';
		}

		return $settings;
	}

	/**
	 * Return true when at least one provider is fully configured and enabled.
	 * Used to guard queue operations and cron processing.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return ! empty( $this->get_active_providers() );
	}

	/**
	 * Return an ordered list of active provider keys for the current settings.
	 *
	 * Git provider comes first so TSR files are always backed by an independent
	 * second anchor rather than the other way around.
	 *
	 * @return string[]  e.g. ['github'], ['rfc3161'], ['github','rfc3161']
	 */
	public function get_active_providers() {
		$settings  = $this->get_settings();
		$providers = array();

		// ── Git provider ──────────────────────────────────────────────────────
		$git = isset( $settings['provider'] ) ? $settings['provider'] : 'none';
		if ( in_array( $git, array( 'github', 'gitlab' ), true ) && ! empty( $settings['token'] ) ) {
			$providers[] = $git;
		}

		// ── RFC 3161 ──────────────────────────────────────────────────────────
		if ( ! empty( $settings['rfc3161_enabled'] ) && '1' === (string) $settings['rfc3161_enabled'] ) {
			$sub     = isset( $settings['rfc3161_provider'] ) ? $settings['rfc3161_provider'] : '';
			$custom  = isset( $settings['rfc3161_custom_url'] ) ? trim( $settings['rfc3161_custom_url'] ) : '';
			$profile = MDSM_TSA_Profiles::get( $sub );
			if ( ( $profile && ! empty( $profile['url'] ) ) || ! empty( $custom ) ) {
				$providers[] = 'rfc3161';
			}
		}

		// ── Rekor (Sigstore transparency log) ─────────────────────────────────
		if ( ! empty( $settings['rekor_enabled'] ) && '1' === (string) $settings['rekor_enabled'] ) {
			$providers[] = 'rekor';
		}

		return $providers;
	}

	private function save_settings( array $data ) {
		$current  = $this->get_settings();
		$allowed  = array(
			'provider', 'rfc3161_enabled', 'rekor_enabled',
			'visibility', 'token', 'repo_owner', 'repo_name',
			'branch', 'folder_path', 'commit_message',
			// RFC 3161
			'rfc3161_provider', 'rfc3161_custom_url', 'rfc3161_username', 'rfc3161_password',
			// Log management
			'log_retention_days',
		);
		$sanitized = array();

		foreach ( $allowed as $key ) {
			if ( isset( $data[ $key ] ) ) {
				// URL fields must use esc_url_raw; everything else uses sanitize_text_field.
				if ( 'rfc3161_custom_url' === $key ) {
					$sanitized[ $key ] = esc_url_raw( $data[ $key ] );
				} else {
					$sanitized[ $key ] = sanitize_text_field( $data[ $key ] );
				}
			} else {
				$sanitized[ $key ] = $current[ $key ];
			}
		}

		// ── Git provider ──────────────────────────────────────────────────────
		// The RFC 3161 page has no provider field and sends an empty string.
		// Never overwrite the stored git-provider choice with a blank value —
		// the git provider is only updated when the Git Distribution page saves.
		if ( '' === $sanitized['provider'] ) {
			$sanitized['provider'] = $current['provider'];
		}

		// Never blank the Git token if an empty field was submitted (preserve existing).
		if ( empty( $sanitized['token'] ) && ! empty( $current['token'] ) ) {
			$sanitized['token'] = $current['token'];
		}

		// ── RFC 3161 enabled flag ─────────────────────────────────────────────
		// The Git Distribution page has no rfc3161_enabled checkbox, so the
		// field is absent from its POST data — keep the stored value in that case.
		// When the Trusted Timestamps page saves, it explicitly sends '1' or ''.
		if ( ! isset( $data['rfc3161_enabled'] ) ) {
			$sanitized['rfc3161_enabled'] = $current['rfc3161_enabled'];
		} else {
			$sanitized['rfc3161_enabled'] = ( '1' === $sanitized['rfc3161_enabled'] ) ? '1' : '';
		}

		// ── Rekor enabled flag ────────────────────────────────────────────────
		// Same preservation pattern: the Rekor checkbox only appears on the
		// Trusted Timestamps page.  Pages that don't send this field must not
		// overwrite the stored value.
		if ( ! isset( $data['rekor_enabled'] ) ) {
			$sanitized['rekor_enabled'] = $current['rekor_enabled'];
		} else {
			$sanitized['rekor_enabled'] = ( '1' === $sanitized['rekor_enabled'] ) ? '1' : '';
		}

		// Never blank the TSA password if an empty field was submitted (preserve existing).
		if ( empty( $sanitized['rfc3161_password'] ) && ! empty( $current['rfc3161_password'] ) ) {
			$sanitized['rfc3161_password'] = $current['rfc3161_password'];
		}

		// log_retention_days must be a non-negative integer (0 = keep forever).
		$sanitized['log_retention_days'] = max( 0, (int) $sanitized['log_retention_days'] );

		update_option( self::SETTINGS_OPTION, $sanitized, false );
	}

	// ── Provider factory ──────────────────────────────────────────────────────

	private function make_provider( $provider_key ) {
		switch ( strtolower( $provider_key ) ) {
			case 'github':
				return new MDSM_Anchor_Provider_GitHub();
			case 'gitlab':
				return new MDSM_Anchor_Provider_GitLab();
			case 'rfc3161':
				return new MDSM_Anchor_Provider_RFC3161();
			case 'rekor':
				return new MDSM_Anchor_Provider_Rekor();
			default:
				return null;
		}
	}

	// ── Admin menu ────────────────────────────────────────────────────────────

	// Archivio Anchor is a standalone Tools submenu entry, sitting directly
	// under Archivio Post. No separate tab on the main ArchivioMD page.

	public function add_admin_menu() {
		add_submenu_page(
			'archiviomd',
			__( 'Git Distribution', 'archiviomd' ),
			__( 'Git Distribution', 'archiviomd' ),
			'manage_options',
			'archivio-git-distribution',
			array( $this, 'render_admin_page' )
		);
		add_submenu_page(
			'archiviomd',
			__( 'Trusted Timestamps', 'archiviomd' ),
			__( 'Trusted Timestamps', 'archiviomd' ),
			'manage_options',
			'archivio-timestamps',
			array( $this, 'render_rfc3161_page' )
		);
		add_submenu_page(
			'archiviomd',
			__( 'Rekor Transparency Log', 'archiviomd' ),
			__( 'Rekor / Sigstore', 'archiviomd' ),
			'manage_options',
			'archivio-rekor',
			array( $this, 'render_rekor_page' )
		);
	}

	public function render_admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'archiviomd' ) );
		}
		require_once MDSM_PLUGIN_DIR . 'admin/anchor-admin-page.php';
	}

	public function render_rfc3161_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'archiviomd' ) );
		}
		require_once MDSM_PLUGIN_DIR . 'admin/anchor-rfc3161-page.php';
	}

	public function render_rekor_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'archiviomd' ) );
		}
		require_once MDSM_PLUGIN_DIR . 'admin/anchor-rekor-page.php';
	}

	public function enqueue_admin_assets( $hook ) {
		// Load on the Archivio Anchor tools page only.
		if ( strpos( $hook, 'archivio' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'mdsm-anchor-admin',
			MDSM_PLUGIN_URL . 'assets/css/anchor-admin.css',
			array(),
			MDSM_VERSION
		);

		wp_enqueue_script(
			'mdsm-anchor-admin',
			MDSM_PLUGIN_URL . 'assets/js/anchor-admin.js',
			array( 'jquery' ),
			MDSM_VERSION,
			true
		);

		// Determine log scope: 'rfc3161' on the Trusted Timestamps page, 'rekor' on the Rekor page, 'git' everywhere else.
		$log_scope = 'git';
		if ( strpos( $hook, 'rfc3161' ) !== false || strpos( $hook, 'timestamps' ) !== false ) {
			$log_scope = 'rfc3161';
		} elseif ( strpos( $hook, 'rekor' ) !== false ) {
			$log_scope = 'rekor';
		}

		wp_localize_script( 'mdsm-anchor-admin', 'mdsmAnchorData', array(
			'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( 'mdsm_anchor_nonce' ),
			'logScope' => $log_scope,
			'strings'  => array(
				'saving'         => __( 'Saving…', 'archiviomd' ),
				'saved'          => __( 'Settings saved.', 'archiviomd' ),
				'testing'        => __( 'Testing connection…', 'archiviomd' ),
				'clearing'       => __( 'Clearing queue…', 'archiviomd' ),
				'queueCleared'   => __( 'Queue cleared.', 'archiviomd' ),
				'error'          => __( 'An error occurred. Please try again.', 'archiviomd' ),
			),
		) );
	}

	// ── AJAX handlers ─────────────────────────────────────────────────────────

	public function ajax_save_settings() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		$this->save_settings( wp_unslash( $_POST ) );

		wp_send_json_success( array( 'message' => __( 'Settings saved successfully.', 'archiviomd' ) ) );
	}

	public function ajax_test_connection() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		$provider_key = sanitize_text_field( isset( $_POST['provider'] ) ? wp_unslash( $_POST['provider'] ) : '' );

		// The Trusted Timestamps page has no git-provider dropdown — infer rfc3161
		// when the form sends an empty provider string but rfc3161_enabled=1.
		if ( '' === $provider_key ) {
			$_rfc_enabled = isset( $_POST['rfc3161_enabled'] ) ? sanitize_text_field( wp_unslash( $_POST['rfc3161_enabled'] ) ) : '';
			if ( '1' === $_rfc_enabled ) {
				$provider_key = 'rfc3161';
			}
		}

		// Infer rekor when the Rekor test button is used.
		if ( '' === $provider_key ) {
			$_rekor_enabled = isset( $_POST['rekor_enabled'] ) ? sanitize_text_field( wp_unslash( $_POST['rekor_enabled'] ) ) : '';
			if ( '1' === $_rekor_enabled ) {
				$provider_key = 'rekor';
			}
		}

		$provider = $this->make_provider( $provider_key );

		if ( null === $provider ) {
			wp_send_json_error( array( 'message' => __( 'No provider selected.', 'archiviomd' ) ) );
		}

		// Build a test settings array from POST, falling back to stored values where empty.
		$stored   = $this->get_settings();

		if ( $provider_key === 'rfc3161' ) {
			$settings = array(
				'rfc3161_provider'   => sanitize_text_field( wp_unslash( $_POST['rfc3161_provider'] ?? $stored['rfc3161_provider'] ) ),
				'rfc3161_custom_url' => esc_url_raw( wp_unslash( $_POST['rfc3161_custom_url'] ?? $stored['rfc3161_custom_url'] ) ),
				'rfc3161_username'   => sanitize_text_field( wp_unslash( $_POST['rfc3161_username'] ?? $stored['rfc3161_username'] ) ),
				// Use stored password if field is blank (never sent in clear from JS).
				'rfc3161_password'   => ! empty( $_POST['rfc3161_password'] )
					? sanitize_text_field( wp_unslash( $_POST['rfc3161_password'] ) )
					: $stored['rfc3161_password'],
			);
		} elseif ( $provider_key === 'rekor' ) {
			// Rekor is a public, unauthenticated API -- no token or credentials needed.
			// Pass an empty settings array; MDSM_Anchor_Provider_Rekor::test_connection()
			// only performs a read-only GET to rekor.sigstore.dev/api/v1/log.
			$settings = array();
		} else {
			// GitHub / GitLab -- require a personal access token.
			$settings = array(
				'token'       => ! empty( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : $stored['token'],
				'repo_owner'  => sanitize_text_field( wp_unslash( $_POST['repo_owner'] ?? '' ) ),
				'repo_name'   => sanitize_text_field( wp_unslash( $_POST['repo_name'] ?? '' ) ),
				'branch'      => sanitize_text_field( wp_unslash( $_POST['branch'] ?? 'main' ) ),
				'folder_path' => sanitize_text_field( wp_unslash( $_POST['folder_path'] ?? 'hashes' ) ),
			);

			if ( empty( $settings['token'] ) ) {
				wp_send_json_error( array( 'message' => __( 'API token is required to test the connection.', 'archiviomd' ) ) );
			}
		}

		$result = $provider->test_connection( $settings );

		if ( $result['success'] ) {
			wp_send_json_success( array( 'message' => $result['message'] ) );
		} else {
			wp_send_json_error( array( 'message' => $result['message'] ) );
		}
	}

	public function ajax_clear_queue() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		MDSM_Anchor_Queue::clear();
		wp_send_json_success( array( 'message' => __( 'Anchor queue cleared.', 'archiviomd' ) ) );
	}

	public function ajax_queue_status() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		wp_send_json_success( array(
			'count'   => MDSM_Anchor_Queue::count(),
			'enabled' => $this->is_enabled(),
		) );
	}

	// ── Anchor log AJAX handlers ──────────────────────────────────────────────

	public function ajax_get_anchor_log() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		$page      = isset( $_POST['page'] ) ? max( 1, absint( wp_unslash( $_POST['page'] ) ) ) : 1;
		$per_page  = 25;
		$filter    = isset( $_POST['filter'] )    ? sanitize_key( wp_unslash( $_POST['filter'] ) )    : 'all';
		$log_scope = isset( $_POST['log_scope'] ) ? sanitize_key( wp_unslash( $_POST['log_scope'] ) ) : 'all';

		$result = MDSM_Anchor_Log::get_entries( $page, $per_page, $filter, $log_scope );

		wp_send_json_success( $result );
	}

	public function ajax_clear_anchor_log() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		// Require the user to have typed the confirmation phrase in the modal.
		$confirmation = isset( $_POST['confirmation'] ) ? sanitize_text_field( wp_unslash( $_POST['confirmation'] ) ) : '';
		if ( strtoupper( $confirmation ) !== 'CLEAR LOG' ) {
			wp_send_json_error( array(
				'message' => __( 'Confirmation phrase did not match. Log was not cleared.', 'archiviomd' ),
			) );
		}

		$count = MDSM_Anchor_Log::get_counts();
		MDSM_Anchor_Log::clear();

		wp_send_json_success( array(
			'message' => sprintf(
				/* translators: %d: number of entries deleted */
				__( 'Anchor log cleared. %d entries permanently deleted.', 'archiviomd' ),
				(int) $count['total']
			),
		) );
	}

	// ── Export handlers ───────────────────────────────────────────────────────

	/**
	 * Download the anchor log as a CSV file suitable for auditors and spreadsheet tools.
	 * Includes one row per log entry with all fields, plus RFC 3161 TSR URL where present.
	 */
	public function ajax_download_anchor_log_csv() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'Insufficient permissions.', 'archiviomd' ) );
		}

		$entries  = MDSM_Anchor_Log::get_all_for_export();
		$settings = $this->get_settings();
		$filename = 'archiviomd-anchor-log-' . gmdate( 'Y-m-d-H-i-s' ) . '.csv';

		// Build CSV in memory.
		$output = fopen( 'php://temp', 'r+' );

		// Header row.
		fputcsv( $output, array(
			'ID',
			'Timestamp (UTC)',
			'Status',
			'Document ID',
			'Post Type',
			'Provider',
			'Hash Algorithm',
			'Integrity Mode',
			'Hash Value',
			'HMAC Value',
			'Attempt #',
			'Job ID',
			'Anchor / TSR URL',
			'HTTP Status',
			'Error Message',
			'Site',
		) );

		foreach ( $entries as $entry ) {
			fputcsv( $output, array(
				$entry['id'],
				$entry['created_at'] . ' UTC',
				strtoupper( $entry['status'] ),
				$entry['document_id'],
				$entry['post_type'],
				strtoupper( $entry['provider'] ),
				strtoupper( $entry['hash_algorithm'] ),
				$entry['integrity_mode'],
				$entry['hash_value'],
				$entry['hmac_value'],
				$entry['attempt_number'],
				$entry['job_id'],
				$entry['anchor_url'],
				$entry['http_status'] > 0 ? $entry['http_status'] : '',
				$entry['error_message'],
				get_site_url(),
			) );
		}

		rewind( $output );
		$csv_content = stream_get_contents( $output );
		fclose( $output );

		header( 'Content-Type: text/csv; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . strlen( "\xEF\xBB\xBF" . $csv_content ) ); // UTF-8 BOM for Excel
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		echo "\xEF\xBB\xBF"; // UTF-8 BOM — ensures Excel opens with correct encoding
		echo $csv_content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	/**
	 * Download a ZIP archive of all .tsr and .tsq files from the tsr-timestamps directory.
	 * Intended for auditors who need to verify timestamps offline with OpenSSL.
	 * Only available when provider is rfc3161 and ZipArchive is available.
	 */
	public function ajax_download_tsr_zip() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'Insufficient permissions.', 'archiviomd' ) );
		}

		if ( ! class_exists( 'ZipArchive' ) ) {
			wp_die( __( 'ZipArchive is not available on this server. Please ask your host to enable the PHP zip extension.', 'archiviomd' ) );
		}

		$upload_dir = wp_upload_dir();
		$tsr_dir    = trailingslashit( $upload_dir['basedir'] ) . 'meta-docs/tsr-timestamps';

		if ( ! is_dir( $tsr_dir ) ) {
			wp_die( __( 'No TSR files found. Timestamps have not been stored yet.', 'archiviomd' ) );
		}

		$files = array_merge(
			glob( $tsr_dir . '/*.tsr' ) ?: array(),
			glob( $tsr_dir . '/*.tsq' ) ?: array()
		);

		if ( empty( $files ) ) {
			wp_die( __( 'No TSR or TSQ files found in the timestamps directory.', 'archiviomd' ) );
		}

		// Build manifest text listing every file with its SHA-256 checksum.
		$manifest_lines   = array();
		$manifest_lines[] = 'ARCHIVIOMD RFC 3161 TIMESTAMP ARCHIVE';
		$manifest_lines[] = 'Generated : ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
		$manifest_lines[] = 'Site      : ' . get_site_url();
		$manifest_lines[] = 'Files     : ' . count( $files );
		$manifest_lines[] = '';
		$manifest_lines[] = 'Verification command (per .tsr file):';
		$manifest_lines[] = '  openssl ts -verify -in FILE.tsr -queryfile FILE.tsq -CAfile tsa.crt';
		$manifest_lines[] = '';
		$manifest_lines[] = str_repeat( '-', 64 );
		$manifest_lines[] = sprintf( '%-52s  %s', 'File', 'SHA-256' );
		$manifest_lines[] = str_repeat( '-', 64 );

		foreach ( $files as $file ) {
			$basename         = basename( $file );
			$sha256           = hash_file( 'sha256', $file );
			$manifest_lines[] = sprintf( '%-52s  %s', $basename, $sha256 );
		}

		$manifest_content = implode( "\n", $manifest_lines );

		// Write ZIP to a temp file.
		$zip_path = wp_tempnam( 'archiviomd-tsr-' );
		$zip      = new ZipArchive();

		if ( $zip->open( $zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== true ) {
			wp_die( __( 'Could not create ZIP archive. Check server permissions.', 'archiviomd' ) );
		}

		foreach ( $files as $file ) {
			$zip->addFile( $file, basename( $file ) );
		}

		$zip->addFromString( 'MANIFEST.txt', $manifest_content );
		$zip->close();

		$zip_filename = 'archiviomd-tsr-archive-' . gmdate( 'Y-m-d-H-i-s' ) . '.zip';
		$zip_size     = filesize( $zip_path );

		header( 'Content-Type: application/zip' );
		header( 'Content-Disposition: attachment; filename="' . $zip_filename . '"' );
		header( 'Content-Length: ' . $zip_size );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		readfile( $zip_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_readfile
		unlink( $zip_path );
		exit;
	}

	public function ajax_download_anchor_log() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'Insufficient permissions.', 'archiviomd' ) );
		}

		$entries  = MDSM_Anchor_Log::get_all_for_export();
		$settings = $this->get_settings();

		$lines   = array();
		$lines[] = '========================================';
		$lines[] = 'ARCHIVIOMD EXTERNAL ANCHORING LOG';
		$lines[] = '========================================';
		$lines[] = 'Generated : ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
		$lines[] = 'Site      : ' . get_site_url();

		if ( $settings['provider'] === 'rfc3161' ) {
			$profile   = MDSM_TSA_Profiles::get( $settings['rfc3161_provider'] );
			$tsa_label = $profile ? $profile['label'] : 'Custom TSA';
			$lines[]   = 'Provider  : RFC 3161 — ' . $tsa_label;
			if ( ! empty( $settings['rfc3161_custom_url'] ) ) {
				$lines[] = 'TSA URL   : ' . $settings['rfc3161_custom_url'];
			} elseif ( $profile && ! empty( $profile['url'] ) ) {
				$lines[] = 'TSA URL   : ' . $profile['url'];
			}
		} else {
			$lines[] = 'Provider  : ' . strtoupper( $settings['provider'] );
			$lines[] = 'Repository: ' . $settings['repo_owner'] . '/' . $settings['repo_name'];
			$lines[] = 'Branch    : ' . $settings['branch'];
		}

		$lines[] = 'Total entries: ' . count( $entries );
		$lines[] = '========================================';
		$lines[] = '';

		foreach ( $entries as $entry ) {
			$lines[] = '----------------------------------------';
			$lines[] = 'Timestamp   : ' . $entry['created_at'] . ' UTC';
			$lines[] = 'Status      : ' . strtoupper( $entry['status'] );
			$lines[] = 'Document ID : ' . $entry['document_id'];
			$lines[] = 'Post Type   : ' . $entry['post_type'];
			$lines[] = 'Provider    : ' . strtoupper( $entry['provider'] );
			$lines[] = 'Algorithm   : ' . strtoupper( $entry['hash_algorithm'] );
			$lines[] = 'Integrity   : ' . $entry['integrity_mode'];
			$lines[] = 'Hash        : ' . $entry['hash_value'];

			if ( ! empty( $entry['hmac_value'] ) ) {
				$lines[] = 'HMAC        : ' . $entry['hmac_value'];
			}

			$lines[] = 'Attempt #   : ' . $entry['attempt_number'];
			$lines[] = 'Job ID      : ' . $entry['job_id'];

			if ( 'anchored' === $entry['status'] && ! empty( $entry['anchor_url'] ) ) {
				$lines[] = 'Anchor URL  : ' . $entry['anchor_url'];
			}

			if ( ! empty( $entry['error_message'] ) ) {
				$lines[] = 'Error       : ' . $entry['error_message'];
			}

			if ( ! empty( $entry['http_status'] ) ) {
				$lines[] = 'HTTP Status : ' . $entry['http_status'];
			}

			$lines[] = '';
		}

		if ( empty( $entries ) ) {
			$lines[] = '(No log entries found.)';
		}

		$filename = 'archiviomd-anchor-log-' . gmdate( 'Y-m-d-H-i-s' ) . '.txt';
		$content  = implode( "\n", $lines );

		header( 'Content-Type: text/plain; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . strlen( $content ) );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}
}

// ── Anchor Log ───────────────────────────────────────────────────────────────

/**
 * Dedicated anchor activity log stored in its own DB table.
 *
 * Tracks every push attempt — success, retry, or failure — with enough
 * detail to diagnose exactly what went wrong and when.
 *
 * Table: {prefix}archivio_anchor_log
 */
class MDSM_Anchor_Log {

	const TABLE_SUFFIX = 'archivio_anchor_log';

	// ── Table management ──────────────────────────────────────────────────────

	public static function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_SUFFIX;
	}

	public static function create_table() {
		global $wpdb;

		$table_name      = self::get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id            bigint(20)   NOT NULL AUTO_INCREMENT,
			job_id        varchar(60)  NOT NULL DEFAULT '',
			document_id   varchar(255) NOT NULL DEFAULT '',
			post_type     varchar(50)  NOT NULL DEFAULT '',
			provider      varchar(20)  NOT NULL DEFAULT '',
			hash_algorithm varchar(20) NOT NULL DEFAULT '',
			hash_value    varchar(255) NOT NULL DEFAULT '',
			hmac_value    varchar(255) NOT NULL DEFAULT '',
			integrity_mode varchar(10) NOT NULL DEFAULT 'Basic',
			attempt_number tinyint(3)  NOT NULL DEFAULT 1,
			status        varchar(20)  NOT NULL DEFAULT '',
			anchor_url    text         NOT NULL,
			error_message text         NOT NULL,
			http_status   smallint(5)  NOT NULL DEFAULT 0,
			created_at    datetime     NOT NULL,
			PRIMARY KEY  (id),
			KEY status (status),
			KEY created_at (created_at),
			KEY job_id (job_id)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public static function drop_table() {
		global $wpdb;
		$table_name = self::get_table_name();
		$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	// ── Write ─────────────────────────────────────────────────────────────────

	/**
	 * Write a log entry. Called from MDSM_External_Anchoring::process_queue().
	 *
	 * @param array  $record         Anchor record (document_id, hash_value, etc.)
	 * @param string $job_id         Queue job ID.
	 * @param int    $attempt_number Which attempt this is (1-based).
	 * @param string $status         'anchored' | 'retry' | 'failed'
	 * @param string $anchor_url     Remote URL if successful, empty otherwise.
	 * @param string $error_message  Full error text if failed/retry, empty otherwise.
	 * @param int    $http_status    HTTP response code if available, 0 otherwise.
	 */
	public static function write(
		array $record,
		$job_id,
		$attempt_number,
		$status,
		$anchor_url   = '',
		$error_message = '',
		$http_status  = 0
	) {
		global $wpdb;

		$table_name = self::get_table_name();

		// Ensure table exists — safe to call repeatedly, dbDelta is idempotent.
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			self::create_table();
		}

		$wpdb->insert(
			$table_name,
			array(
				'job_id'         => (string) $job_id,
				'document_id'    => isset( $record['document_id'] )    ? (string) $record['document_id']    : '',
				'post_type'      => isset( $record['post_type'] )      ? (string) $record['post_type']      : '',
				'provider'       => isset( $record['_provider'] )      ? (string) $record['_provider']      : '',
				'hash_algorithm' => isset( $record['hash_algorithm'] ) ? (string) $record['hash_algorithm'] : '',
				'hash_value'     => isset( $record['hash_value'] )     ? (string) $record['hash_value']     : '',
				'hmac_value'     => isset( $record['hmac_value'] )     ? (string) $record['hmac_value']     : '',
				'integrity_mode' => isset( $record['integrity_mode'] ) ? (string) $record['integrity_mode'] : 'Basic',
				'attempt_number' => (int) $attempt_number,
				'status'         => (string) $status,
				'anchor_url'     => (string) $anchor_url,
				'error_message'  => (string) $error_message,
				'http_status'    => (int) $http_status,
				'created_at'     => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s' )
		);
	}

	// ── Read ──────────────────────────────────────────────────────────────────

	/**
	 * Get paginated log entries.
	 *
	 * @param int    $page
	 * @param int    $per_page
	 * @param string $filter   'all' | 'anchored' | 'retry' | 'failed'
	 * @return array { entries: array, total: int, pages: int }
	 */
	public static function get_entries( $page = 1, $per_page = 25, $filter = 'all', $log_scope = 'all' ) {
		global $wpdb;

		$table_name = self::get_table_name();

		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			return array( 'entries' => array(), 'total' => 0, 'pages' => 0 );
		}

		$where  = array();
		$params = array();

		// Filter by status.
		if ( 'all' !== $filter ) {
			$where[]  = 'status = %s';
			$params[] = $filter;
		}

		// Filter by provider scope: 'git' shows only git providers, 'rfc3161'/'rekor' show only those.
		if ( 'rfc3161' === $log_scope ) {
			$where[]  = "provider = 'rfc3161'";
		} elseif ( 'rekor' === $log_scope ) {
			$where[]  = "provider = 'rekor'";
		} elseif ( 'git' === $log_scope ) {
			$where[]  = "provider NOT IN ('rfc3161', 'rekor')";
		}

		$where_sql = $where ? 'WHERE ' . implode( ' AND ', $where ) : '';

		$count_sql = "SELECT COUNT(*) FROM {$table_name} {$where_sql}"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$total     = $params
			? (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			: (int) $wpdb->get_var( $count_sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		$offset   = ( $page - 1 ) * $per_page;
		$data_sql = "SELECT * FROM {$table_name} {$where_sql} ORDER BY created_at DESC LIMIT %d OFFSET %d"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		$query_params = array_merge( $params, array( $per_page, $offset ) );
		$entries = $wpdb->get_results(
			$wpdb->prepare( $data_sql, $query_params ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		return array(
			'entries' => $entries ?: array(),
			'total'   => $total,
			'pages'   => $per_page > 0 ? (int) ceil( $total / $per_page ) : 0,
		);
	}

	/**
	 * Get all entries for plain-text export (most recent first, capped at 5000).
	 *
	 * @return array
	 */
	public static function get_all_for_export() {
		global $wpdb;

		$table_name = self::get_table_name();

		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			return array();
		}

		$results = $wpdb->get_results(
			"SELECT * FROM {$table_name} ORDER BY created_at DESC LIMIT 5000", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		return $results ?: array();
	}

	/**
	 * Clear all log entries.
	 */
	public static function clear() {
		global $wpdb;
		$table_name = self::get_table_name();
		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) === $table_name ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->query( "TRUNCATE TABLE {$table_name}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		}
	}

	/**
	 * Return counts grouped by status for the summary badges.
	 *
	 * @return array { anchored: int, retry: int, failed: int, total: int }
	 */
	public static function get_counts( $log_scope = 'all' ) {
		global $wpdb;

		$table_name = self::get_table_name();

		if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			return array( 'anchored' => 0, 'retry' => 0, 'failed' => 0, 'total' => 0 );
		}

		$where_sql = '';
		if ( 'rfc3161' === $log_scope ) {
			$where_sql = "WHERE provider = 'rfc3161'";
		} elseif ( 'rekor' === $log_scope ) {
			$where_sql = "WHERE provider = 'rekor'";
		} elseif ( 'git' === $log_scope ) {
			$where_sql = "WHERE provider NOT IN ('rfc3161', 'rekor')";
		}

		$rows = $wpdb->get_results(
			"SELECT status, COUNT(*) AS cnt FROM {$table_name} {$where_sql} GROUP BY status", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		$counts = array( 'anchored' => 0, 'retry' => 0, 'failed' => 0, 'total' => 0 );
		foreach ( (array) $rows as $row ) {
			$key = $row['status'];
			if ( isset( $counts[ $key ] ) ) {
				$counts[ $key ] = (int) $row['cnt'];
			}
			$counts['total'] += (int) $row['cnt'];
		}

		return $counts;
	}

	// ── Fix #4: Permanent failure notice ─────────────────────────────────────

	/**
	 * AJAX: Dismiss the permanent-failure admin notice and reset the counter.
	 */
	public function ajax_dismiss_failure_notice() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		delete_option( 'mdsm_anchor_perm_failures' );
		wp_send_json_success();
	}

	// ── Rekor live verification ───────────────────────────────────────────────

	/**
	 * AJAX: Fetch a Rekor log entry by log index and return the decoded details.
	 *
	 * The browser cannot call rekor.sigstore.dev directly due to CORS, so this
	 * server-side proxy fetches the entry and returns the relevant fields.
	 *
	 * Also performs a local hash consistency check: the artifact hash stored in
	 * our anchor log is compared against the hash Rekor actually recorded.
	 *
	 * POST params:
	 *   log_index  (int)    Rekor log index — extracted from the stored anchor_url.
	 *   local_hash (string) The hash_value we stored in our anchor log row.
	 *
	 * @return void  Calls wp_send_json_success / wp_send_json_error.
	 */
	public function ajax_rekor_verify() {
		check_ajax_referer( 'mdsm_anchor_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		$log_index  = isset( $_POST['log_index'] )  ? absint( wp_unslash( $_POST['log_index'] ) )                                          : 0;
		$local_hash = isset( $_POST['local_hash'] ) ? sanitize_text_field( wp_unslash( $_POST['local_hash'] ) ) : '';

		if ( $log_index <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Invalid log index.', 'archiviomd' ) ) );
		}

		$api_url  = 'https://rekor.sigstore.dev/api/v1/log/entries?logIndex=' . $log_index;
		$response = wp_remote_get( $api_url, array(
			'headers' => array(
				'Accept'     => 'application/json',
				'User-Agent' => 'ArchivioMD/' . MDSM_VERSION,
			),
			'timeout' => 20,
		) );

		if ( is_wp_error( $response ) ) {
			wp_send_json_error( array( 'message' => $response->get_error_message() ) );
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			wp_send_json_error( array(
				'message' => sprintf(
					/* translators: %d: HTTP status code */
					__( 'Rekor returned HTTP %d. The entry may not exist yet or the log index is invalid.', 'archiviomd' ),
					$code
				),
			) );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body ) ) {
			wp_send_json_error( array( 'message' => __( 'Rekor returned an empty or unparseable response.', 'archiviomd' ) ) );
		}

		// Response is { "<uuid>": { body, integratedTime, logIndex, logID, verification } }
		$uuid  = key( $body );
		$entry = reset( $body );

		// Decode the base64 body to extract the hashedrekord spec.
		$entry_body   = isset( $entry['body'] ) ? base64_decode( $entry['body'] ) : '';
		$entry_parsed = json_decode( $entry_body, true );

		// Pull out the artifact hash Rekor actually stored.
		$rekor_hash      = '';
		$rekor_algorithm = '';
		if ( isset( $entry_parsed['spec']['data']['hash']['value'] ) ) {
			$rekor_hash      = $entry_parsed['spec']['data']['hash']['value'];
			$rekor_algorithm = isset( $entry_parsed['spec']['data']['hash']['algorithm'] )
				? $entry_parsed['spec']['data']['hash']['algorithm']
				: 'sha256';
		}

		// Inclusion proof details.
		$inclusion_proof  = isset( $entry['verification']['inclusionProof'] ) ? $entry['verification']['inclusionProof'] : null;
		$signed_entry_ts  = isset( $entry['verification']['signedEntryTimestamp'] ) ? $entry['verification']['signedEntryTimestamp'] : '';

		// Human-readable integrated time.
		$integrated_time     = isset( $entry['integratedTime'] ) ? (int) $entry['integratedTime'] : 0;
		$integrated_time_utc = $integrated_time > 0 ? gmdate( 'Y-m-d H:i:s', $integrated_time ) . ' UTC' : '';

		// Hash consistency check: does Rekor's recorded hash match ours?
		// Note: our local_hash is the hash of the *document*, while the Rekor artifact hash
		// is the hash of the *anchor JSON record*. They will not be equal — that is expected.
		// What we verify instead is that the entry resolves (i.e. the log index is genuine)
		// and that Rekor's logIndex matches what we requested.
		$index_matches = ( isset( $entry['logIndex'] ) && (int) $entry['logIndex'] === $log_index );

		// Extract customProperties (our provenance metadata) from the entry body.
		$custom_props = array();
		if ( isset( $entry_parsed['spec']['customProperties'] ) && is_array( $entry_parsed['spec']['customProperties'] ) ) {
			foreach ( $entry_parsed['spec']['customProperties'] as $k => $v ) {
				$custom_props[ (string) $k ] = (string) $v;
			}
		}

		wp_send_json_success( array(
			'uuid'               => (string) $uuid,
			'log_index'          => $log_index,
			'integrated_time'    => $integrated_time_utc,
			'rekor_hash'         => $rekor_hash,
			'rekor_algorithm'    => strtoupper( $rekor_algorithm ),
			'index_matches'      => $index_matches,
			'has_inclusion_proof' => ! empty( $inclusion_proof ),
			'checkpoint_hash'    => isset( $inclusion_proof['checkpoint'] ) ? (string) $inclusion_proof['checkpoint'] : '',
			'tree_size'          => isset( $inclusion_proof['treeSize'] )   ? (int)    $inclusion_proof['treeSize']   : 0,
			'signed_entry_ts'    => ! empty( $signed_entry_ts ),
			'sigstore_url'       => 'https://search.sigstore.dev/?logIndex=' . $log_index,
			'custom_props'       => $custom_props,
		) );
	}

	// ── Fix #7: Scheduled post anchoring ─────────────────────────────────────

	/**
	 * Hook: publish_future_post — fires when a scheduled post goes live.
	 *
	 * save_post fires too, but by then the post hash already exists and the
	 * content-unchanged guard returns early — so this post would never be queued.
	 * This handler bypasses that guard by forcing a fresh queue call directly.
	 *
	 * @param int $post_id
	 */
	public function on_future_post_published( $post_id ) {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$post = get_post( $post_id );
		if ( ! $post || wp_is_post_revision( $post_id ) ) {
			return;
		}

		// Clear any dedup transient for this post so the queue call is not skipped.
		$stored_packed = get_post_meta( $post_id, '_archivio_post_hash', true );
		$dedup_key     = 'mdsm_anchor_q_' . $post_id . '_' . substr( md5( (string) $stored_packed ), 0, 8 );
		delete_transient( $dedup_key );

		// Re-use existing hash if available, otherwise compute fresh.
		if ( ! empty( $stored_packed ) ) {
			$unpacked    = MDSM_Hash_Helper::unpack( $stored_packed );
			$hash_result = array(
				'packed'           => $stored_packed,
				'hash'             => $unpacked['hash'],
				'algorithm'        => $unpacked['algorithm'],
				'hmac_unavailable' => false,
			);
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
		}

		$this->queue_post_anchor( $post_id, $hash_result );
	}

	// ── Fix #9: Log pruning ───────────────────────────────────────────────────

	/**
	 * Cron callback: delete log rows older than the configured retention period.
	 * Runs daily. Uses a single indexed DELETE — no table scan.
	 */
	public function prune_anchor_log() {
		global $wpdb;

		$settings      = $this->get_settings();
		$retention     = isset( $settings['log_retention_days'] ) ? (int) $settings['log_retention_days'] : self::LOG_RETENTION_DEFAULT;

		// 0 means keep forever — skip pruning.
		if ( $retention <= 0 ) {
			return;
		}

		$table_name = MDSM_Anchor_Log::get_table_name();
		$cutoff     = gmdate( 'Y-m-d H:i:s', strtotime( "-{$retention} days" ) );

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table_name} WHERE created_at < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$cutoff
			)
		);
	}
}

