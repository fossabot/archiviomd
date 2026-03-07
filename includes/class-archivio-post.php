<?php
/**
 * Archivio Post - Content Hash Verification System
 *
 * @package ArchivioMD
 * @since   1.2.0
 * @updated 1.4.0 – HMAC Integrity Mode (hash_hmac via wp-config.php constant)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class MDSM_Archivio_Post
 *
 * Handles deterministic hash generation and verification for WordPress posts.
 *
 * Storage format for hashes:
 *   Standard:  "sha256:hex"        (or legacy bare hex)
 *   HMAC:      "hmac-sha256:hex"
 *
 * The mode tag in the packed string drives every downstream decision
 * (verification, audit log, CSV export, download file) — global settings
 * are never used for verification of existing hashes.
 */
class MDSM_Archivio_Post {

	private static $instance    = null;
	private $audit_table;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		global $wpdb;
		$this->audit_table = $wpdb->prefix . 'archivio_post_audit';
		
		// Ensure table exists and has correct structure
		$this->ensure_table_structure();
		
		$this->init_hooks();
	}
	
	/**
	 * Ensure audit table exists and has correct structure
	 */
	private function ensure_table_structure() {
		global $wpdb;
		
		try {
			$table_name = $wpdb->prefix . 'archivio_post_audit';
			
			// Check if table exists
			if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) !== $table_name ) {
				// Table doesn't exist, create it
				self::create_audit_table();
				return;
			}
			
			// Table exists, check if post_type column exists
			$columns = $wpdb->get_col( "SHOW COLUMNS FROM {$table_name}" );
			if ( ! in_array( 'post_type', $columns, true ) ) {
				// Migration needed for v1.5.9+
				$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN post_type varchar(20) NOT NULL DEFAULT 'post' AFTER post_id, ADD KEY post_type (post_type)" );
			}
		} catch ( Exception $e ) {
			// Silently fail - table will be checked again on next request
		}
	}

	private function init_hooks() {
		if ( is_admin() ) {
			add_action( 'admin_menu', array( $this, 'add_admin_menu' ), 20 );
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
			add_action( 'admin_notices',         array( $this, 'admin_hmac_notices' ) );
			add_action( 'admin_notices',         array( $this, 'admin_signing_notices' ) );
		}

		add_action( 'save_post',      array( $this, 'maybe_generate_hash' ), 10, 3 );
		add_action( 'add_meta_boxes', array( $this, 'add_badge_meta_box' ) );
		add_action( 'save_post',      array( $this, 'save_badge_meta_box' ), 10, 2 );

		add_filter( 'the_content', array( $this, 'maybe_display_badge' ), 20 );
		add_filter( 'the_title',   array( $this, 'maybe_display_title_badge' ), 10, 2 );

		add_shortcode( 'hash_verify', array( $this, 'shortcode_verify_badge' ) );

		add_action( 'wp_ajax_archivio_post_download_verification',        array( $this, 'ajax_download_verification' ) );
		add_action( 'wp_ajax_nopriv_archivio_post_download_verification',  array( $this, 'ajax_download_verification' ) );
		add_action( 'wp_ajax_archivio_post_get_audit_logs',               array( $this, 'ajax_get_audit_logs' ) );
		add_action( 'wp_ajax_archivio_post_save_settings',                array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_archivio_post_fix_settings',                 array( $this, 'ajax_fix_settings' ) );
		add_action( 'wp_ajax_archivio_post_export_audit_csv',             array( $this, 'ajax_export_audit_csv' ) );
		add_action( 'wp_ajax_archivio_post_recreate_table',               array( $this, 'ajax_recreate_table' ) );
		add_action( 'wp_ajax_archivio_post_save_algorithm',               array( $this, 'ajax_save_algorithm' ) );
		add_action( 'wp_ajax_archivio_post_save_hmac_settings',           array( $this, 'ajax_save_hmac_settings' ) );
		add_action( 'wp_ajax_archivio_post_save_extended_settings',       array( $this, 'ajax_save_extended_settings' ) );
		add_action( 'wp_ajax_archivio_rsa_save_settings',                 array( $this, 'ajax_rsa_save_settings'       ) );
		add_action( 'wp_ajax_archivio_rsa_upload_key',                    array( $this, 'ajax_rsa_upload_key'          ) );
		add_action( 'wp_ajax_archivio_rsa_upload_cert',                   array( $this, 'ajax_rsa_upload_cert'         ) );
		add_action( 'wp_ajax_archivio_rsa_clear_key',                     array( $this, 'ajax_rsa_clear_key'           ) );
		add_action( 'wp_ajax_archivio_rsa_clear_cert',                    array( $this, 'ajax_rsa_clear_cert'          ) );
		add_action( 'wp_ajax_archivio_cms_save_settings',                 array( $this, 'ajax_cms_save_settings'       ) );
		add_action( 'wp_ajax_archivio_jsonld_save_settings',              array( $this, 'ajax_jsonld_save_settings'    ) );
		add_action( 'wp_ajax_archivio_dane_save_settings',                array( $this, 'ajax_dane_save_settings'     ) );
		add_action( 'wp_ajax_archivio_dane_health_check',                 array( $this, 'ajax_dane_health_check'      ) );
		add_action( 'wp_ajax_archivio_dane_tlsa_check',                   array( $this, 'ajax_dane_tlsa_check'        ) );
		add_action( 'wp_ajax_archivio_dane_start_rotation',               array( $this, 'ajax_dane_start_rotation'   ) );
		add_action( 'wp_ajax_archivio_dane_finish_rotation',              array( $this, 'ajax_dane_finish_rotation'  ) );
		add_action( 'wp_ajax_archivio_dane_dismiss_notice',               array( $this, 'ajax_dane_dismiss_notice'   ) );

		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_frontend_assets' ) );
	}

	public function add_admin_menu() {
		add_submenu_page(
			'archiviomd',
			__( 'Cryptographic Verification', 'archiviomd' ),
			__( 'Cryptographic Verification', 'archiviomd' ),
			'manage_options',
			'archivio-post',
			array( $this, 'render_admin_page' )
		);
	}

	public function enqueue_admin_assets( $hook ) {
		// Only load on our plugin pages - check if we're on an archiviomd page
		if ( strpos( $hook, 'archivio' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'archivio-post-admin',
			MDSM_PLUGIN_URL . 'assets/css/archivio-post-admin.css',
			array(),
			MDSM_VERSION
		);

		wp_enqueue_script(
			'archivio-post-admin',
			MDSM_PLUGIN_URL . 'assets/js/archivio-post-admin.js',
			array( 'jquery' ),
			MDSM_VERSION,
			true
		);

		wp_localize_script( 'archivio-post-admin', 'archivioPostData', array(
			'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
			'nonce'          => wp_create_nonce( 'archivio_post_nonce' ),
			'checkboxStates' => array(
				'auto-generate'   => (bool) get_option( 'archivio_post_auto_generate', false ),
				'show-badge'      => (bool) get_option( 'archivio_post_show_badge', false ),
				'show-badge-posts'=> (bool) get_option( 'archivio_post_show_badge_posts', false ),
				'show-badge-pages'=> (bool) get_option( 'archivio_post_show_badge_pages', false ),
			),
			'strings' => array(
				'saving'  => __( 'Saving...', 'archiviomd' ),
				'saved'   => __( 'Settings saved successfully!', 'archiviomd' ),
				'error'   => __( 'Error occurred. Please try again.', 'archiviomd' ),
				'loading' => __( 'Loading...', 'archiviomd' ),
			),
		) );
	}

	public function enqueue_frontend_assets() {
		if ( ! is_singular() ) {
			return;
		}

		wp_enqueue_style(
			'archivio-post-frontend',
			MDSM_PLUGIN_URL . 'assets/css/archivio-post-frontend.css',
			array(),
			MDSM_VERSION
		);

		wp_enqueue_script(
			'archivio-post-frontend',
			MDSM_PLUGIN_URL . 'assets/js/archivio-post-frontend.js',
			array( 'jquery' ),
			MDSM_VERSION,
			true
		);

		wp_localize_script( 'archivio-post-frontend', 'archivioPostFrontend', array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'archivio_post_frontend_nonce' ),
			'strings' => array(
				'downloading' => __( 'Downloading...', 'archiviomd' ),
				'error'       => __( 'Error downloading verification file.', 'archiviomd' ),
			),
		) );
	}

	public function admin_hmac_notices() {
		if ( ! MDSM_Hash_Helper::is_hmac_mode_enabled() ) {
			// Check for algorithm fallback notices even when HMAC is disabled
			$this->display_algorithm_fallback_notice();
			return;
		}

		$status = MDSM_Hash_Helper::hmac_status();

		if ( $status['notice_level'] === 'ok' ) {
			$this->display_algorithm_fallback_notice();
			return;
		}

		$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';

		printf(
			'<div class="notice %s"><p><strong>ArchivioMD HMAC:</strong> %s</p></div>',
			esc_attr( $class ),
			wp_kses( $status['notice_message'], array( 'code' => array() ) )
		);

		$this->display_algorithm_fallback_notice();
	}

	/**
	 * Sitewide admin notice for Ed25519 and SLH-DSA misconfiguration.
	 *
	 * Fires on every admin page when either signing algorithm is enabled
	 * but its key constant has gone missing from wp-config.php — the same
	 * pattern as admin_hmac_notices() for HMAC.
	 */
	public function admin_signing_notices() {
		// Ed25519 ─────────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_Ed25519_Signing' ) && MDSM_Ed25519_Signing::is_mode_enabled() ) {
			$status = MDSM_Ed25519_Signing::status();
			if ( $status['notice_level'] !== 'ok' ) {
				$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';
				printf(
					'<div class="notice %s"><p><strong>ArchivioMD Ed25519:</strong> %s</p></div>',
					esc_attr( $class ),
					wp_kses( $status['notice_message'], array( 'code' => array() ) )
				);
			}
		}

		// SLH-DSA ─────────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_SLHDSA_Signing' ) && MDSM_SLHDSA_Signing::is_mode_enabled() ) {
			$status = MDSM_SLHDSA_Signing::status();
			if ( $status['notice_level'] !== 'ok' ) {
				$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';
				printf(
					'<div class="notice %s"><p><strong>ArchivioMD SLH-DSA:</strong> %s</p></div>',
					esc_attr( $class ),
					wp_kses( $status['notice_message'], array( 'code' => array() ) )
				);
			}
		}

		// ECDSA ───────────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::is_mode_enabled() ) {
			$status = MDSM_ECDSA_Signing::status();
			if ( $status['notice_level'] !== 'ok' ) {
				$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';
				printf(
					'<div class="notice %s"><p><strong>ArchivioMD ECDSA:</strong> %s</p></div>',
					esc_attr( $class ),
					esc_html( $status['notice_message'] )
				);
			}
		}

		// RSA ─────────────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::is_mode_enabled() ) {
			$status = MDSM_RSA_Signing::status();
			if ( $status['notice_level'] !== 'ok' ) {
				$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';
				printf(
					'<div class="notice %s"><p><strong>ArchivioMD RSA:</strong> %s</p></div>',
					esc_attr( $class ),
					esc_html( $status['notice_message'] )
				);
			}
		}

		// CMS / PKCS#7 ────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_CMS_Signing' ) && MDSM_CMS_Signing::is_mode_enabled() ) {
			$status = MDSM_CMS_Signing::status();
			if ( $status['notice_level'] !== 'ok' ) {
				$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';
				printf(
					'<div class="notice %s"><p><strong>ArchivioMD CMS/PKCS#7:</strong> %s</p></div>',
					esc_attr( $class ),
					esc_html( $status['notice_message'] )
				);
			}
		}

		// JSON-LD / W3C Data Integrity ─────────────────────────────────────────
		if ( class_exists( 'MDSM_JSONLD_Signing' ) && MDSM_JSONLD_Signing::is_mode_enabled() ) {
			$status = MDSM_JSONLD_Signing::status();
			if ( $status['notice_level'] !== 'ok' ) {
				$class = ( $status['notice_level'] === 'error' ) ? 'notice-error' : 'notice-warning';
				printf(
					'<div class="notice %s"><p><strong>ArchivioMD JSON-LD:</strong> %s</p></div>',
					esc_attr( $class ),
					esc_html( $status['notice_message'] )
				);
			}
		}
	}

	private function display_algorithm_fallback_notice() {
		$user_id = get_current_user_id();
		$fallback_data = get_transient( 'archivio_post_fallback_notice_' . $user_id );

		if ( ! $fallback_data ) {
			return;
		}

		$requested_label = MDSM_Hash_Helper::algorithm_label( $fallback_data['requested'] );
		$fallback_label  = MDSM_Hash_Helper::algorithm_label( $fallback_data['fallback'] );

		printf(
			'<div class="notice notice-warning is-dismissible"><p><strong>%s</strong> %s</p></div>',
			esc_html__( 'Algorithm Fallback:', 'archiviomd' ),
			sprintf(
				/* translators: 1: requested algorithm name, 2: fallback algorithm name, 3: post ID */
				esc_html__( 'The requested algorithm %1$s is not available on this server. Hash for post #%3$d was generated using fallback algorithm %2$s instead.', 'archiviomd' ),
				'<code>' . esc_html( $requested_label ) . '</code>',
				'<code>' . esc_html( $fallback_label ) . '</code>',
				esc_html( $fallback_data['post_id'] )
			)
		);

		delete_transient( 'archivio_post_fallback_notice_' . $user_id );
	}

	public function render_admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'archiviomd' ) );
		}

		global $wpdb;
		$table_name = $wpdb->prefix . 'archivio_post_audit';
		if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) !== $table_name ) {
			self::create_audit_table();
		}

		require_once MDSM_PLUGIN_DIR . 'admin/archivio-post-page.php';
	}

	public function canonicalize_content( $content, $post_id, $author_id ) {
		$content = str_replace( "\r\n", "\n", $content );
		$content = str_replace( "\r",   "\n", $content );

		$lines   = explode( "\n", $content );
		$lines   = array_map( 'trim', $lines );
		$content = trim( implode( "\n", $lines ) );

		$canonical  = "post_id:{$post_id}\n";
		$canonical .= "author_id:{$author_id}\n";
		$canonical .= "content:\n{$content}";

		return $canonical;
	}

	public function generate_hash( $post_id ) {
		$post = get_post( $post_id );

		if ( ! $post || $post->post_status !== 'publish' ) {
			return false;
		}

		$canonical = $this->canonicalize_content(
			$post->post_content,
			$post_id,
			$post->post_author
		);

		$result = MDSM_Hash_Helper::compute_hash( $canonical );

		if ( false === $result ) {
			return false;
		}

		return array(
			'packed'           => $result['packed'],
			'mode'             => $result['mode'],
			'hmac_unavailable' => $result['hmac_unavailable'],
		);
	}

	public function maybe_generate_hash( $post_id, $post, $update ) {
		// Ensure we have a valid post object
		if ( ! is_object( $post ) || ! isset( $post->post_status ) ) {
			$post = get_post( $post_id );
			if ( ! $post ) {
				return;
			}
		}
		
		if ( wp_is_post_revision( $post_id ) || wp_is_post_autosave( $post_id ) ) {
			return;
		}

		if ( $post->post_status !== 'publish' ) {
			return;
		}

		$auto_generate = get_option( 'archivio_post_auto_generate', false );
		
		// Handle both boolean and string values (WordPress sometimes stores as '1'/'0' or ''/1)
		$auto_generate = filter_var( $auto_generate, FILTER_VALIDATE_BOOLEAN );
		
		if ( ! $auto_generate ) {
			return;
		}

		$existing = get_post_meta( $post_id, '_archivio_post_hash', true );
		if ( ! empty( $existing ) && ! $update ) {
			return;
		}

		$result = $this->generate_hash( $post_id );

		if ( false === $result ) {
			$this->log_event(
				$post_id,
				$post->post_author,
				'',
				'sha256',
				'standard',
				'auto_generate',
				'failed'
			);
			return;
		}

		// Only log if the hash has actually changed (prevents double-logging from multiple save_post fires)
		if ( $existing === $result['packed'] ) {
			return;
		}

		update_post_meta( $post_id, '_archivio_post_hash', $result['packed'] );

		$unpacked = MDSM_Hash_Helper::unpack( $result['packed'] );

		// Check if fallback occurred and log it
		$result_type = 'success';
		if ( $unpacked['algorithm'] !== MDSM_Hash_Helper::get_active_algorithm() ) {
			$result_type = 'fallback';
			$requested_algo = MDSM_Hash_Helper::get_active_algorithm();
			$fallback_algo  = $unpacked['algorithm'];
			set_transient(
				'archivio_post_fallback_notice_' . get_current_user_id(),
				array(
					'requested' => $requested_algo,
					'fallback'  => $fallback_algo,
					'post_id'   => $post_id,
				),
				300
			);
		}

		$this->log_event(
			$post_id,
			$post->post_author,
			$result['packed'],
			$unpacked['algorithm'],
			$unpacked['mode'],
			'auto_generate',
			$result_type
		);
	}

	public function verify_hash( $post_id ) {
		$stored_hash = get_post_meta( $post_id, '_archivio_post_hash', true );

		if ( empty( $stored_hash ) ) {
			return array(
				'verified'          => false,
				'current_hash'      => false,
				'stored_hash'       => false,
				'mode'              => '',
				'algorithm'         => '',
				'hmac_unavailable'  => false,
				'hmac_key_missing'  => false,
			);
		}

		$unpacked = MDSM_Hash_Helper::unpack( $stored_hash );

		$post = get_post( $post_id );
		if ( ! $post ) {
			return array(
				'verified'          => false,
				'current_hash'      => false,
				'stored_hash'       => $stored_hash,
				'mode'              => $unpacked['mode'],
				'algorithm'         => $unpacked['algorithm'],
				'hmac_unavailable'  => false,
				'hmac_key_missing'  => false,
			);
		}

		$canonical = $this->canonicalize_content(
			$post->post_content,
			$post_id,
			$post->post_author
		);

		$current = MDSM_Hash_Helper::compute_hash_for_verification(
			$canonical,
			$unpacked['algorithm'],
			$unpacked['mode']
		);

		if ( false === $current ) {
			return array(
				'verified'          => false,
				'current_hash'      => false,
				'stored_hash'       => $stored_hash,
				'mode'              => $unpacked['mode'],
				'algorithm'         => $unpacked['algorithm'],
				'hmac_unavailable'  => $current === false && $unpacked['mode'] === 'hmac',
				'hmac_key_missing'  => ! MDSM_Hash_Helper::is_hmac_key_defined(),
			);
		}

		$current_packed = MDSM_Hash_Helper::pack( $current['hash'], $unpacked['algorithm'], $unpacked['mode'] );

		return array(
			'verified'          => hash_equals( $stored_hash, $current_packed ),
			'current_hash'      => $current_packed,
			'stored_hash'       => $stored_hash,
			'mode'              => $unpacked['mode'],
			'algorithm'         => $unpacked['algorithm'],
			'hmac_unavailable'  => false,
			'hmac_key_missing'  => ( $unpacked['mode'] === 'hmac' && ! MDSM_Hash_Helper::is_hmac_key_defined() ),
		);
	}

	public function add_badge_meta_box() {
		$post_types = get_post_types( array( 'public' => true ), 'names' );
		add_meta_box(
			'archivio_post_badge',
			__( 'ArchivioMD Badge Settings', 'archiviomd' ),
			array( $this, 'render_badge_meta_box' ),
			$post_types,
			'side',
			'low'
		);
	}

	public function render_badge_meta_box( $post ) {
		$show_badge        = get_post_meta( $post->ID, '_archivio_post_show_badge',        true );
		$show_title_badge  = get_post_meta( $post->ID, '_archivio_post_show_title_badge',  true );
		$badge_override    = get_post_meta( $post->ID, '_archivio_post_badge_override',    true );

		wp_nonce_field( 'archivio_post_badge_meta_box', 'archivio_post_badge_meta_box_nonce' );
		?>
		<p>
			<label>
				<input type="checkbox" name="archivio_post_show_badge" value="1" <?php checked( $show_badge, '1' ); ?> />
				<?php esc_html_e( 'Also show badge below content', 'archiviomd' ); ?>
			</label>
		</p>
		<p>
			<label>
				<input type="checkbox" name="archivio_post_show_title_badge" value="0" <?php checked( $show_title_badge, '0' ); ?> />
				<?php esc_html_e( 'Hide badge from title', 'archiviomd' ); ?>
			</label>
		</p>
		<p>
			<label for="archivio_post_badge_override">
				<?php esc_html_e( 'Custom badge text (optional):', 'archiviomd' ); ?>
			</label>
			<input type="text" id="archivio_post_badge_override" name="archivio_post_badge_override" value="<?php echo esc_attr( $badge_override ); ?>" style="width:100%;" />
		</p>
		<?php
	}

	public function save_badge_meta_box( $post_id, $post ) {
		if ( ! isset( $_POST['archivio_post_badge_meta_box_nonce'] ) ) {
			return;
		}

		$nonce = sanitize_text_field( wp_unslash( $_POST['archivio_post_badge_meta_box_nonce'] ) );
		if ( ! wp_verify_nonce( $nonce, 'archivio_post_badge_meta_box' ) ) {
			return;
		}

		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}

		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}

		$show_badge       = isset( $_POST['archivio_post_show_badge'] ) ? '1' : '';
		$show_title_badge = isset( $_POST['archivio_post_show_title_badge'] ) ? '1' : '';
		$badge_override   = isset( $_POST['archivio_post_badge_override'] )   ? sanitize_text_field( wp_unslash( $_POST['archivio_post_badge_override'] ) ) : '';

		update_post_meta( $post_id, '_archivio_post_show_badge',        $show_badge );
		update_post_meta( $post_id, '_archivio_post_show_title_badge',  $show_title_badge );
		update_post_meta( $post_id, '_archivio_post_badge_override',    $badge_override );
	}

	public function maybe_display_badge( $content ) {
		if ( ! is_singular() ) {
			return $content;
		}

		$post_id = get_the_ID();
		if ( ! $post_id ) {
			return $content;
		}

		// Badge below content is opt-in only (meta = '1').
		// The title badge is the default display location.
		$show_badge_meta = get_post_meta( $post_id, '_archivio_post_show_badge', true );
		if ( $show_badge_meta !== '1' ) {
			return $content;
		}

		$badge = $this->generate_badge_html( $post_id, 'content' );
		if ( $badge ) {
			$content .= $badge;
		}

		return $content;
	}

	public function maybe_display_title_badge( $title, $post_id = null ) {
		if ( ! is_singular() || ! in_the_loop() || ! is_main_query() ) {
			return $title;
		}

		if ( ! $post_id ) {
			return $title;
		}

		// Default: show title badge whenever a hash exists.
		// Per-post meta '_archivio_post_show_title_badge' can be set to '0' to suppress it.
		$suppress = get_post_meta( $post_id, '_archivio_post_show_title_badge', true );
		if ( $suppress === '0' ) {
			return $title;
		}

		$badge = $this->generate_badge_html( $post_id, 'title' );
		if ( $badge ) {
			$title .= ' ' . $badge;
		}

		return $title;
	}

	public function shortcode_verify_badge( $atts ) {
		$atts = shortcode_atts( array(
			'post_id' => get_the_ID(),
		), $atts, 'hash_verify' );

		$post_id = intval( $atts['post_id'] );

		if ( ! $post_id ) {
			return '';
		}

		return $this->generate_badge_html( $post_id, 'shortcode' );
	}

	private function generate_badge_html( $post_id, $context = 'content' ) {
		$stored_hash    = get_post_meta( $post_id, '_archivio_post_hash', true );
		$badge_override = get_post_meta( $post_id, '_archivio_post_badge_override', true );

		// SVG: download arrow
		$dl_icon = '<svg class="apb-dl-svg" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M8 2v8M5 7l3 3 3-3M3 13h10" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>';

		// No hash stored — show "Not Signed" pill
		if ( empty( $stored_hash ) ) {
			$label = ! empty( $badge_override ) ? esc_html( $badge_override ) : esc_html__( 'Not Signed', 'archiviomd' );
			return '<span class="archivio-post-badge archivio-post-badge-' . esc_attr( $context ) . ' not-signed">'
				. '<span class="apb-icon" aria-hidden="true">&#8212;</span>'
				. '<span class="apb-text">' . $label . '</span>'
				. '</span>';
		}

		$verification = $this->verify_hash( $post_id );
		$verified     = $verification['verified'];

		if ( $verified ) {
			$status_class = 'verified';
			$icon         = '<svg class="apb-svg" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><polyline points="2.5,8.5 6,12 13.5,4" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
			$label        = ! empty( $badge_override ) ? esc_html( $badge_override ) : esc_html__( 'Verified', 'archiviomd' );
		} else {
			$status_class = 'unverified';
			$icon         = '<svg class="apb-svg" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><line x1="3" y1="3" x2="13" y2="13" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><line x1="13" y1="3" x2="3" y2="13" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>';
			$label        = ! empty( $badge_override ) ? esc_html( $badge_override ) : esc_html__( 'Unverified', 'archiviomd' );
		}

		$html  = '<span class="archivio-post-badge archivio-post-badge-' . esc_attr( $context ) . ' ' . esc_attr( $status_class ) . '" data-post-id="' . esc_attr( $post_id ) . '">';
		$html .= '<span class="apb-icon">' . $icon . '</span>';
		$html .= '<span class="apb-text">' . $label . '</span>';
		$html .= '<span class="apb-divider" aria-hidden="true"></span>';
		$html .= '<button class="apb-download archivio-post-download" data-post-id="' . esc_attr( $post_id ) . '" title="' . esc_attr__( 'Download Verification File', 'archiviomd' ) . '" aria-label="' . esc_attr__( 'Download Verification File', 'archiviomd' ) . '">' . $dl_icon . '</button>';
		$html .= '</span>';

		return $html;
	}

	private function log_event( $post_id, $author_id, $hash, $algorithm, $mode, $event_type, $result ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'archivio_post_audit';
		
		// Sanity check - table should exist (created/verified in __construct)
		if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) !== $table_name ) {
			return;
		}

		$post_type = get_post_type( $post_id );
		if ( ! $post_type ) {
			$post_type = 'post';
		}

		$wpdb->insert(
			$table_name,
			array(
				'post_id'    => $post_id,
				'post_type'  => $post_type,
				'author_id'  => $author_id,
				'hash'       => $hash,
				'algorithm'  => $algorithm,
				'mode'       => $mode,
				'event_type' => $event_type,
				'result'     => $result,
				'timestamp'  => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	public function ajax_download_verification() {
		check_ajax_referer( 'archivio_post_frontend_nonce', 'nonce' );

		$post_id = isset( $_POST['post_id'] ) ? intval( $_POST['post_id'] ) : 0;

		if ( ! $post_id ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Invalid post ID', 'archiviomd' ) ) );
		}

		$post = get_post( $post_id );
		if ( ! $post ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Post not found', 'archiviomd' ) ) );
		}

		$stored_hash = get_post_meta( $post_id, '_archivio_post_hash', true );
		if ( empty( $stored_hash ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'No hash found for this post', 'archiviomd' ) ) );
		}

		$verification = $this->verify_hash( $post_id );
		$unpacked     = MDSM_Hash_Helper::unpack( $stored_hash );

		$canonical = $this->canonicalize_content(
			$post->post_content,
			$post_id,
			$post->post_author
		);

		$file_content  = "ArchivioMD Content Verification\n";
		$file_content .= "================================\n\n";
		$file_content .= "Post ID:       {$post_id}\n";
		$file_content .= "Post Title:    {$post->post_title}\n";
		$file_content .= "Author ID:     {$post->post_author}\n";
		$file_content .= "Verification:  " . ( $verification['verified'] ? 'PASSED' : 'FAILED' ) . "\n\n";

		$file_content .= "Hash Details:\n";
		$file_content .= "-------------\n";
		$file_content .= "Mode:       " . MDSM_Hash_Helper::mode_label( $unpacked['mode'] ) . "\n";
		$file_content .= "Algorithm:  " . MDSM_Hash_Helper::algorithm_label( $unpacked['algorithm'] ) . "\n";
		$file_content .= "Hash:       {$unpacked['hash']}\n\n";

		$file_content .= "Canonical Content:\n";
		$file_content .= "------------------\n";
		$file_content .= $canonical . "\n\n";

		$file_content .= "Verification Instructions:\n";
		$file_content .= "--------------------------\n";

		$algo_key   = $unpacked['algorithm'];
		$algo_label = MDSM_Hash_Helper::algorithm_label( $algo_key );

		$std_cmd = "echo -n \"<canonical_content>\" | openssl dgst -{$algo_key}";

		if ( $unpacked['mode'] === 'hmac' ) {
			$file_content .= "This hash was produced using HMAC-{$algo_label}.\n";
			$file_content .= "Offline verification requires the ARCHIVIOMD_HMAC_KEY secret.\n";
			$file_content .= "Example (replace KEY with your secret):\n";
			$file_content .= "echo -n \"<canonical_content>\" | openssl dgst -{$algo_key} -hmac \"KEY\"\n";
		} else {
			$file_content .= "To verify offline, compute the {$algo_label} hash of the\n";
			$file_content .= "canonical content above. It must match the hash shown.\n\n";
			$file_content .= "Example:\n";
			$file_content .= $std_cmd . "\n";
		}

		// ── RFC 3161 Timestamp cross-reference ──────────────────────────────────
		// If a timestamp was issued for this post, append its details so the
		// verification file is a self-contained evidence package.
		// Guard: the anchor log table may not exist yet (timestamps never enabled,
		// or plugin freshly installed). Also suppress wpdb errors around the query
		// so a missing table never corrupts the JSON response on WP_DEBUG hosts.
		if ( class_exists( 'MDSM_Anchor_Log' ) ) {
			global $wpdb;
			$log_table = MDSM_Anchor_Log::get_table_name();

			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $log_table ) ) === $log_table ) {
				$doc_id  = 'post-' . $post_id;

				$suppress = $wpdb->suppress_errors( true );

				$tsr_row = $wpdb->get_row(
					$wpdb->prepare(
						"SELECT anchor_url, created_at FROM {$log_table} WHERE document_id = %s AND provider = 'rfc3161' AND status = 'anchored' ORDER BY created_at DESC LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						$doc_id
					)
				);

				$wpdb->suppress_errors( $suppress );

				if ( $tsr_row ) {
					$file_content .= "\n\nRFC 3161 Trusted Timestamp:\n";
					$file_content .= "----------------------------\n";
					$file_content .= "Anchored at (UTC): {$tsr_row->created_at}\n";
					$file_content .= "TSR file:          {$tsr_row->anchor_url}\n";
					$file_content .= "The .tsr file contains a signed timestamp token from a trusted TSA\n";
					$file_content .= "proving this content hash existed at the time shown above.\n";
					$file_content .= "Download the .tsr from the Anchor Activity Log to verify offline.\n";
				}
			}
		}

		// ── DSSE Envelope ────────────────────────────────────────────────────────
		// Include the shared DSSE envelope (Ed25519 ± SLH-DSA) when present, plus
		// the standalone SLH-DSA-only envelope when SLH-DSA DSSE is active without
		// Ed25519.  Iterate every signatures[] entry so verifiers see per-algorithm
		// status and offline instructions for each algorithm that signed this post.
		$dsse_raw = get_post_meta( $post_id, MDSM_Ed25519_Signing::DSSE_META_KEY, true );

		// Fall back to standalone SLH-DSA envelope when no shared envelope exists.
		if ( ! $dsse_raw && class_exists( 'MDSM_SLHDSA_Signing' ) ) {
			$dsse_raw = get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_DSSE, true );
		}

		if ( $dsse_raw ) {
			$dsse_envelope = json_decode( $dsse_raw, true );
			if ( is_array( $dsse_envelope ) ) {

				// Server-side Ed25519 verification (if key is available).
				$ed_result  = class_exists( 'MDSM_Ed25519_Signing' )
					? MDSM_Ed25519_Signing::verify_post_dsse( $post_id )
					: null;
				$ed_valid   = $ed_result && ! is_wp_error( $ed_result ) && ! empty( $ed_result['valid'] );

				// Server-side SLH-DSA verification (reads _mdsm_slhdsa_sig directly).
				$slh_result = class_exists( 'MDSM_SLHDSA_Signing' )
					? MDSM_SLHDSA_Signing::verify_post( $post_id )
					: null;
				$slh_valid  = $slh_result && ! is_wp_error( $slh_result ) && ! empty( $slh_result['valid'] );

				$file_content .= "\n\nDSSE Envelope (Dead Simple Signing Envelope):\n";
				$file_content .= "----------------------------------------------\n";
				$file_content .= "Spec:         https://github.com/secure-systems-lab/dsse\n";
				$file_content .= "Payload type: " . ( $dsse_envelope['payloadType'] ?? '' ) . "\n";
				$file_content .= "Signatures:   " . count( $dsse_envelope['signatures'] ?? array() ) . "\n";

				// Per-signature status and verification notes.
				foreach ( (array) ( $dsse_envelope['signatures'] ?? array() ) as $idx => $sig_entry ) {
					$alg    = isset( $sig_entry['alg'] ) ? strtolower( $sig_entry['alg'] ) : 'ed25519';
					$keyid  = $sig_entry['keyid'] ?? '';
					$is_ed  = ( $alg === 'ed25519' );
					$is_slh = ( strpos( $alg, 'slh-dsa' ) !== false );
					$is_ecdsa = ( strpos( $alg, 'ecdsa' ) !== false );

					if ( $is_ed ) {
						$status_line = $ed_valid
							? 'VALID — Ed25519 signature verified server-side'
							: 'UNVERIFIED — Ed25519 key not available or signature mismatch';
					} elseif ( $is_slh ) {
						$status_line = $slh_valid
							? 'VALID — SLH-DSA signature verified server-side'
							: 'UNVERIFIED — SLH-DSA key not available or signature mismatch';
					} elseif ( $is_ecdsa ) {
						$ecdsa_r     = class_exists( 'MDSM_ECDSA_Signing' ) ? MDSM_ECDSA_Signing::verify( $post_id ) : null;
						$ecdsa_ok    = $ecdsa_r && ! is_wp_error( $ecdsa_r ) && ! empty( $ecdsa_r['valid'] );
						$status_line = $ecdsa_ok
							? 'VALID — ECDSA P-256 signature verified server-side via OpenSSL'
							: 'UNVERIFIED — ECDSA certificate not available or signature mismatch';
					} else {
						$status_line = 'UNKNOWN algorithm — not verified';
					}

					$file_content .= "\nSignature [" . ( $idx + 1 ) . "]:\n";
					$file_content .= "  Algorithm:          " . ( $alg ?: 'ed25519' ) . "\n";
					$file_content .= "  Key fingerprint:    " . ( $keyid ?: '(none)' ) . "\n";
					$file_content .= "  Server-side status: " . $status_line . "\n";

					if ( $is_ed ) {
						$file_content .= "  Public key URL:     " . home_url( '/.well-known/ed25519-pubkey.txt' ) . "\n";
						$file_content .= "  Offline verify:     Rebuild PAE (see below), then:\n";
						$file_content .= "    sodium_crypto_sign_verify_detached(base64decode(sig), PAE, hex2bin(pubkey))\n";
					} elseif ( $is_slh ) {
						$slh_param = get_post_meta( $post_id, '_mdsm_slhdsa_param', true ) ?: $alg;
						$file_content .= "  Public key URL:     " . home_url( '/.well-known/slhdsa-pubkey.txt' ) . "\n";
						$file_content .= "  Parameter set:      " . strtoupper( $slh_param ) . " (NIST FIPS 205)\n";
						$file_content .= "  Offline verify:     Rebuild PAE (see below), then verify using an\n";
						$file_content .= "    SLH-DSA library with the " . strtoupper( $slh_param ) . " parameter set.\n";
						$file_content .= "    Example (pyspx):\n";
						$file_content .= "      from pyspx import shake_128s\n";
						$file_content .= "      ok = shake_128s.verify(pae_bytes, base64.b64decode(sig), bytes.fromhex(pubkey))\n";
					} elseif ( $is_ecdsa ) {
						$file_content .= "  Certificate URL:    " . home_url( '/.well-known/ecdsa-cert.pem' ) . "\n";
						$file_content .= "  Offline verify:     Rebuild PAE (see below), base64-decode 'sig' for DER bytes, then:\n";
						$file_content .= "    openssl dgst -sha256 -verify <(openssl x509 -in cert.pem -pubkey -noout) -signature sig.der <<< PAE\n";
					}
				}

				$file_content .= "\nFull envelope (JSON):\n";
				$file_content .= wp_json_encode( $dsse_envelope, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";

				$file_content .= "\nPAE reconstruction (applies to all signatures above):\n";
				$file_content .= "  PAE = \"DSSEv1 \" + len(payloadType) + \" \" + payloadType\n";
				$file_content .= "                  + \" \" + len(payload)     + \" \" + payload\n";
				$file_content .= "  (lengths are byte lengths as decimal ASCII integers)\n";
				$file_content .= "  1. Base64-decode the 'payload' field to get the canonical message.\n";
				$file_content .= "  2. Build PAE from payloadType and the decoded payload bytes.\n";
				$file_content .= "  3. For each signature entry, base64-decode 'sig' and verify against PAE\n";
				$file_content .= "     using the algorithm and public key identified above.\n";
			}
		}

		// ── Standalone SLH-DSA bare signature (when no DSSE envelope) ────────────
		// If DSSE is off but bare SLH-DSA signing is on, surface the bare sig
		// so the verification file is still a self-contained evidence package.
		if ( ! $dsse_raw && class_exists( 'MDSM_SLHDSA_Signing' ) ) {
			$slh_sig_hex = get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_SIG, true );
			if ( $slh_sig_hex ) {
				$slh_param   = get_post_meta( $post_id, '_mdsm_slhdsa_param', true )
					?: MDSM_SLHDSA_Signing::get_param();
				$slh_result  = MDSM_SLHDSA_Signing::verify_post( $post_id );
				$slh_valid   = $slh_result && ! is_wp_error( $slh_result ) && ! empty( $slh_result['valid'] );

				$file_content .= "\n\nSLH-DSA Signature (NIST FIPS 205):\n";
				$file_content .= "-----------------------------------\n";
				$file_content .= "Algorithm:    " . strtoupper( $slh_param ) . "\n";
				$file_content .= "Status:       " . ( $slh_valid ? 'VALID — verified server-side' : 'UNVERIFIED' ) . "\n";
				$file_content .= "Public key:   " . home_url( '/.well-known/slhdsa-pubkey.txt' ) . "\n";
				$file_content .= "Signed at:    " . gmdate( 'Y-m-d H:i:s T', (int) get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_SIGNED_AT, true ) ) . "\n";
				$file_content .= "Signature:    " . $slh_sig_hex . "\n";
				$file_content .= "\nThe signature covers the canonical message shown above.\n";
				$file_content .= "Offline verification (pyspx example):\n";
				$file_content .= "  from pyspx import shake_128s\n";
				$file_content .= "  ok = shake_128s.verify(message.encode(), bytes.fromhex(signature), bytes.fromhex(pubkey))\n";
			}
		}

		// ── ECDSA P-256 signatures ────────────────────────────────────────────────
		// Surface the ECDSA DSSE envelope when present, with fallback to the bare sig.
		if ( class_exists( 'MDSM_ECDSA_Signing' ) ) {
			$ecdsa_dsse_raw = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_DSSE, true );

			if ( $ecdsa_dsse_raw ) {
				$ecdsa_envelope = json_decode( $ecdsa_dsse_raw, true );
				if ( is_array( $ecdsa_envelope ) ) {
					$ecdsa_result = MDSM_ECDSA_Signing::verify( $post_id );
					$ecdsa_valid  = $ecdsa_result && ! is_wp_error( $ecdsa_result ) && ! empty( $ecdsa_result['valid'] );

					$file_content .= "\n\nECDSA P-256 DSSE Envelope (Enterprise / Compliance Mode):\n";
					$file_content .= "---------------------------------------------------------\n";
					$file_content .= "Spec:         https://github.com/secure-systems-lab/dsse\n";
					$file_content .= "Algorithm:    ecdsa-p256-sha256 (NIST P-256 / secp256r1)\n";
					$file_content .= "Status:       " . ( $ecdsa_valid ? 'VALID — verified server-side via OpenSSL' : 'UNVERIFIED — certificate or signature mismatch' ) . "\n";
					$file_content .= "Certificate:  " . home_url( '/.well-known/ecdsa-cert.pem' ) . "\n";

					// Surface the stored cert fingerprint from meta for offline reference.
					$stored_cert_pem = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_CERT, true );
					if ( $stored_cert_pem ) {
						$b64  = preg_replace( '/-----[^-]+-----|\s/', '', $stored_cert_pem );
						$der  = base64_decode( $b64 ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
						$fp   = strtoupper( implode( ':', str_split( hash( 'sha256', $der ), 2 ) ) );
						$file_content .= "Cert SHA-256: " . $fp . "\n";
					}

					$file_content .= "\nOffline verification (OpenSSL CLI):\n";
					$file_content .= "  1. Download the certificate: curl " . home_url( '/.well-known/ecdsa-cert.pem' ) . " -o cert.pem\n";
					$file_content .= "  2. Base64-decode the 'payload' field, rebuild PAE (see below)\n";
					$file_content .= "  3. Base64-decode the 'sig' field from signatures[0] to get the DER signature\n";
					$file_content .= "  4. echo -n \"<PAE>\" | openssl dgst -sha256 -verify <(openssl x509 -in cert.pem -pubkey -noout) -signature sig.der\n";
					$file_content .= "\nOffline verification (Python / cryptography library):\n";
					$file_content .= "  from cryptography.hazmat.primitives.serialization import load_pem_public_key\n";
					$file_content .= "  from cryptography.hazmat.primitives.asymmetric.ec import ECDSA\n";
					$file_content .= "  from cryptography.hazmat.primitives.hashes import SHA256\n";
					$file_content .= "  from cryptography.x509 import load_pem_x509_certificate\n";
					$file_content .= "  cert = load_pem_x509_certificate(open('cert.pem','rb').read())\n";
					$file_content .= "  cert.public_key().verify(sig_der_bytes, pae_bytes, ECDSA(SHA256()))\n";
					$file_content .= "\nFull DSSE envelope (JSON):\n";
					// Strip x5c from the output envelope to avoid a huge PEM blob in the text file;
					// the cert is available at the well-known URL referenced above.
					$display_envelope = $ecdsa_envelope;
					if ( isset( $display_envelope['signatures'] ) ) {
						foreach ( $display_envelope['signatures'] as &$s ) {
							unset( $s['x5c'] );
						}
						unset( $s );
					}
					$file_content .= wp_json_encode( $display_envelope, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
					$file_content .= "\nPAE reconstruction:\n";
					$file_content .= "  PAE = \"DSSEv1 \" + len(payloadType) + \" \" + payloadType\n";
					$file_content .= "                  + \" \" + len(payload)     + \" \" + payload\n";
					$file_content .= "  (lengths are byte lengths as decimal ASCII integers)\n";
				}
			} elseif ( MDSM_ECDSA_Signing::is_mode_enabled() ) {
				// DSSE off but bare ECDSA sig may exist.
				$ecdsa_sig_hex = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_SIG, true );
				if ( $ecdsa_sig_hex ) {
					$ecdsa_result = MDSM_ECDSA_Signing::verify( $post_id );
					$ecdsa_valid  = $ecdsa_result && ! is_wp_error( $ecdsa_result ) && ! empty( $ecdsa_result['valid'] );

					$file_content .= "\n\nECDSA P-256 Signature (Enterprise / Compliance Mode):\n";
					$file_content .= "-----------------------------------------------------\n";
					$file_content .= "Algorithm:    ecdsa-p256-sha256 (NIST P-256, DER-encoded)\n";
					$file_content .= "Status:       " . ( $ecdsa_valid ? 'VALID — verified server-side via OpenSSL' : 'UNVERIFIED' ) . "\n";
					$file_content .= "Certificate:  " . home_url( '/.well-known/ecdsa-cert.pem' ) . "\n";
					$file_content .= "Signed at:    " . gmdate( 'Y-m-d H:i:s T', (int) get_post_meta( $post_id, MDSM_ECDSA_Signing::META_SIGNED_AT, true ) ) . "\n";
					$file_content .= "Signature:    " . $ecdsa_sig_hex . " (hex of DER-encoded ECDSA signature)\n";
					$file_content .= "\nOffline verification:\n";
					$file_content .= "  echo -n \"{canonical_message}\" | openssl dgst -sha256 \\\n";
					$file_content .= "    -verify <(openssl x509 -in cert.pem -pubkey -noout) \\\n";
					$file_content .= "    -signature <(echo -n \"{sig_hex}\" | xxd -r -p)\n";
				}
			}
		}

		// ── RSA Compatibility Signature ───────────────────────────────────────
		if ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::is_mode_enabled() ) {
			$rsa_sig_hex = get_post_meta( $post_id, MDSM_RSA_Signing::META_SIG, true );
			if ( $rsa_sig_hex ) {
				$rsa_result = MDSM_RSA_Signing::verify( $post_id );
				$rsa_valid  = $rsa_result && ! is_wp_error( $rsa_result ) && ! empty( $rsa_result['valid'] );
				$rsa_scheme = get_post_meta( $post_id, MDSM_RSA_Signing::META_SCHEME, true ) ?: MDSM_RSA_Signing::get_scheme();
				$rsa_signed = get_post_meta( $post_id, MDSM_RSA_Signing::META_SIGNED_AT, true );

				$file_content .= "\n\nRSA Compatibility Signature (Enterprise / Legacy Mode):\n";
				$file_content .= "--------------------------------------------------------\n";
				$file_content .= "Scheme:       " . strtoupper( $rsa_scheme ) . " (DER-encoded)\n";
				$file_content .= "Status:       " . ( $rsa_valid ? 'VALID — verified server-side via OpenSSL' : 'UNVERIFIED' ) . "\n";
				$file_content .= "Public key:   " . home_url( '/.well-known/rsa-pubkey.pem' ) . "\n";
				if ( $rsa_signed ) {
					$file_content .= "Signed at:    " . gmdate( 'Y-m-d H:i:s T', (int) $rsa_signed ) . "\n";
				}
				$file_content .= "Signature:    " . $rsa_sig_hex . " (hex of DER-encoded signature)\n";
				$file_content .= "\nOffline verification (OpenSSL CLI):\n";
				$file_content .= "  curl " . home_url( '/.well-known/rsa-pubkey.pem' ) . " -o rsa-pubkey.pem\n";
				$file_content .= "  echo -n \"{canonical_message}\" | openssl dgst -sha256 \\\n";
				$file_content .= "    -verify rsa-pubkey.pem -signature <(echo -n \"{sig_hex}\" | xxd -r -p)\n";
			}
		}

		// ── CMS / PKCS#7 Detached Signature ──────────────────────────────────
		if ( class_exists( 'MDSM_CMS_Signing' ) && MDSM_CMS_Signing::is_mode_enabled() ) {
			$cms_sig_b64 = get_post_meta( $post_id, MDSM_CMS_Signing::META_SIG, true );
			if ( $cms_sig_b64 ) {
				$cms_result     = MDSM_CMS_Signing::verify( $post_id );
				$cms_valid      = $cms_result && ! is_wp_error( $cms_result ) && ! empty( $cms_result['valid'] );
				$cms_signed     = get_post_meta( $post_id, MDSM_CMS_Signing::META_SIGNED_AT, true );
				$cms_key_source = get_post_meta( $post_id, MDSM_CMS_Signing::META_KEY_SOURCE, true ) ?: 'unknown';

				$file_content .= "\n\nCMS / PKCS#7 Detached Signature (RFC 5652):\n";
				$file_content .= "--------------------------------------------\n";
				$file_content .= "Format:       CMS SignedData, DER-encoded, base64-encoded here\n";
				$file_content .= "Key source:   " . strtoupper( $cms_key_source ) . "\n";
				$file_content .= "Status:       " . ( $cms_valid ? 'VALID — verified server-side via OpenSSL' : 'UNVERIFIED' ) . "\n";
				if ( $cms_signed ) {
					$file_content .= "Signed at:    " . gmdate( 'Y-m-d H:i:s T', (int) $cms_signed ) . "\n";
				}
				$file_content .= "Signature:    " . $cms_sig_b64 . "\n";
				$file_content .= "\nOffline verification (OpenSSL CLI):\n";
				$file_content .= "  # Save the base64 blob above to sig.b64, then:\n";
				$file_content .= "  base64 -d sig.b64 > sig.der\n";
				$file_content .= "  openssl cms -verify -inform DER -in sig.der \\\n";
				$file_content .= "    -content message.txt -noverify\n";
				$file_content .= "\nTo verify the full certificate chain, add: -CAfile ca-bundle.pem\n";
				$file_content .= "The .p7s blob is directly openable in Adobe Acrobat / Reader.\n";
			}
		}

		// ── JSON-LD / W3C Data Integrity Proof ───────────────────────────────
		if ( class_exists( 'MDSM_JSONLD_Signing' ) && MDSM_JSONLD_Signing::is_mode_enabled() ) {
			$proof_json = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_PROOF, true );
			if ( $proof_json ) {
				$proof_arr  = json_decode( $proof_json, true );
				$jsonld_result = MDSM_JSONLD_Signing::verify( $post_id );
				$jsonld_valid  = $jsonld_result && ! is_wp_error( $jsonld_result ) && ! empty( $jsonld_result['valid'] );
				$suite      = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_SUITE, true ) ?: 'unknown';
				$signed_at  = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_SIGNED_AT, true );

				$file_content .= "\n\nJSON-LD / W3C Data Integrity Proof:\n";
				$file_content .= "------------------------------------\n";
				$file_content .= "Cryptosuite:  " . $suite . "\n";
				$file_content .= "Standards:    W3C Data Integrity 1.0 — https://www.w3.org/TR/vc-data-integrity/\n";
				$file_content .= "DID document: " . home_url( '/.well-known/did.json' ) . "\n";
				$file_content .= "Status:       " . ( $jsonld_valid ? 'VALID — proof verified server-side' : 'UNVERIFIED' ) . "\n";
				if ( $signed_at ) {
					$file_content .= "Created:      " . gmdate( 'Y-m-d H:i:s T', (int) $signed_at ) . "\n";
				}
				$file_content .= "\nProof block (JSON):\n";
				$file_content .= wp_json_encode( $proof_arr, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
				$file_content .= "\nOffline verification:\n";
				$file_content .= "  Use any W3C Data Integrity-compatible library (jsonld-signatures, verifiable-credentials).\n";
				$file_content .= "  Resolve the DID at " . home_url( '/.well-known/did.json' ) . "\n";
				$file_content .= "  to obtain the verification method public key, then verify the proof block above.\n";
			}
		}

		wp_send_json_success( array(
			'content'  => $file_content,
			'filename' => 'post-' . $post_id . '-verification.txt',
		) );
	}

	public function ajax_get_audit_logs() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		global $wpdb;

		$page     = isset( $_POST['page'] ) ? max( 1, intval( $_POST['page'] ) ) : 1;
		$per_page = 20;
		$offset   = ( $page - 1 ) * $per_page;

		$total = $wpdb->get_var( "SELECT COUNT(*) FROM {$this->audit_table}" );

		$logs = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$this->audit_table} ORDER BY timestamp DESC LIMIT %d OFFSET %d",
			$per_page,
			$offset
		) );

		wp_send_json_success( array(
			'logs'        => $logs,
			'total'       => $total,
			'page'        => $page,
			'per_page'    => $per_page,
			'total_pages' => ceil( $total / $per_page ),
		) );
	}

	public function ajax_save_settings() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		
		$auto_generate = isset( $_POST['auto_generate'] ) && sanitize_text_field( wp_unslash( $_POST['auto_generate'] ) ) === 'true';
		$show_badge = isset( $_POST['show_badge'] ) && sanitize_text_field( wp_unslash( $_POST['show_badge'] ) ) === 'true';
		$show_badge_posts = isset( $_POST['show_badge_posts'] ) && sanitize_text_field( wp_unslash( $_POST['show_badge_posts'] ) ) === 'true';
		$show_badge_pages = isset( $_POST['show_badge_pages'] ) && sanitize_text_field( wp_unslash( $_POST['show_badge_pages'] ) ) === 'true';

		update_option( 'archivio_post_auto_generate',    $auto_generate );
		update_option( 'archivio_post_show_badge',       $show_badge );
		update_option( 'archivio_post_show_badge_posts', $show_badge_posts );
		update_option( 'archivio_post_show_badge_pages', $show_badge_pages );

		wp_send_json_success( array(
			'message' => esc_html__( 'Settings saved successfully!', 'archiviomd' ),
		) );
	}

	public function ajax_fix_settings() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		// Force all settings to true (enabled) when user clicks fix button
		update_option( 'archivio_post_auto_generate',    true );
		update_option( 'archivio_post_show_badge',       true );
		update_option( 'archivio_post_show_badge_posts', true );
		update_option( 'archivio_post_show_badge_pages', true );

		wp_send_json_success( array(
			'message' => esc_html__( 'Settings enabled! Auto-Generate is now active.', 'archiviomd' ),
		) );
	}

	public function ajax_save_algorithm() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$algorithm = isset( $_POST['algorithm'] ) ? sanitize_key( $_POST['algorithm'] ) : '';

		if ( ! MDSM_Hash_Helper::set_active_algorithm( $algorithm ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Invalid algorithm selected.', 'archiviomd' ) ) );
		}

		$warning = '';
		$is_experimental = MDSM_Hash_Helper::is_experimental( $algorithm );

		// Check availability and provide fallback warnings
		$available = MDSM_Hash_Helper::get_algorithm_availability( $algorithm );

		if ( ! $available ) {
			if ( $algorithm === 'blake3' ) {
				$warning = esc_html__( 'BLAKE3 is not natively available on this PHP build. Hashes will fall back to BLAKE2b or SHA-256.', 'archiviomd' );
			} elseif ( $algorithm === 'shake128' || $algorithm === 'shake256' ) {
				$warning = esc_html__( 'SHAKE algorithm is not available on this PHP build. Hashes will fall back to BLAKE2b or SHA-256.', 'archiviomd' );
			} elseif ( $algorithm === 'blake2b' ) {
				$warning = esc_html__( 'BLAKE2b is not available on this PHP build. New hashes will fall back to SHA-256 until the server is updated.', 'archiviomd' );
			}
		}

		if ( $is_experimental && empty( $warning ) ) {
			$warning = esc_html__( 'You have selected an experimental algorithm. It is natively available on this server, but may be slower than standard algorithms.', 'archiviomd' );
		}

		$active_label = MDSM_Hash_Helper::algorithm_label( MDSM_Hash_Helper::get_active_algorithm() );

		wp_send_json_success( array(
			/* translators: %s: algorithm name */
			'message' => sprintf( esc_html__( 'Algorithm saved. New hashes will use %s.', 'archiviomd' ), $active_label ),
			'warning' => $warning,
		) );
	}

	public function ajax_save_hmac_settings() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$enable_hmac = isset( $_POST['hmac_mode'] ) && sanitize_text_field( wp_unslash( $_POST['hmac_mode'] ) ) === 'true';

		if ( $enable_hmac && ! MDSM_Hash_Helper::is_hmac_key_defined() ) {
			wp_send_json_error( array(
				/* translators: %s: constant name */
				'message' => sprintf(
					esc_html__( 'Cannot enable HMAC Integrity Mode: the %s constant is not defined in wp-config.php.', 'archiviomd' ),
					'<code>' . esc_html( MDSM_Hash_Helper::HMAC_KEY_CONSTANT ) . '</code>'
				),
			) );
		}

		MDSM_Hash_Helper::set_hmac_mode( $enable_hmac );

		$status = MDSM_Hash_Helper::hmac_status();

		wp_send_json_success( array(
			'message'        => $enable_hmac
				? esc_html__( 'HMAC Integrity Mode enabled. All new hashes will be HMAC-signed.', 'archiviomd' )
				: esc_html__( 'HMAC Integrity Mode disabled. New hashes will use standard mode.', 'archiviomd' ),
			'notice_level'   => $status['notice_level'],
			'notice_message' => wp_strip_all_tags( $status['notice_message'] ),
			'key_defined'    => $status['key_defined'],
			'key_strong'     => $status['key_strong'],
		) );
	}

	public function ajax_save_extended_settings() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$rsa_enabled    = isset( $_POST['rsa_enabled'] )    && sanitize_text_field( wp_unslash( $_POST['rsa_enabled'] ) )    === 'true';
		$cms_enabled    = isset( $_POST['cms_enabled'] )    && sanitize_text_field( wp_unslash( $_POST['cms_enabled'] ) )    === 'true';
		$jsonld_enabled = isset( $_POST['jsonld_enabled'] ) && sanitize_text_field( wp_unslash( $_POST['jsonld_enabled'] ) ) === 'true';

		$rsa_scheme = isset( $_POST['rsa_scheme'] ) ? sanitize_text_field( wp_unslash( $_POST['rsa_scheme'] ) ) : '';
		if ( ! in_array( $rsa_scheme, array( 'rsa-pss-sha256', 'rsa-pkcs1v15-sha256' ), true ) ) {
			$rsa_scheme = 'rsa-pss-sha256';
		}

		update_option( 'archiviomd_rsa_enabled',    $rsa_enabled );
		update_option( 'archiviomd_rsa_scheme',      $rsa_scheme );
		update_option( 'archiviomd_cms_enabled',    $cms_enabled );
		update_option( 'archiviomd_jsonld_enabled', $jsonld_enabled );

		// Collect live status for the response.
		$rsa_status    = class_exists( 'MDSM_RSA_Signing' )    ? MDSM_RSA_Signing::status()    : array( 'ready' => false, 'notice_level' => 'ok', 'notice_message' => '' );
		$cms_status    = class_exists( 'MDSM_CMS_Signing' )    ? MDSM_CMS_Signing::status()    : array( 'ready' => false, 'notice_level' => 'ok', 'notice_message' => '' );
		$jsonld_status = class_exists( 'MDSM_JSONLD_Signing' ) ? MDSM_JSONLD_Signing::status() : array( 'ready' => false, 'notice_level' => 'ok', 'notice_message' => '' );

		wp_send_json_success( array(
			'message'       => esc_html__( 'Extended format settings saved.', 'archiviomd' ),
			'rsa_status'    => wp_strip_all_tags( $rsa_status['notice_message'] ),
			'cms_status'    => wp_strip_all_tags( $cms_status['notice_message'] ),
			'jsonld_status' => wp_strip_all_tags( $jsonld_status['notice_message'] ),
		) );
	}

	public function ajax_rsa_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		$enabled    = isset( $_POST['rsa_enabled'] ) && sanitize_text_field( wp_unslash( $_POST['rsa_enabled'] ) ) === 'true';
		$rsa_scheme = isset( $_POST['rsa_scheme'] ) ? sanitize_text_field( wp_unslash( $_POST['rsa_scheme'] ) ) : 'rsa-pss-sha256';
		if ( ! in_array( $rsa_scheme, array( 'rsa-pss-sha256', 'rsa-pkcs1v15-sha256' ), true ) ) {
			$rsa_scheme = 'rsa-pss-sha256';
		}

		// Don't allow enabling if prerequisites are not met.
		if ( $enabled && class_exists( 'MDSM_RSA_Signing' ) ) {
			$st = MDSM_RSA_Signing::status();
			if ( ! $st['openssl_available'] || ! $st['key_configured'] ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Cannot enable RSA signing: prerequisites not met. Configure a private key first.', 'archiviomd' ) ) );
			}
		}

		update_option( 'archiviomd_rsa_enabled', $enabled );
		update_option( 'archiviomd_rsa_scheme',  $rsa_scheme );

		$status = class_exists( 'MDSM_RSA_Signing' ) ? MDSM_RSA_Signing::status() : array( 'notice_message' => '' );
		wp_send_json_success( array(
			'message'  => $enabled
				? esc_html__( 'RSA signing enabled.', 'archiviomd' )
				: esc_html__( 'RSA signing disabled.', 'archiviomd' ),
			'enabled'  => $enabled,
			'notice'   => wp_strip_all_tags( $status['notice_message'] ?? '' ),
		) );
	}

	private function handle_rsa_pem_upload( string $post_field, string $option_key, string $type_label, bool $is_private ): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		if ( empty( $_FILES[ $post_field ]['tmp_name'] ) ) {
			wp_send_json_error( array( 'message' => sprintf( esc_html__( 'No %s file received.', 'archiviomd' ), $type_label ) ) );
		}
		$tmp = $_FILES[ $post_field ]['tmp_name'];
		if ( ! is_uploaded_file( $tmp ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'File upload error.', 'archiviomd' ) ) );
		}
		$pem = file_get_contents( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $pem ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Uploaded file is empty.', 'archiviomd' ) ) );
		}
		if ( $is_private ) {
			if ( ! str_contains( $pem, 'PRIVATE KEY' ) ) {
				wp_send_json_error( array( 'message' => esc_html__( 'File does not appear to be a PEM private key.', 'archiviomd' ) ) );
			}
			if ( ! extension_loaded( 'openssl' ) ) {
				wp_send_json_error( array( 'message' => esc_html__( 'ext-openssl is required to validate the key.', 'archiviomd' ) ) );
			}
			$pkey = openssl_pkey_get_private( $pem );
			if ( ! $pkey ) {
				wp_send_json_error( array( 'message' => esc_html__( 'OpenSSL could not parse the private key. Ensure it is PEM-encoded and not password-protected.', 'archiviomd' ) ) );
			}
			$details = openssl_pkey_get_details( $pkey );
			if ( ( $details['type'] ?? -1 ) !== OPENSSL_KEYTYPE_RSA ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Key is not an RSA key. RSA mode requires an RSA private key.', 'archiviomd' ) ) );
			}
			if ( ( $details['bits'] ?? 0 ) < 2048 ) {
				wp_send_json_error( array( 'message' => esc_html__( 'RSA key must be at least 2048 bits.', 'archiviomd' ) ) );
			}
		} else {
			if ( ! str_contains( $pem, 'CERTIFICATE' ) ) {
				wp_send_json_error( array( 'message' => esc_html__( 'File does not appear to be a PEM certificate.', 'archiviomd' ) ) );
			}
		}

		$base_dir  = dirname( ABSPATH ); // one level above webroot — outside HTTP reach
		$store_dir = $base_dir . '/archiviomd-pem';
		if ( ! wp_mkdir_p( $store_dir ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Could not create secure PEM storage directory.', 'archiviomd' ) ) );
		}
		$htaccess = $store_dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Deny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		$filename    = sanitize_file_name( $type_label ) . '.pem';
		$destination = $store_dir . '/' . $filename;

		// Verify the resolved destination is outside the webroot before writing.
		// Uses the same check as the ECDSA handler to ensure the RSA key path
		// is safe regardless of symlinks or unexpected ABSPATH layouts.
		if ( ! MDSM_ECDSA_Signing::is_safe_pem_path( $destination ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Destination path failed safety check. Contact your server administrator.', 'archiviomd' ) ) );
		}

		if ( file_put_contents( $destination, $pem ) === false ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			wp_send_json_error( array( 'message' => esc_html__( 'Could not write PEM file. Check filesystem permissions.', 'archiviomd' ) ) );
		}
		if ( $is_private ) {
			chmod( $destination, 0600 );
		}

		update_option( $option_key, $destination );
		wp_send_json_success( array( 'message' => sprintf( esc_html__( '%s uploaded successfully.', 'archiviomd' ), $type_label ) ) );
	}

	private function handle_rsa_pem_clear( string $option_key, string $type_label ): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		$path = get_option( $option_key, '' );
		if ( $path && file_exists( $path ) ) {
			$len = filesize( $path );
			if ( $len > 0 ) {
				file_put_contents( $path, str_repeat( "\0", $len ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		delete_option( $option_key );
		if ( $option_key === MDSM_RSA_Signing::OPTION_KEY_PATH ) {
			update_option( 'archiviomd_rsa_enabled', false );
		}
		wp_send_json_success( array( 'message' => sprintf( esc_html__( '%s cleared.', 'archiviomd' ), $type_label ) ) );
	}

	public function ajax_rsa_upload_key(): void {
		$this->handle_rsa_pem_upload( 'rsa_key_pem', MDSM_RSA_Signing::OPTION_KEY_PATH, 'rsa-private-key', true );
	}

	public function ajax_rsa_upload_cert(): void {
		$this->handle_rsa_pem_upload( 'rsa_cert_pem', 'archiviomd_rsa_cert_path', 'rsa-certificate', false );
	}

	public function ajax_rsa_clear_key(): void {
		$this->handle_rsa_pem_clear( MDSM_RSA_Signing::OPTION_KEY_PATH, 'RSA private key' );
	}

	public function ajax_rsa_clear_cert(): void {
		$this->handle_rsa_pem_clear( 'archiviomd_rsa_cert_path', 'RSA certificate' );
	}

	public function ajax_cms_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		$enabled = isset( $_POST['cms_enabled'] ) && sanitize_text_field( wp_unslash( $_POST['cms_enabled'] ) ) === 'true';
		if ( $enabled && class_exists( 'MDSM_CMS_Signing' ) ) {
			$st = MDSM_CMS_Signing::status();
			if ( ! $st['openssl_available'] || ! $st['key_available'] ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Cannot enable CMS signing: no compatible key source is active. Enable ECDSA P-256 or RSA signing first.', 'archiviomd' ) ) );
			}
		}
		update_option( 'archiviomd_cms_enabled', $enabled );
		$status = class_exists( 'MDSM_CMS_Signing' ) ? MDSM_CMS_Signing::status() : array( 'notice_message' => '' );
		wp_send_json_success( array(
			'message' => $enabled
				? esc_html__( 'CMS/PKCS#7 signing enabled.', 'archiviomd' )
				: esc_html__( 'CMS/PKCS#7 signing disabled.', 'archiviomd' ),
			'enabled' => $enabled,
			'notice'  => wp_strip_all_tags( $status['notice_message'] ?? '' ),
		) );
	}

	public function ajax_jsonld_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}
		$enabled = isset( $_POST['jsonld_enabled'] ) && sanitize_text_field( wp_unslash( $_POST['jsonld_enabled'] ) ) === 'true';
		if ( $enabled && class_exists( 'MDSM_JSONLD_Signing' ) ) {
			$st = MDSM_JSONLD_Signing::status();
			if ( ! $st['signer_available'] ) {
				wp_send_json_error( array( 'message' => esc_html__( 'Cannot enable JSON-LD signing: no compatible signer is active. Enable Ed25519 or ECDSA P-256 signing first.', 'archiviomd' ) ) );
			}
		}
		update_option( 'archiviomd_jsonld_enabled', $enabled );
		$status = class_exists( 'MDSM_JSONLD_Signing' ) ? MDSM_JSONLD_Signing::status() : array( 'notice_message' => '' );
		wp_send_json_success( array(
			'message' => $enabled
				? esc_html__( 'JSON-LD / W3C Data Integrity signing enabled.', 'archiviomd' )
				: esc_html__( 'JSON-LD signing disabled.', 'archiviomd' ),
			'enabled' => $enabled,
			'notice'  => wp_strip_all_tags( $status['notice_message'] ?? '' ),
			'suites'  => class_exists( 'MDSM_JSONLD_Signing' ) ? implode( ', ', MDSM_JSONLD_Signing::get_active_suites() ) : '',
		) );
	}

	public function ajax_dane_save_settings(): void {
		if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
			MDSM_DANE_Corroboration::get_instance()->ajax_save_settings();
		} else {
			check_ajax_referer( 'archivio_post_nonce', 'nonce' );
			wp_send_json_error( array( 'message' => esc_html__( 'DANE module not loaded.', 'archiviomd' ) ) );
		}
	}

	public function ajax_dane_health_check(): void {
		if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
			MDSM_DANE_Corroboration::get_instance()->ajax_health_check();
		} else {
			check_ajax_referer( 'archivio_post_nonce', 'nonce' );
			wp_send_json_error( array( 'message' => esc_html__( 'DANE module not loaded.', 'archiviomd' ) ) );
		}
	}

	public function ajax_dane_tlsa_check(): void {
		if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
			MDSM_DANE_Corroboration::get_instance()->ajax_tlsa_check();
		} else {
			check_ajax_referer( 'archivio_post_nonce', 'nonce' );
			wp_send_json_error( array( 'message' => esc_html__( 'DANE module not loaded.', 'archiviomd' ) ) );
		}
	}

	public function ajax_dane_start_rotation(): void {
		if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
			MDSM_DANE_Corroboration::get_instance()->ajax_start_rotation();
		} else {
			check_ajax_referer( 'archivio_post_nonce', 'nonce' );
			wp_send_json_error( array( 'message' => esc_html__( 'DANE module not loaded.', 'archiviomd' ) ) );
		}
	}

	public function ajax_dane_finish_rotation(): void {
		if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
			MDSM_DANE_Corroboration::get_instance()->ajax_finish_rotation();
		} else {
			check_ajax_referer( 'archivio_post_nonce', 'nonce' );
			wp_send_json_error( array( 'message' => esc_html__( 'DANE module not loaded.', 'archiviomd' ) ) );
		}
	}

	public function ajax_dane_dismiss_notice(): void {
		if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
			MDSM_DANE_Corroboration::get_instance()->ajax_dismiss_notice();
		} else {
			check_ajax_referer( 'archivio_post_nonce', 'nonce' );
			wp_send_json_success(); // Nothing to dismiss.
		}
	}

	public function ajax_export_audit_csv() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied', 'archiviomd' ) );
		}

		global $wpdb;

		$logs = $wpdb->get_results(
			"SELECT * FROM {$this->audit_table} ORDER BY timestamp DESC",
			ARRAY_A
		);

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=archivio-post-audit-log-' . gmdate( 'Y-m-d-H-i-s' ) . '.csv' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		$output = fopen( 'php://output', 'w' );
		fprintf( $output, chr( 0xEF ) . chr( 0xBB ) . chr( 0xBF ) );

		fputcsv( $output, array( 'ID', 'Post ID', 'Post Type', 'Author ID', 'Algorithm', 'Mode', 'Hash', 'Event Type', 'Result', 'Timestamp' ) );

		if ( ! empty( $logs ) ) {
			foreach ( $logs as $log ) {
				$unpacked = MDSM_Hash_Helper::unpack( $log['hash'] );

				$algo = ! empty( $log['algorithm'] ) ? $log['algorithm'] : $unpacked['algorithm'];
				$mode = ! empty( $log['mode'] )      ? $log['mode']      : $unpacked['mode'];

				fputcsv( $output, array(
					$log['id'],
					$log['post_id'],
					! empty( $log['post_type'] ) ? $log['post_type'] : 'post',
					$log['author_id'],
					MDSM_Hash_Helper::algorithm_label( $algo ),
					MDSM_Hash_Helper::mode_label( $mode ),
					$log['hash'],
					$log['event_type'],
					$log['result'],
					$log['timestamp'],
				) );
			}
		}

		fclose( $output );
		exit;
	}

	public function ajax_recreate_table() {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied', 'archiviomd' ) ) );
		}

		self::create_audit_table();

		global $wpdb;
		$table_name = $wpdb->prefix . 'archivio_post_audit';

		if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) {
			wp_send_json_success( array( 'message' => esc_html__( 'Audit log table recreated successfully!', 'archiviomd' ) ) );
		} else {
			wp_send_json_error( array( 'message' => esc_html__( 'Failed to create table. Check database permissions.', 'archiviomd' ) ) );
		}
	}

	public static function create_audit_table() {
		global $wpdb;

		$table_name      = $wpdb->prefix . 'archivio_post_audit';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			post_id bigint(20) NOT NULL,
			post_type varchar(20) NOT NULL DEFAULT 'post',
			author_id bigint(20) NOT NULL,
			hash varchar(210) NOT NULL,
			algorithm varchar(20) NOT NULL DEFAULT 'sha256',
			mode varchar(8) NOT NULL DEFAULT 'standard',
			event_type varchar(20) NOT NULL,
			result text NOT NULL,
			timestamp datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY post_id (post_id),
			KEY post_type (post_type),
			KEY author_id (author_id),
			KEY timestamp (timestamp)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// Backfill post_type column for existing installs that predate v1.5.9
		$columns = $wpdb->get_col( "SHOW COLUMNS FROM {$table_name}" );
		if ( ! in_array( 'post_type', $columns, true ) ) {
			$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN post_type varchar(20) NOT NULL DEFAULT 'post' AFTER post_id, ADD KEY post_type (post_type)" );
		}
	}

	public static function drop_audit_table() {
		global $wpdb;
		$table_name = $wpdb->prefix . 'archivio_post_audit';
		$wpdb->query( $wpdb->prepare( "DROP TABLE IF EXISTS %i", $table_name ) );
	}
}
