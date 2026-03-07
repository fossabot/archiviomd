<?php
/**
 * Plugin Name: ArchivioMD
 * Plugin URI: https://mountainviewprovisions.com/ArchivioMD
 * Description: Manage meta-docs, SEO files, and sitemaps with audit tools and HTML-rendered Markdown support.
 * Version: 1.17.6
 * Author: Mountain View Provisions LLC
 * Author URI: https://mountainviewprovisions.com/
 * Requires at least: 5.0
 * Tested up to: 6.9
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: archiviomd
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('MDSM_VERSION', '1.17.6');
define('MDSM_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('MDSM_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MDSM_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Main Plugin Class
 */
class Meta_Documentation_SEO_Manager {
    
    /**
     * Single instance of the class
     */
    private static $instance = null;
    
    /**
     * Get single instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->init();
    }
    
    /**
     * Initialize plugin
     */
    private function init() {
        // Load required files
        $this->load_dependencies();
        
        // Initialize public index
        new MDSM_Public_Index();
        
        // Initialize compliance tools (singleton)
        MDSM_Compliance_Tools::get_instance();
        
        // Initialize Archivio Post (singleton)
        MDSM_Archivio_Post::get_instance();
        
        // Initialize External Anchoring (singleton)
        MDSM_External_Anchoring::get_instance();

        // Initialize Ed25519 Document Signing (singleton)
        MDSM_Ed25519_Signing::get_instance();
        MDSM_SLHDSA_Signing::get_instance();
        MDSM_ECDSA_Signing::get_instance();
        MDSM_RSA_Signing::get_instance();
        MDSM_CMS_Signing::get_instance();
        MDSM_JSONLD_Signing::get_instance();
        MDSM_DANE_Corroboration::get_instance();

        // Initialize Canary Token fingerprinting (singleton)
        MDSM_Canary_Token::get_instance();
        
        // Initialize admin
        if (is_admin()) {
            add_action('admin_menu', array($this, 'add_admin_menu'));
            add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
            add_action('admin_notices', array($this, 'show_permalink_notice'));
            add_action('wp_ajax_mdsm_dismiss_permalink_notice', array($this, 'dismiss_permalink_notice'));
        }
        
        // Handle AJAX requests
        add_action('wp_ajax_mdsm_save_file', array($this, 'ajax_save_file'));
        add_action('wp_ajax_mdsm_delete_file', array($this, 'ajax_delete_file'));
        add_action('wp_ajax_mdsm_get_file_content', array($this, 'ajax_get_file_content'));
        add_action('wp_ajax_mdsm_get_file_counts', array($this, 'ajax_get_file_counts'));
        add_action('wp_ajax_mdsm_generate_sitemap', array($this, 'ajax_generate_sitemap'));
        add_action('wp_ajax_mdsm_generate_html', array($this, 'ajax_generate_html'));
        add_action('wp_ajax_mdsm_delete_html', array($this, 'ajax_delete_html'));
        add_action('wp_ajax_mdsm_check_html_status', array($this, 'ajax_check_html_status'));
        add_action('wp_ajax_mdsm_save_public_index', array($this, 'ajax_save_public_index'));
        add_action('wp_ajax_mdsm_create_custom_markdown', array($this, 'ajax_create_custom_markdown'));
        add_action('wp_ajax_mdsm_delete_custom_markdown', array($this, 'ajax_delete_custom_markdown'));
        add_action('wp_ajax_mdsm_get_changelog', array($this, 'ajax_get_changelog'));
        
        // Auto-update sitemaps if enabled
        add_action('save_post', array($this, 'maybe_auto_update_sitemap'));
        add_action('delete_post', array($this, 'maybe_auto_update_sitemap'));
        
        // Load plugin textdomain for translations (must run on init or later)
        add_action('init', array($this, 'load_textdomain'));

        // Add rewrite rules and serve files
        add_action('init', array($this, 'add_rewrite_rules'));
        add_filter('query_vars', array($this, 'add_query_vars'));
        add_action('template_redirect', array($this, 'serve_files'), 1);
        
        // Activation/deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    /**
     * Load plugin textdomain for translations.
     * Hooked to 'init' to satisfy WP 6.7+ requirements.
     */
    public function load_textdomain() {
        load_plugin_textdomain(
            'archiviomd',
            false,
            dirname( plugin_basename( __FILE__ ) ) . '/languages'
        );
    }

    /**
     * Load required files
     */
    private function load_dependencies() {
        require_once MDSM_PLUGIN_DIR . 'includes/class-file-manager.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-blake3.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-hash-helper.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-document-metadata.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-seo-file-metadata.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-sitemap-generator.php';
        require_once MDSM_PLUGIN_DIR . 'includes/file-definitions.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-html-renderer.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-public-index.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-compliance-tools.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-archivio-post.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-external-anchoring.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-ed25519-signing.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-slhdsa-signing.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-ecdsa-signing.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-rsa-signing.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-cms-signing.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-jsonld-signing.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-dane-corroboration.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-canary-token.php';
        require_once MDSM_PLUGIN_DIR . 'includes/class-cache-compat.php';

        // WP-CLI commands — loaded only when CLI is active, invisible at runtime.
        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            require_once MDSM_PLUGIN_DIR . 'includes/class-cli.php';
        }
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_menu_page(
            __('Meta Documentation & SEO', 'archiviomd'),
            __('Meta Docs & SEO', 'archiviomd'),
            'manage_options',
            'archiviomd',
            array($this, 'render_admin_page'),
            'dashicons-media-document',
            30
        );

        // WordPress auto-generates a duplicate first submenu entry matching the
        // parent slug. Remove it so only our real submenu items appear.
        remove_submenu_page( 'archiviomd', 'archiviomd' );
    }
    
    /**
     * Enqueue admin assets
     */
    public function enqueue_admin_assets($hook) {
        if ( 'toplevel_page_archiviomd' !== $hook ) {
            return;
        }
        
        wp_enqueue_style(
            'mdsm-admin-styles',
            MDSM_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            MDSM_VERSION
        );
        
        wp_enqueue_script(
            'mdsm-admin-scripts',
            MDSM_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery'),
            MDSM_VERSION,
            true
        );
        
        wp_localize_script('mdsm-admin-scripts', 'mdsmData', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('mdsm_nonce'),
            'siteUrl' => get_site_url(),
            'strings' => array(
                'saving' => __('Saving...', 'archiviomd'),
                'saved' => __('Saved successfully!', 'archiviomd'),
                'error' => __('Error occurred. Please try again.', 'archiviomd'),
                'confirmDelete' => __('This file will be deleted because it is empty. Continue?', 'archiviomd'),
                'generating' => __('Generating sitemap...', 'archiviomd'),
                'generated' => __('Sitemap generated successfully!', 'archiviomd'),
                'copied' => __('Link copied to clipboard!', 'archiviomd'),
                'generatingHtml' => __('Generating HTML...', 'archiviomd'),
                'htmlGenerated' => __('HTML file generated successfully!', 'archiviomd'),
                'deletingHtml' => __('Deleting HTML...', 'archiviomd'),
                'htmlDeleted' => __('HTML file deleted successfully!', 'archiviomd'),
                'confirmDeleteHtml' => __('Do you want to delete the associated HTML file?', 'archiviomd'),
            )
        ));
    }
    
    /**
     * Render admin page
     */
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'archiviomd'));
        }
        
        require_once MDSM_PLUGIN_DIR . 'admin/admin-page.php';
    }
    
    /**
     * Show permalink flush notice
     */
    public function show_permalink_notice() {
        // Only show on our plugin page
        $screen = get_current_screen();
        if (!$screen || $screen->id !== 'toplevel_page_archiviomd') {
            return;
        }
        
        // Check if notice has been dismissed
        if (get_option('mdsm_permalink_notice_dismissed', false)) {
            return;
        }
        
        ?>
        <div class="notice notice-warning is-dismissible" id="mdsm-permalink-notice">
            <p><strong>Go to Settings → Permalinks and click 'Save Changes' ← CRITICAL!</strong></p>
        </div>
        <?php
        wp_add_inline_script(
            'mdsm-admin-scripts',
            'jQuery(document).ready(function($){$("#mdsm-permalink-notice").on("click",".notice-dismiss",function(){$.post(ajaxurl,{action:"mdsm_dismiss_permalink_notice",nonce:"' . esc_js( wp_create_nonce('mdsm_dismiss_notice') ) . '"});});});'
        );
        ?>
        <?php
    }
    
    /**
     * Dismiss permalink notice
     */
    public function dismiss_permalink_notice() {
        check_ajax_referer('mdsm_dismiss_notice', 'nonce');
        
        if (current_user_can('manage_options')) {
            update_option('mdsm_permalink_notice_dismissed', true);
            wp_send_json_success();
        }
        
        wp_send_json_error();
    }
    
    /**
     * AJAX: Save file
     */
    public function ajax_save_file() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_type = sanitize_text_field( wp_unslash( $_POST['file_type'] ) );
        $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
        
        // Validate file_type against known-good values before any file operation
        $allowed_file_types = array( 'meta', 'seo' );
        if ( ! in_array( $file_type, $allowed_file_types, true ) ) {
            wp_send_json_error( array( 'message' => 'Invalid file type.' ) );
        }
        
        // Content is raw markdown/text and must not be sanitized (that would corrupt formatting).
        // XSS safety is enforced at render time: parse_inline() escapes all text nodes via esc_html()
        // before applying markdown patterns, and HTML output is served with X-Content-Type-Options: nosniff.
        $content = wp_unslash( $_POST['content'] );
        
        $file_manager = new MDSM_File_Manager();
        $result = $file_manager->save_file( $file_type, $file_name, $content );
        
        // Queue external anchor for native Markdown documents after successful save.
        // Queued in both HMAC and Basic modes — compute_packed() always returns a valid hash result.
        if ($result['success'] && $file_type === 'meta' && !empty($result['metadata']) && !empty(trim($content))) {
            $metadata    = $result['metadata'];
            $hash_result = MDSM_Hash_Helper::compute_packed($content);
            MDSM_External_Anchoring::get_instance()->queue_document_anchor(
                $file_name,
                $metadata,
                $hash_result
            );
        }
        
        // Auto-generate HTML for meta files if content is not empty
        if ($result['success'] && $file_type === 'meta' && !empty(trim($content))) {
            $html_renderer = new MDSM_HTML_Renderer();
            $html_result = $html_renderer->generate_html_file($file_type, $file_name);
            
            if ($html_result['success']) {
                $result['html_generated'] = true;
                $result['html_url'] = $html_result['html_url'];
                
                // Queue external anchor for the generated HTML output.
                $html_path = $html_renderer->get_html_file_path($file_type, $html_result['html_filename']);
                if ($html_path && file_exists($html_path)) {
                    $html_content = file_get_contents($html_path);
                    if ($html_content !== false) {
                        MDSM_External_Anchoring::get_instance()->queue_html_anchor(
                            $html_result['html_filename'],
                            $html_content
                        );
                    }
                }
            }
        }
        
        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
    
    /**
     * AJAX: Delete file
     */
    public function ajax_delete_file() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_type = sanitize_text_field( wp_unslash( $_POST['file_type'] ) );
        $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
        $delete_html = isset( $_POST['delete_html'] ) ? (bool) sanitize_text_field( wp_unslash( $_POST['delete_html'] ) ) : false;
        
        $file_manager = new MDSM_File_Manager();
        $result = $file_manager->delete_file($file_type, $file_name);
        
        // Check if HTML file exists for this MD file
        if ($result['success'] && $file_type === 'meta') {
            $html_renderer = new MDSM_HTML_Renderer();
            $html_exists = $html_renderer->html_file_exists($file_type, $file_name);
            
            if ($html_exists) {
                if ($delete_html) {
                    // User confirmed to delete HTML file
                    $html_renderer->delete_html_file($file_type, $file_name);
                } else {
                    // HTML file exists but user hasn't chosen yet
                    $result['html_exists'] = true;
                }
            }
        }
        
        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
    
    /**
     * AJAX: Get file content
     */
    public function ajax_get_file_content() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_type = sanitize_text_field( wp_unslash( $_POST['file_type'] ) );
        $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
        
        $file_manager = new MDSM_File_Manager();
        $file_info = $file_manager->get_file_info($file_type, $file_name);
        
        wp_send_json_success($file_info);
    }
    
    /**
     * AJAX: Get file counts
     */
    public function ajax_get_file_counts() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_manager = new MDSM_File_Manager();
        
        $meta_files = mdsm_get_meta_files();
        $meta_total = 0;
        foreach ($meta_files as $category => $files) {
            $meta_total += count($files);
        }
        
        $seo_files = mdsm_get_seo_files();
        $seo_total = count($seo_files);
        
        wp_send_json_success(array(
            'meta_exists' => $file_manager->get_existing_files_count('meta'),
            'meta_total' => $meta_total,
            'seo_exists' => $file_manager->get_existing_files_count('seo'),
            'seo_total' => $seo_total
        ));
    }
    
    /**
     * AJAX: Generate sitemap
     */
    public function ajax_generate_sitemap() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $sitemap_type = sanitize_text_field( wp_unslash( $_POST['sitemap_type'] ) );
        $auto_update = isset( $_POST['auto_update'] ) ? (bool) sanitize_text_field( wp_unslash( $_POST['auto_update'] ) ) : false;
        
        // Save auto-update preference
        update_option('mdsm_auto_update_sitemap', $auto_update);
        update_option('mdsm_sitemap_type', $sitemap_type);
        
        $generator = new MDSM_Sitemap_Generator();
        $result = $generator->generate($sitemap_type);
        
        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
    
    /**
     * Maybe auto-update sitemap
     */
    public function maybe_auto_update_sitemap() {
        if (get_option('mdsm_auto_update_sitemap', false)) {
            $sitemap_type = get_option('mdsm_sitemap_type', 'small');
            $generator = new MDSM_Sitemap_Generator();
            $generator->generate($sitemap_type);
        }
    }
    
    /**
     * AJAX: Generate HTML file
     */
    public function ajax_generate_html() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_type = sanitize_text_field( wp_unslash( $_POST['file_type'] ) );
        $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
        
        $html_renderer = new MDSM_HTML_Renderer();
        $result = $html_renderer->generate_html_file($file_type, $file_name);
        
        // Queue external anchor for the freshly generated HTML file.
        if ($result['success'] && !empty($result['html_filename'])) {
            $html_path = $html_renderer->get_html_file_path($file_type, $result['html_filename']);
            if ($html_path && file_exists($html_path)) {
                $html_content = file_get_contents($html_path);
                if ($html_content !== false) {
                    MDSM_External_Anchoring::get_instance()->queue_html_anchor(
                        $result['html_filename'],
                        $html_content
                    );
                }
            }
        }
        
        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
    
    /**
     * AJAX: Delete HTML file
     */
    public function ajax_delete_html() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_type = sanitize_text_field( wp_unslash( $_POST['file_type'] ) );
        $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
        
        $html_renderer = new MDSM_HTML_Renderer();
        $result = $html_renderer->delete_html_file($file_type, $file_name);
        
        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }
    
    /**
     * AJAX: Check HTML file status
     */
    public function ajax_check_html_status() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_type = sanitize_text_field( wp_unslash( $_POST['file_type'] ) );
        $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
        
        $html_renderer = new MDSM_HTML_Renderer();
        $exists = $html_renderer->html_file_exists($file_type, $file_name);
        $url = $exists ? $html_renderer->get_html_file_url($html_renderer->get_html_filename($file_name)) : null;
        
        wp_send_json_success(array(
            'exists' => $exists,
            'url' => $url
        ));
    }
    
    /**
     * AJAX: Save public index settings
     */
    public function ajax_save_public_index() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $enabled = isset( $_POST['enabled'] ) && sanitize_text_field( wp_unslash( $_POST['enabled'] ) ) === '1';
        $page_id = isset( $_POST['page_id'] ) ? absint( $_POST['page_id'] ) : 0;
        $public_docs = isset( $_POST['public_docs'] ) ? wp_unslash( $_POST['public_docs'] ) : array();
        $descriptions = isset( $_POST['descriptions'] ) ? wp_unslash( $_POST['descriptions'] ) : array();
        
        // Validate page selection if enabled
        if ($enabled && !$page_id) {
            wp_send_json_error(array('message' => 'Page selection is required when page mode is enabled'));
        }
        
        // Verify page exists if page_id is set
        if ($page_id && get_post_status($page_id) !== 'publish') {
            wp_send_json_error(array('message' => 'Selected page does not exist or is not published'));
        }
        
        // Sanitize public docs
        $sanitized_docs = array();
        if (is_array($public_docs)) {
            foreach ($public_docs as $key => $value) {
                $sanitized_docs[sanitize_text_field($key)] = true;
            }
        }
        
        // Sanitize descriptions
        $sanitized_descriptions = array();
        if (is_array($descriptions)) {
            foreach ($descriptions as $key => $value) {
                $sanitized_descriptions[sanitize_text_field($key)] = sanitize_text_field($value);
            }
        }
        
        // Save options
        $result1 = update_option('mdsm_public_index_enabled', $enabled);
        $result2 = update_option('mdsm_public_index_page_id', $page_id);
        $result3 = update_option('mdsm_public_documents', $sanitized_docs);
        $result4 = update_option('mdsm_document_descriptions', $sanitized_descriptions);
        
        wp_send_json_success(array(
            'message' => 'Settings saved successfully',
            'page_id' => $page_id,
            'enabled' => $enabled
        ));
    }
    
    /**
     * AJAX: Create custom markdown file
     */
    public function ajax_create_custom_markdown() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
            exit;
        }
        
        $filename = isset($_POST['filename']) ? sanitize_text_field( wp_unslash( $_POST['filename'] ) ) : '';
        $description = isset($_POST['description']) ? sanitize_text_field( wp_unslash( $_POST['description'] ) ) : '';
        
        if (empty($filename)) {
            wp_send_json_error(array('message' => 'Filename is required'));
            exit;
        }
        
        // Sanitize filename
        $filename = sanitize_file_name($filename);
        
        // Ensure .md extension
        if (!preg_match('/\.md$/', $filename)) {
            $filename .= '.md';
        }
        
        // Validate filename (no path traversal, etc.)
        if (preg_match('/[\/\\\\]/', $filename) || $filename === '.md' || $filename === '..md') {
            wp_send_json_error(array('message' => 'Invalid filename'));
            exit;
        }
        
        // Check if file already exists in predefined files
        $meta_files = mdsm_get_meta_files();
        foreach ($meta_files as $category => $files) {
            if (isset($files[$filename])) {
                wp_send_json_error(array('message' => 'This filename is already defined in ' . $category));
                exit;
            }
        }
        
        // Add to custom files
        if (mdsm_add_custom_markdown_file($filename, $description)) {
            // Flush rewrite rules to include the new file
            flush_rewrite_rules();
            
            wp_send_json_success(array(
                'message' => 'Custom markdown file created successfully',
                'filename' => $filename,
                'description' => $description
            ));
            exit;
        } else {
            wp_send_json_error(array('message' => 'This custom markdown file already exists'));
            exit;
        }
    }
    
    /**
     * AJAX: Delete custom markdown file
     */
    public function ajax_delete_custom_markdown() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $filename = isset($_POST['filename']) ? sanitize_text_field( wp_unslash( $_POST['filename'] ) ) : '';
        
        if (empty($filename)) {
            wp_send_json_error(array('message' => 'Filename is required'));
        }
        
        if (mdsm_delete_custom_markdown_file($filename)) {
            // Flush rewrite rules to remove the file
            flush_rewrite_rules();
            
            wp_send_json_success(array('message' => 'Custom markdown file deleted successfully'));
        } else {
            wp_send_json_error(array('message' => 'Failed to delete custom markdown file'));
        }
    }
    
    /**
     * AJAX: Get changelog for a document
     */
    public function ajax_get_changelog() {
        check_ajax_referer('mdsm_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $file_name = isset($_POST['file_name']) ? sanitize_text_field( wp_unslash( $_POST['file_name'] ) ) : '';
        
        if (empty($file_name)) {
            wp_send_json_error(array('message' => 'File name is required'));
        }
        
        $metadata_manager = new MDSM_Document_Metadata();
        $changelog = $metadata_manager->get_changelog($file_name);
        
        if (empty($changelog)) {
            wp_send_json_error(array('message' => 'No changelog found for this document'));
        }
        
        // Format changelog for display
        $formatted_changelog = array();
        foreach ($changelog as $entry) {
            $user = get_userdata($entry['user_id']);
            $user_display = $user ? $user->display_name : 'Unknown User';
            
            $formatted_changelog[] = array(
                'timestamp' => gmdate('Y-m-d H:i:s \U\T\C', strtotime($entry['timestamp'])),
                'user' => $user_display,
                'action' => ucfirst($entry['action']),
                'checksum' => substr($entry['checksum'], 0, 16) . '...'
            );
        }
        
        wp_send_json_success(array(
            'changelog' => $formatted_changelog,
            'file_name' => $file_name
        ));
    }
    
    /**
     * Add rewrite rules for our files
     */
    public function add_rewrite_rules() {
        // Get all managed files
        $meta_files = mdsm_get_meta_files();
        $seo_files = mdsm_get_seo_files();
        $custom_files = mdsm_get_custom_markdown_files();
        
        $all_files = array();
        
        // Add meta files (both .md and .html)
        foreach ($meta_files as $category => $files) {
            foreach ($files as $file_name => $description) {
                $all_files[] = $file_name; // .md file
                // Add corresponding .html file
                $html_filename = preg_replace('/\.md$/', '.html', $file_name);
                $all_files[] = $html_filename;
            }
        }
        
        // Add custom markdown files (both .md and .html)
        foreach ($custom_files as $file_name => $description) {
            $all_files[] = $file_name; // .md file
            // Add corresponding .html file
            $html_filename = preg_replace('/\.md$/', '.html', $file_name);
            $all_files[] = $html_filename;
        }
        
        // Add SEO files
        $all_files = array_merge($all_files, array_keys($seo_files));
        
        // Add sitemap files
        $all_files[] = 'sitemap.xml';
        $all_files[] = 'sitemap_index.xml';
        
        // Add rewrite rule for each file
        foreach ($all_files as $file) {
            add_rewrite_rule(
                '^' . preg_quote($file) . '$',
                'index.php?mdsm_file=' . $file,
                'top'
            );
        }
        
        // Add pattern for sitemap-*.xml files
        add_rewrite_rule(
            '^sitemap-([^/]+)\.xml$',
            'index.php?mdsm_file=sitemap-$matches[1].xml',
            'top'
        );

        // Well-known endpoint for Ed25519 public key.
        add_rewrite_rule(
            '^\.well-known/ed25519-pubkey\.txt$',
            'index.php?mdsm_file=ed25519-pubkey.txt',
            'top'
        );

        // Well-known endpoint for SLH-DSA public key.
        add_rewrite_rule(
            '^\.well-known/slhdsa-pubkey.txt$',
            'index.php?mdsm_file=slhdsa-pubkey.txt',
            'top'
        );

        // Well-known endpoint for ECDSA leaf certificate.
        add_rewrite_rule(
            '^\.well-known/ecdsa-cert.pem$',
            'index.php?mdsm_file=ecdsa-cert.pem',
            'top'
        );

        // Well-known endpoint for RSA public key (Extended / compatibility mode).
        add_rewrite_rule(
            '^\.well-known/rsa-pubkey.pem$',
            'index.php?mdsm_file=rsa-pubkey.pem',
            'top'
        );

        // Well-known endpoint for W3C DID document (JSON-LD / Data Integrity).
        add_rewrite_rule(
            '^\.well-known/did.json$',
            'index.php?mdsm_file=did.json',
            'top'
        );

        // Well-known endpoint for DANE DNS discovery document.
        add_rewrite_rule(
            '^\.well-known/archiviomd-dns\.json$',
            'index.php?mdsm_file=archiviomd-dns.json',
            'top'
        );

        // Well-known endpoint for DANE DNS format specification.
        add_rewrite_rule(
            '^\.well-known/archiviomd-dns-spec\.json$',
            'index.php?mdsm_file=archiviomd-dns-spec.json',
            'top'
        );
    }
    
    /**
     * Add query vars
     */
    public function add_query_vars($vars) {
        $vars[] = 'mdsm_file';
        return $vars;
    }
    
    /**
     * Serve files when requested
     */
    public function serve_files() {
        $file = get_query_var('mdsm_file');
        
        if (empty($file)) {
            return; // Not a request for our files
        }

        // ── Ed25519 public key well-known endpoint ──────────────────────
        if ( $file === 'ed25519-pubkey.txt' ) {
            MDSM_Ed25519_Signing::serve_public_key(); // exits
        }

        // ── SLH-DSA public key well-known endpoint ──────────────────────
        if ( $file === 'slhdsa-pubkey.txt' ) {
            MDSM_SLHDSA_Signing::serve_public_key(); // exits
        }

        // ── ECDSA leaf certificate well-known endpoint ───────────────────
        if ( $file === 'ecdsa-cert.pem' ) {
            MDSM_ECDSA_Signing::serve_certificate(); // exits
        }

        // ── RSA public key well-known endpoint ───────────────────────────
        if ( $file === 'rsa-pubkey.pem' ) {
            MDSM_RSA_Signing::serve_public_key(); // exits (stub: 404 until implemented)
        }

        // ── W3C DID document well-known endpoint ─────────────────────────
        if ( $file === 'did.json' ) {
            MDSM_JSONLD_Signing::serve_did_document(); // exits
        }

        // ── DANE DNS discovery document ───────────────────────────────────
        if ( $file === 'archiviomd-dns.json' ) {
            if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
                MDSM_DANE_Corroboration::serve_dns_json(); // exits
            }
            status_header( 404 );
            exit;
        }

        // ── DANE DNS format specification ─────────────────────────────────
        if ( $file === 'archiviomd-dns-spec.json' ) {
            if ( class_exists( 'MDSM_DANE_Corroboration' ) ) {
                MDSM_DANE_Corroboration::serve_dns_spec(); // exits
            }
            status_header( 404 );
            exit;
        }
        
        // Determine file type
        $file_type = null;
        if (preg_match('/\.md$/', $file)) {
            $file_type = 'meta';
        } elseif (preg_match('/\.html$/', $file)) {
            $file_type = 'html';
        } elseif (preg_match('/\.(txt)$/', $file)) {
            $file_type = 'seo';
        } elseif (preg_match('/\.xml$/', $file)) {
            $file_type = 'sitemap';
        }
        
        if (!$file_type) {
            return;
        }
        
        // Get file path
        if ($file_type === 'sitemap') {
            $upload_dir = wp_upload_dir();
            $root_sitemap = ABSPATH . $file;
            $upload_sitemap = $upload_dir['basedir'] . '/meta-docs/' . $file;
            $file_path = file_exists($root_sitemap) ? $root_sitemap : $upload_sitemap;
        } elseif ($file_type === 'html') {
            // Handle HTML files
            $html_renderer = new MDSM_HTML_Renderer();
            $file_path = $html_renderer->get_html_file_path('meta', $file);
        } else {
            $file_manager = new MDSM_File_Manager();
            $file_path = $file_manager->get_file_path($file_type, $file);
        }
        
        // Check if file exists
        if (!$file_path || !file_exists($file_path) || !is_readable($file_path)) {
            status_header(404);
            nocache_headers();
            include(get_404_template());
            exit;
        }
        
        // Serve the file
        $this->output_file($file_path, $file);
    }
    
    /**
     * Output file with proper headers
     */
    private function output_file($filepath, $filename) {
        // Get extension
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        
        // Content types
        $content_types = array(
            'md' => 'text/markdown; charset=utf-8',
            'txt' => 'text/plain; charset=utf-8',
            'xml' => 'application/xml; charset=utf-8',
            'html' => 'text/html; charset=utf-8',
        );
        
        $content_type = isset($content_types[$ext]) ? $content_types[$ext] : 'text/plain; charset=utf-8';
        
        // Get content
        $content = file_get_contents($filepath);
        
        if ($content === false) {
            status_header(500);
            exit('Error reading file');
        }
        
        // Clear output buffers
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        // Set status and headers
        status_header(200);
        header('Content-Type: ' . $content_type);
        header('Content-Length: ' . strlen($content));
        header('Cache-Control: public, max-age=3600');
        // Prevent MIME-sniffing and clickjacking on generated files
        header('X-Content-Type-Options: nosniff');
        if ($ext !== 'html') {
            // Force non-HTML files to download rather than render, preventing
            // browsers from sniffing and executing as HTML
            header('Content-Disposition: inline; filename="' . rawurlencode($filename) . '"');
        }
        
        // Output
        echo $content;
        exit;
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Create directories if needed
        $upload_dir = wp_upload_dir();
        $plugin_dir = $upload_dir['basedir'] . '/meta-docs';
        
        if (!file_exists($plugin_dir)) {
            wp_mkdir_p($plugin_dir);
        }
        
        // Set default options
        add_option('mdsm_auto_update_sitemap', false);
        add_option('mdsm_sitemap_type', 'small');
        
        // Set default Archivio Post options - use update_option to ensure they're set correctly
        // even if they existed before with wrong values
        // Default to false (unchecked) - user must explicitly enable
        if (get_option('archivio_post_auto_generate') === false) {
            update_option('archivio_post_auto_generate', false);
        }
        if (get_option('archivio_post_show_badge') === false) {
            update_option('archivio_post_show_badge', false);
        }
        if (get_option('archivio_post_show_badge_posts') === false) {
            update_option('archivio_post_show_badge_posts', false);
        }
        if (get_option('archivio_post_show_badge_pages') === false) {
            update_option('archivio_post_show_badge_pages', false);
        }
        if (get_option('archivio_hash_algorithm') === false) {
            update_option('archivio_hash_algorithm', 'sha256');
        }
        
        // Create Archivio Post audit table
        MDSM_Archivio_Post::create_audit_table();
        
        // Create External Anchoring log table
        MDSM_Anchor_Log::create_table();

        // Create Canary Token discovery log table
        MDSM_Canary_Token::create_log_table();

        // Schedule daily cache health check for canary Unicode stripping detection
        MDSM_Canary_Token::schedule_cache_check();
        
        // Schedule anchoring cron
        MDSM_External_Anchoring::activate_cron();
        
        // Add rewrite rules and flush
        $this->add_rewrite_rules();
        flush_rewrite_rules();
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Flush rewrite rules to remove our custom rules
        flush_rewrite_rules();
        
        // Unschedule anchoring cron
        MDSM_External_Anchoring::deactivate_cron();

        // Unschedule canary cache health check
        MDSM_Canary_Token::unschedule_cache_check();
    }
}

// Initialize plugin
function mdsm_init() {
    return Meta_Documentation_SEO_Manager::get_instance();
}

// Start the plugin
add_action('plugins_loaded', 'mdsm_init');

// Cache compatibility layer — must run after mdsm_init so MDSM_Canary_Token
// is available, but early enough that our ob_start wraps any caching plugin
// that also hooks template_redirect.  plugins_loaded priority 15 achieves this.
add_action( 'plugins_loaded', function() {
	MDSM_Canary_Cache_Compat::get_instance();
}, 15 );

/**
 * Run lightweight upgrade checks on every load.
 * Creates the canary discovery log table for sites that were already active
 * before 1.10.0 (activation hook only fires on fresh installs / re-activations).
 */
add_action( 'plugins_loaded', function() {
    $db_ver = get_option( 'archiviomd_db_version', '0' );
    if ( version_compare( $db_ver, '1.10.0', '<' ) ) {
        MDSM_Canary_Token::create_log_table();
        MDSM_Canary_Token::schedule_cache_check();
        update_option( 'archiviomd_db_version', '1.10.0', false );
    }
}, 20 );
