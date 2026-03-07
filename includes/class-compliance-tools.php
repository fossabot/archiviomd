<?php
/**
 * Compliance Tools Handler
 * 
 * Handles backend operations for compliance tools:
 * - Metadata Export (CSV)
 * - Backup & Restore
 * - Metadata Verification
 */

if (!defined('ABSPATH')) {
    exit;
}

class MDSM_Compliance_Tools {
    
    /**
     * Single instance of the class
     */
    private static $instance = null;

    /**
     * Confirm a resolved filepath is confined within an expected directory.
     *
     * Uses realpath() so symlinks and '..' sequences cannot escape the boundary.
     * Returns false if the file does not exist yet; call after wp_mkdir_p() has
     * created the parent directory so realpath() on dirname() works reliably.
     *
     * @param string $filepath     The candidate file path to check.
     * @param string $allowed_dir  The directory it must resolve inside.
     * @return bool True if safe, false otherwise.
     */
    private static function is_path_confined( string $filepath, string $allowed_dir ): bool {
        $real_dir  = realpath( $allowed_dir );
        $real_file = realpath( dirname( $filepath ) );
        if ( false === $real_dir || false === $real_file ) {
            return false;
        }
        return str_starts_with( $real_file . DIRECTORY_SEPARATOR, $real_dir . DIRECTORY_SEPARATOR );
    }
    
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
        // Add tools submenu
        add_action('admin_menu', array($this, 'add_tools_menu'), 20);
        
        // Register AJAX handlers
        add_action('wp_ajax_mdsm_export_metadata_csv', array($this, 'ajax_export_metadata_csv'));
        add_action('wp_ajax_mdsm_create_backup_archive', array($this, 'ajax_create_backup_archive'));
        add_action('wp_ajax_mdsm_restore_dryrun', array($this, 'ajax_restore_dryrun'));
        add_action('wp_ajax_mdsm_execute_restore', array($this, 'ajax_execute_restore'));
        add_action('wp_ajax_mdsm_verify_checksums', array($this, 'ajax_verify_checksums'));
        add_action('wp_ajax_mdsm_download_csv', array($this, 'ajax_download_csv'));
        add_action('wp_ajax_mdsm_download_backup', array($this, 'ajax_download_backup'));
        add_action('wp_ajax_mdsm_save_uninstall_cleanup', array($this, 'ajax_save_uninstall_cleanup'));
        add_action('wp_ajax_mdsm_export_compliance_json',  array($this, 'ajax_export_compliance_json'));
        add_action('wp_ajax_mdsm_download_compliance_json', array($this, 'ajax_download_compliance_json'));
        add_action('wp_ajax_mdsm_download_export_sig', array($this, 'ajax_download_export_sig'));
        
        // Add admin notice about backups
        add_action('admin_notices', array($this, 'show_backup_notice'));
        add_action('wp_ajax_mdsm_dismiss_backup_notice', array($this, 'dismiss_backup_notice'));
    }
    
    /**
     * Add Tools submenu
     */
    /**
     * Enqueue compliance page assets
     */
    public function enqueue_compliance_assets( $hook ) {
        if ( 'tools_page_archivio-md-compliance' !== $hook ) {
            return;
        }
        // Styles and scripts are added via wp_add_inline_style/script from the page template
        wp_register_style( 'mdsm-compliance-tools', false, array(), MDSM_VERSION );
        wp_enqueue_style( 'mdsm-compliance-tools' );
        wp_register_script( 'mdsm-compliance-tools-js', false, array( 'jquery' ), MDSM_VERSION, true );
        wp_enqueue_script( 'mdsm-compliance-tools-js' );
    }
    
    public function add_tools_menu() {
        add_submenu_page(
            'archiviomd',
            __('ArchivioMD Compliance', 'archiviomd'),
            __('Metadata Engine', 'archiviomd'),
            'manage_options',
            'archivio-md-compliance',
            array($this, 'render_tools_page')
        );
    }
    
    /**
     * Render tools page
     */
    public function render_tools_page() {
        require_once MDSM_PLUGIN_DIR . 'admin/compliance-tools-page.php';
    }
    
    /**
     * Show dismissible admin notice about backups
     */
    public function show_backup_notice() {
        // Check if notice has been dismissed
        if (get_option('mdsm_backup_notice_dismissed', false)) {
            return;
        }
        
        // Only show to admins
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Show on admin pages
        $screen = get_current_screen();
        if (!$screen || $screen->parent_base === 'options-general') {
            return; // Don't show on settings pages
        }
        
        ?>
        <div class="notice notice-info is-dismissible" id="mdsm-backup-notice">
            <p><strong>ArchivioMD:</strong> Metadata (UUIDs, checksums, changelogs) is stored in your WordPress database. 
            Regular database backups are required for complete data protection. 
            <a href="<?php echo esc_url( admin_url('tools.php?page=archivio-md-compliance') ); ?>">View compliance tools</a></p>
        </div>
        <?php
        wp_add_inline_script(
            'mdsm-admin-scripts',
            'jQuery(document).ready(function($){$("#mdsm-backup-notice").on("click",".notice-dismiss",function(){$.post(ajaxurl,{action:"mdsm_dismiss_backup_notice",nonce:"' . esc_js( wp_create_nonce('mdsm_dismiss_backup_notice') ) . '"});});});'
        );
        ?>
        <?php
    }
    
    /**
     * Dismiss backup notice
     */
    public function dismiss_backup_notice() {
        check_ajax_referer('mdsm_dismiss_backup_notice', 'nonce');
        
        if (current_user_can('manage_options')) {
            update_option('mdsm_backup_notice_dismissed', true);
            wp_send_json_success();
        }
        
        wp_send_json_error();
    }
    
    /**
     * AJAX: Export metadata to CSV
     */
    public function ajax_export_metadata_csv() {
        check_ajax_referer('mdsm_export_metadata', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        try {
            $csv_data = $this->generate_metadata_csv();
            
            // Save to temp file
            $upload_dir = wp_upload_dir();
            $temp_dir = $upload_dir['basedir'] . '/archivio-md-temp';
            
            if (!file_exists($temp_dir)) {
                wp_mkdir_p($temp_dir);
            }
            
            $timestamp = gmdate('Y-m-d_H-i-s');
            $filename = 'archivio-md-metadata-' . $timestamp . '.csv';
            $filepath = $temp_dir . '/' . $filename;
            
            file_put_contents($filepath, $csv_data);

            // Sign the export and write a sidecar .sig.json file.
            $sig_result = $this->sign_export_file( $filepath, $filename, 'metadata_csv' );

            // Create download URL with nonce
            $download_nonce = wp_create_nonce('mdsm_download_csv_' . $filename);
            $download_url = admin_url('admin-ajax.php?action=mdsm_download_csv&file=' . urlencode($filename) . '&nonce=' . $download_nonce);

            $response = array(
                'download_url' => $download_url,
                'filename'     => $filename,
            );

            if ( $sig_result ) {
                $sig_filename      = basename( $sig_result );
                $sig_nonce         = wp_create_nonce( 'mdsm_download_export_sig_' . $sig_filename );
                $response['sig_url']      = admin_url( 'admin-ajax.php?action=mdsm_download_export_sig&file=' . urlencode( $sig_filename ) . '&nonce=' . $sig_nonce );
                $response['sig_filename'] = $sig_filename;
            }

            wp_send_json_success( $response );
            
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Generate metadata CSV content
     */
    private function generate_metadata_csv() {
        $file_manager = new MDSM_File_Manager();
        $metadata_manager = new MDSM_Document_Metadata();
        
        // Get all managed files
        $meta_files = mdsm_get_meta_files();
        $custom_files = mdsm_get_custom_markdown_files();
        
        $csv_rows = array();
        
        // CSV header
        $csv_rows[] = array(
            'UUID',
            'Filename',
            'File Path',
            'Last Modified (UTC)',
            'SHA-256 Checksum',
            'Changelog Count',
            'Changelog Entries (JSON)'
        );
        
        // Process meta files
        foreach ($meta_files as $category => $files) {
            foreach ($files as $file_name => $description) {
                if ($file_manager->file_exists('meta', $file_name)) {
                    $metadata = $metadata_manager->get_metadata($file_name);
                    if (!empty($metadata['uuid'])) {
                        $file_path = $file_manager->get_file_path('meta', $file_name);
                        $csv_rows[] = array(
                            $metadata['uuid'],
                            $file_name,
                            $file_path,
                            $metadata['modified_at'] ?? '',
                            $metadata['checksum'] ?? '',
                            count($metadata['changelog']),
                            json_encode($metadata['changelog'])
                        );
                    }
                }
            }
        }
        
        // Process custom files
        foreach ($custom_files as $file_name => $description) {
            if ($file_manager->file_exists('meta', $file_name)) {
                $metadata = $metadata_manager->get_metadata($file_name);
                if (!empty($metadata['uuid'])) {
                    $file_path = $file_manager->get_file_path('meta', $file_name);
                    $csv_rows[] = array(
                        $metadata['uuid'],
                        $file_name,
                        $file_path,
                        $metadata['modified_at'] ?? '',
                        $metadata['checksum'] ?? '',
                        count($metadata['changelog']),
                        json_encode($metadata['changelog'])
                    );
                }
            }
        }
        
        // Convert to CSV format
        $output = '';
        foreach ($csv_rows as $row) {
            $output .= $this->csv_row($row);
        }
        
        return $output;
    }
    
    /**
     * Format CSV row
     */
    private function csv_row($fields) {
        $escaped = array();
        foreach ($fields as $field) {
            $escaped[] = '"' . str_replace('"', '""', $field) . '"';
        }
        return implode(',', $escaped) . "\n";
    }
    
    /**
     * AJAX: Download CSV file
     */
    public function ajax_download_csv() {
        $filename = isset($_GET['file']) ? sanitize_file_name( wp_unslash( $_GET['file'] ) ) : '';
        $nonce = isset( $_GET['nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['nonce'] ) ) : '';
        
        if (empty($filename) || !wp_verify_nonce($nonce, 'mdsm_download_csv_' . $filename)) {
            wp_die('Invalid request');
        }
        
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }
        
        $upload_dir = wp_upload_dir();
        $temp_dir   = $upload_dir['basedir'] . '/archivio-md-temp';
        $filepath   = $temp_dir . '/' . $filename;

        // Confine the resolved path to the temp directory — defence against
        // sanitize_file_name() edge-cases or symlink tricks.
        if ( ! self::is_path_confined( $filepath, $temp_dir ) ) {
            wp_die( 'Invalid file path' );
        }

        if (!file_exists($filepath)) {
            wp_die('File not found');
        }
        
        // Send file
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($filepath));
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        readfile($filepath);
        
        // Delete temp file
        @unlink($filepath);
        
        exit;
    }
    
    /**
     * AJAX: Create backup archive
     */
    public function ajax_create_backup_archive() {
        check_ajax_referer('mdsm_create_backup', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        try {
            $backup_file = $this->create_backup_archive();
            
            if (!$backup_file) {
                wp_send_json_error(array('message' => 'Failed to create backup archive'));
            }
            
            // Create download URL
            $filename = basename($backup_file);
            $download_nonce = wp_create_nonce('mdsm_download_backup_' . $filename);
            $download_url = admin_url('admin-ajax.php?action=mdsm_download_backup&file=' . urlencode($filename) . '&nonce=' . $download_nonce);

            // Sign the backup archive and write a sidecar .sig.json file.
            $sig_result = $this->sign_export_file( $backup_file, $filename, 'backup_zip' );

            $response = array(
                'download_url' => $download_url,
                'filename'     => $filename,
            );

            if ( $sig_result ) {
                $sig_filename      = basename( $sig_result );
                $sig_nonce         = wp_create_nonce( 'mdsm_download_export_sig_' . $sig_filename );
                $response['sig_url']      = admin_url( 'admin-ajax.php?action=mdsm_download_export_sig&file=' . urlencode( $sig_filename ) . '&nonce=' . $sig_nonce );
                $response['sig_filename'] = $sig_filename;
            }

            wp_send_json_success( $response );
            
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Create backup archive
     */
    private function create_backup_archive() {
        $file_manager = new MDSM_File_Manager();
        $metadata_manager = new MDSM_Document_Metadata();
        
        // Get all files with metadata
        $meta_files = mdsm_get_meta_files();
        $custom_files = mdsm_get_custom_markdown_files();
        
        $backup_data = array(
            'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'wordpress_version' => get_bloginfo('version'),
            'plugin_version' => MDSM_VERSION,
            'site_url' => get_site_url(),
            'documents' => array()
        );
        
        // Collect all documents and metadata
        foreach ($meta_files as $category => $files) {
            foreach ($files as $file_name => $description) {
                if ($file_manager->file_exists('meta', $file_name)) {
                    $metadata = $metadata_manager->get_metadata($file_name);
                    if (!empty($metadata['uuid'])) {
                        $content = $file_manager->read_file('meta', $file_name);
                        $backup_data['documents'][$file_name] = array(
                            'metadata' => $metadata,
                            'content' => $content,
                            'category' => $category,
                            'description' => $description
                        );
                    }
                }
            }
        }
        
        foreach ($custom_files as $file_name => $description) {
            if ($file_manager->file_exists('meta', $file_name)) {
                $metadata = $metadata_manager->get_metadata($file_name);
                if (!empty($metadata['uuid'])) {
                    $content = $file_manager->read_file('meta', $file_name);
                    $backup_data['documents'][$file_name] = array(
                        'metadata' => $metadata,
                        'content' => $content,
                        'category' => 'Custom',
                        'description' => $description
                    );
                }
            }
        }
        
        // Create temp directory
        $upload_dir = wp_upload_dir();
        $temp_dir = $upload_dir['basedir'] . '/archivio-md-temp';
        
        if (!file_exists($temp_dir)) {
            wp_mkdir_p($temp_dir);
        }
        
        $timestamp = gmdate('Y-m-d_H-i-s');
        $backup_id = 'backup-' . $timestamp . '-' . substr(md5(uniqid()), 0, 8);
        $backup_dir = $temp_dir . '/' . $backup_id;
        
        wp_mkdir_p($backup_dir);
        wp_mkdir_p($backup_dir . '/documents');
        
        // Save manifest
        $manifest = array(
            'backup_id' => $backup_id,
            'created_at' => $backup_data['created_at'],
            'wordpress_version' => $backup_data['wordpress_version'],
            'plugin_version' => $backup_data['plugin_version'],
            'site_url' => $backup_data['site_url'],
            'document_count' => count($backup_data['documents']),
            'documents' => array()
        );
        
        // Save individual documents and build manifest
        foreach ($backup_data['documents'] as $file_name => $doc_data) {
            // Save metadata
            $metadata_file = $backup_dir . '/documents/' . $file_name . '.meta.json';
            file_put_contents($metadata_file, json_encode($doc_data['metadata'], JSON_PRETTY_PRINT));
            
            // Save content
            $content_file = $backup_dir . '/documents/' . $file_name;
            file_put_contents($content_file, $doc_data['content']);
            
            // Add to manifest
            $manifest['documents'][$file_name] = array(
                'uuid' => $doc_data['metadata']['uuid'],
                'checksum' => $doc_data['metadata']['checksum'],
                'modified_at' => $doc_data['metadata']['modified_at'],
                'category' => $doc_data['category']
            );
        }
        
        file_put_contents($backup_dir . '/manifest.json', json_encode($manifest, JSON_PRETTY_PRINT));
        
        // Create README
        $readme = "ArchivioMD Backup Archive\n";
        $readme .= "==========================\n\n";
        $readme .= "Created: " . $backup_data['created_at'] . "\n";
        $readme .= "Documents: " . count($backup_data['documents']) . "\n";
        $readme .= "Plugin Version: " . $backup_data['plugin_version'] . "\n\n";
        $readme .= "This archive contains:\n";
        $readme .= "- manifest.json: Backup metadata and checksums\n";
        $readme .= "- documents/: All Markdown files and their metadata\n\n";
        $readme .= "To restore, upload this ZIP file to Tools → ArchivioMD in your WordPress admin.\n";
        
        file_put_contents($backup_dir . '/README.txt', $readme);
        
        // Create ZIP archive
        $zip_file = $temp_dir . '/' . $backup_id . '.zip';
        
        if (!$this->create_zip($backup_dir, $zip_file)) {
            return false;
        }
        
        // Clean up temp directory
        $this->delete_directory($backup_dir);
        
        return $zip_file;
    }
    
    /**
     * Create ZIP archive
     */
    private function create_zip($source, $destination) {
        if (!extension_loaded('zip')) {
            return false;
        }
        
        $zip = new ZipArchive();
        if (!$zip->open($destination, ZipArchive::CREATE)) {
            return false;
        }
        
        $source = realpath($source);
        
        if (is_dir($source)) {
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($source),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            
            foreach ($files as $file) {
                if (!$file->isDir()) {
                    $filePath = $file->getRealPath();
                    $relativePath = substr($filePath, strlen($source) + 1);
                    $zip->addFile($filePath, $relativePath);
                }
            }
        }
        
        return $zip->close();
    }
    
    /**
     * Delete directory recursively
     */
    private function delete_directory($dir) {
        if (!file_exists($dir)) {
            return true;
        }
        
        $files = array_diff(scandir($dir), array('.', '..'));
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->delete_directory($path) : unlink($path);
        }
        
        return rmdir($dir);
    }
    
    /**
     * AJAX: Download backup file
     */
    public function ajax_download_backup() {
        $filename = isset($_GET['file']) ? sanitize_file_name( wp_unslash( $_GET['file'] ) ) : '';
        $nonce = isset( $_GET['nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['nonce'] ) ) : '';
        
        if (empty($filename) || !wp_verify_nonce($nonce, 'mdsm_download_backup_' . $filename)) {
            wp_die('Invalid request');
        }
        
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }
        
        $upload_dir = wp_upload_dir();
        $temp_dir   = $upload_dir['basedir'] . '/archivio-md-temp';
        $filepath   = $temp_dir . '/' . $filename;

        if ( ! self::is_path_confined( $filepath, $temp_dir ) ) {
            wp_die( 'Invalid file path' );
        }

        if (!file_exists($filepath)) {
            wp_die('File not found');
        }
        
        // Send file
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($filepath));
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        readfile($filepath);
        
        // Delete temp file
        @unlink($filepath);
        
        exit;
    }
    
    /**
     * AJAX: Restore dry run (analyze backup)
     */
    public function ajax_restore_dryrun() {
        check_ajax_referer('mdsm_restore_dryrun', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        if (empty($_FILES['backup_file'])) {
            wp_send_json_error(array('message' => 'No backup file uploaded'));
        }
        
        try {
            $analysis = $this->analyze_backup($_FILES['backup_file']);
            wp_send_json_success($analysis);
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Analyze backup file (dry run)
     */
    private function analyze_backup($uploaded_file) {
        // Validate uploaded file
        if ( $uploaded_file['error'] !== UPLOAD_ERR_OK ) {
            throw new Exception( 'Upload failed' );
        }
        
        if ( ! is_uploaded_file( $uploaded_file['tmp_name'] ) ) {
            throw new Exception( 'Invalid file upload' );
        }
        
        // Validate MIME type for ZIP
        $finfo = new finfo( FILEINFO_MIME_TYPE );
        $mime  = $finfo->file( $uploaded_file['tmp_name'] );
        $allowed_mime = array( 'application/zip', 'application/x-zip-compressed', 'application/octet-stream' );
        if ( ! in_array( $mime, $allowed_mime, true ) ) {
            throw new Exception( 'Uploaded file is not a valid ZIP archive' );
        }
        
        // Extract ZIP to temp directory
        $upload_dir = wp_upload_dir();
        $temp_dir = $upload_dir['basedir'] . '/archivio-md-temp';
        
        if (!file_exists($temp_dir)) {
            wp_mkdir_p($temp_dir);
        }
        
        $extract_dir = $temp_dir . '/restore-' . uniqid();
        wp_mkdir_p($extract_dir);
        
        $zip = new ZipArchive();
        if ($zip->open($uploaded_file['tmp_name']) !== true) {
            throw new Exception('Failed to open backup archive');
        }

        // Zip slip guard: reject any entry whose name contains a path traversal
        // sequence or an absolute path before we allow extractTo() to run.
        for ( $i = 0; $i < $zip->numFiles; $i++ ) {
            $entry = $zip->getNameIndex( $i );
            if ( $entry === false ) { continue; }
            if ( strpos( $entry, '..' ) !== false || strpos( $entry, '\\' ) !== false
                    || substr( $entry, 0, 1 ) === '/' ) {
                $zip->close();
                $this->delete_directory( $extract_dir );
                throw new Exception( 'Invalid backup: archive contains unsafe file paths.' );
            }
        }

        $zip->extractTo($extract_dir);
        $zip->close();
        
        // Read manifest
        $manifest_file = $extract_dir . '/manifest.json';
        if (!file_exists($manifest_file)) {
            $this->delete_directory($extract_dir);
            throw new Exception('Invalid backup: manifest.json not found');
        }
        
        $manifest = json_decode(file_get_contents($manifest_file), true);
        
        if (empty($manifest['backup_id']) || empty($manifest['documents'])) {
            $this->delete_directory($extract_dir);
            throw new Exception('Invalid backup manifest');
        }
        
        // Analyze each document
        $file_manager = new MDSM_File_Manager();
        $metadata_manager = new MDSM_Document_Metadata();
        
        $actions = array(
            'restore' => array(),   // New documents
            'overwrite' => array(), // Existing documents that will be overwritten
            'conflict' => array()   // Documents with issues
        );
        
        foreach ($manifest['documents'] as $file_name => $doc_info) {
            $existing_metadata = $metadata_manager->get_metadata($file_name);
            $file_exists = $file_manager->file_exists('meta', $file_name);
            
            if (empty($existing_metadata['uuid'])) {
                // New document - will be restored
                $actions['restore'][] = array(
                    'filename' => $file_name,
                    'uuid' => $doc_info['uuid'],
                    'checksum' => $doc_info['checksum']
                );
            } else {
                // Existing document - will be overwritten
                $actions['overwrite'][] = array(
                    'filename' => $file_name,
                    'existing_checksum' => $existing_metadata['checksum'],
                    'new_checksum' => $doc_info['checksum']
                );
            }
        }
        
        // Store extracted backup info for later use
        $backup_id = $manifest['backup_id'];
        set_transient('mdsm_restore_data_' . $backup_id, array(
            'extract_dir' => $extract_dir,
            'manifest' => $manifest
        ), HOUR_IN_SECONDS);
        
        return array(
            'backup_info' => array(
                'backup_id' => $backup_id,
                'created_at' => $manifest['created_at'],
                'document_count' => $manifest['document_count'],
                'plugin_version' => $manifest['plugin_version'] ?? 'unknown'
            ),
            'actions' => $actions
        );
    }
    
    /**
     * AJAX: Execute restore
     */
    public function ajax_execute_restore() {
        check_ajax_referer('mdsm_execute_restore', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        $backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';
        
        if (empty($backup_id)) {
            wp_send_json_error(array('message' => 'Invalid backup ID'));
        }
        
        try {
            $result = $this->execute_restore($backup_id);
            wp_send_json_success($result);
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Execute restore operation
     */
    private function execute_restore($backup_id) {
        // Get restore data from transient
        $restore_data = get_transient('mdsm_restore_data_' . $backup_id);
        
        if (empty($restore_data)) {
            throw new Exception('Restore session expired. Please re-upload the backup file.');
        }
        
        $extract_dir = $restore_data['extract_dir'];
        $manifest = $restore_data['manifest'];
        
        if (!file_exists($extract_dir)) {
            throw new Exception('Backup files not found');
        }
        
        $file_manager = new MDSM_File_Manager();
        $metadata_manager = new MDSM_Document_Metadata();
        
        $restored_count = 0;
        $overwritten_count = 0;
        $failed_count = 0;
        
        foreach ($manifest['documents'] as $file_name => $doc_info) {
            try {
                // Read metadata and content from backup
                $metadata_file = $extract_dir . '/documents/' . $file_name . '.meta.json';
                $content_file = $extract_dir . '/documents/' . $file_name;
                
                if (!file_exists($metadata_file) || !file_exists($content_file)) {
                    $failed_count++;
                    continue;
                }
                
                $metadata = json_decode(file_get_contents($metadata_file), true);
                $content = file_get_contents($content_file);
                
                // Check if document exists
                $existing_metadata = $metadata_manager->get_metadata($file_name);
                $is_overwrite = !empty($existing_metadata['uuid']);
                
                // Restore file content
                $result = $file_manager->save_file('meta', $file_name, $content);
                
                if (!$result['success']) {
                    $failed_count++;
                    continue;
                }
                
                // Restore metadata (overwrite with backup metadata, preserving UUIDs)
                $option_name = 'mdsm_doc_meta_' . sanitize_key(str_replace(array('.', '/'), '_', $file_name));
                update_option($option_name, $metadata, false);
                
                if ($is_overwrite) {
                    $overwritten_count++;
                } else {
                    $restored_count++;
                }
                
            } catch (Exception $e) {
                $failed_count++;
            }
        }
        
        // Clean up
        $this->delete_directory($extract_dir);
        delete_transient('mdsm_restore_data_' . $backup_id);
        
        return array(
            'restored_count' => $restored_count,
            'overwritten_count' => $overwritten_count,
            'failed_count' => $failed_count
        );
    }
    
    /**
     * AJAX: Verify checksums
     */
    public function ajax_verify_checksums() {
        check_ajax_referer('mdsm_verify_metadata', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }
        
        try {
            $results = $this->verify_all_checksums();
            wp_send_json_success($results);
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }
    
    /**
     * Verify all document checksums
     */
    private function verify_all_checksums() {
        $file_manager = new MDSM_File_Manager();
        $metadata_manager = new MDSM_Document_Metadata();
        
        $meta_files = mdsm_get_meta_files();
        $custom_files = mdsm_get_custom_markdown_files();
        
        $results = array();
        $verified = 0;
        $mismatch = 0;
        $missing = 0;
        
        // Check meta files
        foreach ($meta_files as $category => $files) {
            foreach ($files as $file_name => $description) {
                $metadata = $metadata_manager->get_metadata($file_name);
                
                if (empty($metadata['uuid'])) {
                    continue; // Skip files without metadata
                }
                
                if (!$file_manager->file_exists('meta', $file_name)) {
                    $missing++;
                    $results[] = array(
                        'filename' => $file_name,
                        'status' => 'missing',
                        'stored_checksum' => $metadata['checksum']
                    );
                    continue;
                }
                
                // Compute current checksum using the algorithm recorded in stored metadata
                $content = $file_manager->read_file('meta', $file_name);
                $stored_unpacked = MDSM_Hash_Helper::unpack($metadata['checksum']);
                $computed = MDSM_Hash_Helper::compute($content, $stored_unpacked['algorithm']);
                $current_checksum = MDSM_Hash_Helper::pack($computed['hash'], $computed['algorithm']);
                
                if ($current_checksum === $metadata['checksum']) {
                    $verified++;
                    $results[] = array(
                        'filename' => $file_name,
                        'status' => 'verified',
                        'stored_checksum' => $metadata['checksum']
                    );
                } else {
                    $mismatch++;
                    $results[] = array(
                        'filename' => $file_name,
                        'status' => 'mismatch',
                        'stored_checksum' => $metadata['checksum'],
                        'current_checksum' => $current_checksum
                    );
                }
            }
        }
        
        // Check custom files
        foreach ($custom_files as $file_name => $description) {
            $metadata = $metadata_manager->get_metadata($file_name);
            
            if (empty($metadata['uuid'])) {
                continue;
            }
            
            if (!$file_manager->file_exists('meta', $file_name)) {
                $missing++;
                $results[] = array(
                    'filename' => $file_name,
                    'status' => 'missing',
                    'stored_checksum' => $metadata['checksum']
                );
                continue;
            }
            
            $content = $file_manager->read_file('meta', $file_name);
            $stored_unpacked = MDSM_Hash_Helper::unpack($metadata['checksum']);
            $computed = MDSM_Hash_Helper::compute($content, $stored_unpacked['algorithm']);
            $current_checksum = MDSM_Hash_Helper::pack($computed['hash'], $computed['algorithm']);
            
            if ($current_checksum === $metadata['checksum']) {
                $verified++;
                $results[] = array(
                    'filename' => $file_name,
                    'status' => 'verified',
                    'stored_checksum' => $metadata['checksum']
                );
            } else {
                $mismatch++;
                $results[] = array(
                    'filename' => $file_name,
                    'status' => 'mismatch',
                    'stored_checksum' => $metadata['checksum'],
                    'current_checksum' => $current_checksum
                );
            }
        }
        
        return array(
            'verified' => $verified,
            'mismatch' => $mismatch,
            'missing' => $missing,
            'results' => $results
        );
    }
    
    /**
     * AJAX: Save uninstall cleanup settings
     * 
     * COMPLIANCE-CRITICAL: This handler processes the opt-in metadata cleanup preference.
     * It requires explicit administrator permission and proper nonce verification.
     */
    public function ajax_save_uninstall_cleanup() {
        // Verify nonce
        check_ajax_referer('mdsm_uninstall_cleanup_settings', 'nonce');
        
        // Check permissions - admin only
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array(
                'message' => 'Insufficient permissions. Only administrators can modify cleanup settings.'
            ));
        }
        
        // Get cleanup preference (sanitize as boolean)
        $cleanup_enabled = isset( $_POST['cleanup_enabled'] ) && sanitize_text_field( wp_unslash( $_POST['cleanup_enabled'] ) ) === '1';
        
        // Save the opt-in preference
        $result = update_option('mdsm_uninstall_cleanup_enabled', $cleanup_enabled);
        
        if ($result || get_option('mdsm_uninstall_cleanup_enabled') == $cleanup_enabled) {
            // Log the change for audit trail
            $user = wp_get_current_user();
            $action = $cleanup_enabled ? 'ENABLED' : 'DISABLED';
            $log_message = sprintf(
                '[ArchivioMD] Metadata cleanup on uninstall %s by user %s (ID: %d) at %s UTC',
                $action,
                $user->user_login,
                $user->ID,
                gmdate('Y-m-d H:i:s')
            );
            error_log($log_message);
            
            // Prepare response message
            if ($cleanup_enabled) {
                $message = 'Metadata cleanup ENABLED. All ArchivioMD database options will be deleted when the plugin is uninstalled.';
            } else {
                $message = 'Metadata cleanup DISABLED. All metadata will be preserved on uninstall (default behavior).';
            }
            
            wp_send_json_success(array(
                'message' => $message,
                'cleanup_enabled' => $cleanup_enabled
            ));
        } else {
            wp_send_json_error(array(
                'message' => 'Failed to save cleanup settings. Please try again.'
            ));
        }
    }

	// ── Compliance JSON Export ────────────────────────────────────────────────

	/**
	 * AJAX: Generate a structured compliance JSON export and return a signed
	 * download URL.  All data is assembled server-side and written to a temp
	 * file; the browser then follows the download URL to retrieve it.
	 */
	public function ajax_export_compliance_json() {
		check_ajax_referer( 'mdsm_export_compliance_json', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'archiviomd' ) ) );
		}

		try {
			$json_data = $this->generate_compliance_json();

			$upload_dir = wp_upload_dir();
			$temp_dir   = $upload_dir['basedir'] . '/archivio-md-temp';

			if ( ! file_exists( $temp_dir ) ) {
				wp_mkdir_p( $temp_dir );
			}

			$timestamp = gmdate( 'Y-m-d_H-i-s' );
			$filename  = 'archiviomd-compliance-export-' . $timestamp . '.json';
			$filepath  = $temp_dir . '/' . $filename;

			file_put_contents( $filepath, $json_data );

			// Sign the export and write a sidecar .sig.json file.
			$sig_result = $this->sign_export_file( $filepath, $filename, 'compliance_json' );

			$download_nonce = wp_create_nonce( 'mdsm_download_compliance_json_' . $filename );
			$download_url   = admin_url(
				'admin-ajax.php?action=mdsm_download_compliance_json&file='
				. urlencode( $filename )
				. '&nonce=' . $download_nonce
			);

			$response = array(
				'download_url' => $download_url,
				'filename'     => $filename,
			);

			if ( $sig_result ) {
				$sig_filename             = basename( $sig_result );
				$sig_nonce                = wp_create_nonce( 'mdsm_download_export_sig_' . $sig_filename );
				$response['sig_url']      = admin_url( 'admin-ajax.php?action=mdsm_download_export_sig&file=' . urlencode( $sig_filename ) . '&nonce=' . $sig_nonce );
				$response['sig_filename'] = $sig_filename;
			}

			wp_send_json_success( $response );

		} catch ( Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * AJAX: Serve the pre-generated compliance JSON temp file and delete it
	 * afterwards.  Uses the same signed-nonce pattern as ajax_download_csv().
	 */
	public function ajax_download_compliance_json() {
		$filename = isset( $_GET['file'] ) ? sanitize_file_name( wp_unslash( $_GET['file'] ) ) : '';
		$nonce    = isset( $_GET['nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['nonce'] ) ) : '';

		if ( empty( $filename ) || ! wp_verify_nonce( $nonce, 'mdsm_download_compliance_json_' . $filename ) ) {
			wp_die( esc_html__( 'Invalid request.', 'archiviomd' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'archiviomd' ) );
		}

		$upload_dir = wp_upload_dir();
		$temp_dir   = $upload_dir['basedir'] . '/archivio-md-temp';
		$filepath   = $temp_dir . '/' . $filename;

		if ( ! self::is_path_confined( $filepath, $temp_dir ) ) {
			wp_die( esc_html__( 'Invalid file path.', 'archiviomd' ) );
		}

		if ( ! file_exists( $filepath ) ) {
			wp_die( esc_html__( 'Export file not found. Please generate a new export.', 'archiviomd' ) );
		}

		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . filesize( $filepath ) );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		readfile( $filepath ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@unlink( $filepath );
		exit;
	}

	/**
	 * Build the full compliance JSON string.
	 *
	 * Structure:
	 *   export_meta   – generation info, plugin version, site URL
	 *   posts[]       – each published post that has an _archivio_post_hash,
	 *                   with hash_history[] from archivio_post_audit and
	 *                   anchor_log[]  from archivio_anchor_log
	 *   documents[]   – each managed Markdown document with its changelog[]
	 *                   and anchor_log[]
	 *
	 * Posts are processed in batches of 50 to avoid loading thousands of
	 * WP_Post objects into memory at once.
	 *
	 * @return string JSON-encoded string (UTF-8, pretty-printed).
	 */
	private function generate_compliance_json() {
		global $wpdb;

		// ── Export meta ──────────────────────────────────────────────────────
		$export = array(
			'export_meta' => array(
				'generated_at'   => gmdate( 'Y-m-d\TH:i:s\Z' ),
				'site_url'       => get_site_url(),
				'plugin_version' => MDSM_VERSION,
				'export_version' => '1',
			),
			'posts'       => array(),
			'documents'   => array(),
		);

		$audit_table  = $wpdb->prefix . 'archivio_post_audit';
		$anchor_table = MDSM_Anchor_Log::get_table_name();
		$upload_dir   = wp_upload_dir();

		// ── Posts — batch 50 at a time ───────────────────────────────────────
		$offset     = 0;
		$batch_size = 50;

		do {
			$post_ids = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT DISTINCT post_id FROM {$wpdb->postmeta}
					 WHERE meta_key = '_archivio_post_hash'
					 ORDER BY post_id ASC
					 LIMIT %d OFFSET %d",
					$batch_size,
					$offset
				)
			);

			foreach ( (array) $post_ids as $post_id ) {
				$post_id = (int) $post_id;
				$post    = get_post( $post_id );

				if ( ! $post ) {
					continue;
				}

				$stored_packed = get_post_meta( $post_id, '_archivio_post_hash', true );
				$unpacked      = MDSM_Hash_Helper::unpack( $stored_packed );

				// Current hash.
				$current_hash = array(
					'algorithm' => MDSM_Hash_Helper::algorithm_label( $unpacked['algorithm'] ),
					'mode'      => MDSM_Hash_Helper::mode_label( $unpacked['mode'] ),
					'value'     => $unpacked['hash'],
				);

				// Hash history from audit table.
				$audit_rows = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT id, event_type, result, timestamp, author_id, hash, algorithm, mode
						 FROM {$audit_table}
						 WHERE post_id = %d
						 ORDER BY timestamp ASC",
						$post_id
					),
					ARRAY_A
				);

				$hash_history = array();
				foreach ( (array) $audit_rows as $row ) {
					$row_unpacked = MDSM_Hash_Helper::unpack( $row['hash'] );
					$algo         = ! empty( $row['algorithm'] ) ? $row['algorithm'] : $row_unpacked['algorithm'];
					$mode         = ! empty( $row['mode'] )      ? $row['mode']      : $row_unpacked['mode'];

					$hash_history[] = array(
						'audit_id'   => (int) $row['id'],
						'event_type' => $row['event_type'],
						'result'     => $row['result'],
						'timestamp'  => $row['timestamp'],
						'author_id'  => (int) $row['author_id'],
						'algorithm'  => MDSM_Hash_Helper::algorithm_label( $algo ),
						'mode'       => MDSM_Hash_Helper::mode_label( $mode ),
						'hash'       => $row_unpacked['hash'],
					);
				}

				// Anchor log entries for this post.
				$anchor_rows = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT * FROM {$anchor_table}
						 WHERE document_id = %s
						 ORDER BY created_at ASC",
						'post-' . $post_id
					),
					ARRAY_A
				);

				$anchor_log = $this->build_anchor_log_entries( $anchor_rows, $upload_dir );

				$export['posts'][] = array(
					'post_id'      => $post_id,
					'title'        => $post->post_title,
					'url'          => get_permalink( $post_id ),
					'post_type'    => $post->post_type,
					'post_status'  => $post->post_status,
					'current_hash' => $current_hash,
					'hash_history' => $hash_history,
					'anchor_log'   => $anchor_log,
					'signatures'   => $this->build_post_signature_block( $post_id ),
				);
			}

			$offset += $batch_size;

		} while ( count( $post_ids ) === $batch_size );

		// ── Documents ────────────────────────────────────────────────────────
		$file_manager     = new MDSM_File_Manager();
		$metadata_manager = new MDSM_Document_Metadata();
		$meta_files       = mdsm_get_meta_files();
		$custom_files     = mdsm_get_custom_markdown_files();

		// Merge both file sets into a flat list for uniform processing.
		$all_files = array();
		foreach ( $meta_files as $files ) {
			foreach ( $files as $file_name => $description ) {
				$all_files[ $file_name ] = $description;
			}
		}
		foreach ( $custom_files as $file_name => $description ) {
			$all_files[ $file_name ] = $description;
		}

		foreach ( $all_files as $file_name => $description ) {
			if ( ! $file_manager->file_exists( 'meta', $file_name ) ) {
				continue;
			}

			$metadata = $metadata_manager->get_metadata( $file_name );

			if ( empty( $metadata['uuid'] ) ) {
				continue;
			}

			// Anchor log entries keyed by UUID.
			$anchor_rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$anchor_table}
					 WHERE document_id = %s
					 ORDER BY created_at ASC",
					$metadata['uuid']
				),
				ARRAY_A
			);

			$anchor_log = $this->build_anchor_log_entries( $anchor_rows, $upload_dir );

			// Normalise changelog entries.
			$changelog = array();
			foreach ( (array) $metadata['changelog'] as $entry ) {
				$cl_unpacked = MDSM_Hash_Helper::unpack( $entry['checksum'] ?? '' );
				$changelog[] = array(
					'timestamp' => $entry['timestamp'] ?? '',
					'action'    => $entry['action'] ?? '',
					'user_id'   => (int) ( $entry['user_id'] ?? 0 ),
					'algorithm' => MDSM_Hash_Helper::algorithm_label( $entry['algorithm'] ?? $cl_unpacked['algorithm'] ),
					'mode'      => MDSM_Hash_Helper::mode_label( $entry['mode'] ?? $cl_unpacked['mode'] ),
					'checksum'  => $cl_unpacked['hash'] ?? $entry['checksum'],
				);
			}

			$export['documents'][] = array(
				'uuid'             => $metadata['uuid'],
				'filename'         => $file_name,
				'description'      => (string) $description,
				'last_modified'    => $metadata['modified_at'] ?? '',
				'current_checksum' => $metadata['checksum'] ?? '',
				'changelog'        => $changelog,
				'anchor_log'       => $anchor_log,
			);
		}

		// Pretty-print with JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE.
		$flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

		return wp_json_encode( $export, $flags );
	}

	/**
	 * Convert raw anchor log DB rows into the normalised structure used in
	 * both post and document entries.  For RFC 3161 entries, reads the
	 * sidecar .manifest.json from the filesystem if it exists and inlines it.
	 *
	 * @param array[] $rows       Rows from ARRAY_A wpdb query.
	 * @param array   $upload_dir wp_upload_dir() result.
	 * @return array[]
	 */
	private function build_anchor_log_entries( array $rows, array $upload_dir ) {
		$entries = array();

		foreach ( $rows as $row ) {
			$entry = array(
				'log_id'         => (int) $row['id'],
				'status'         => $row['status'],
				'provider'       => $row['provider'],
				'anchored_at'    => $row['created_at'] . ' UTC',
				'hash_algorithm' => strtoupper( $row['hash_algorithm'] ),
				'integrity_mode' => $row['integrity_mode'],
				'hash_value'     => $row['hash_value'],
				'attempt_number' => (int) $row['attempt_number'],
				'job_id'         => $row['job_id'],
				'anchor_url'     => $row['anchor_url'],
				'http_status'    => (int) $row['http_status'],
				'error_message'  => $row['error_message'],
			);

			// For RFC 3161 entries, inline the manifest JSON sidecar when available.
			// The TSR URL is the public URL; derive the filesystem path from it.
			if ( 'rfc3161' === $row['provider'] && ! empty( $row['anchor_url'] ) ) {
				$tsr_url  = $row['anchor_url'];
				$base_url = trailingslashit( $upload_dir['baseurl'] );
				$base_dir = trailingslashit( $upload_dir['basedir'] );

				if ( strpos( $tsr_url, $base_url ) === 0 ) {
					$relative      = substr( $tsr_url, strlen( $base_url ) );
					$tsr_fs_path   = $base_dir . $relative;
					$manifest_path = preg_replace( '/\.tsr$/', '.manifest.json', $tsr_fs_path );

					if ( $manifest_path && file_exists( $manifest_path ) ) {
						$raw_manifest = file_get_contents( $manifest_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
						$manifest     = json_decode( $raw_manifest, true );
						if ( is_array( $manifest ) ) {
							$entry['tsr_manifest'] = $manifest;
						}
					}
				}
			}

		$entries[] = $entry;
		}

		return $entries;
	}

	// ── Export Signing ───────────────────────────────────────────────────────

	/**
	 * Build the signatures block for a single post in the compliance JSON export.
	 *
	 * Returns a structured array covering Ed25519, SLH-DSA, and ECDSA P-256 — whichever are
	 * configured.  Each entry records what is stored in post meta so the export
	 * is a self-contained evidence package: the signature hex, algorithm, key
	 * fingerprint, public key URL, and the DSSE envelope if present.
	 *
	 * @param  int $post_id
	 * @return array
	 */
	private function build_post_signature_block( int $post_id ): array {
		$block = array();

		// ── Ed25519 ──────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_Ed25519_Signing' ) ) {
			$sig_hex   = get_post_meta( $post_id, '_mdsm_ed25519_sig',       true );
			$signed_at = get_post_meta( $post_id, '_mdsm_ed25519_signed_at', true );
			$dsse_raw  = get_post_meta( $post_id, MDSM_Ed25519_Signing::DSSE_META_KEY, true );

			if ( $sig_hex ) {
				$ed_entry = array(
					'algorithm'      => 'Ed25519',
					'standard'       => 'RFC 8032',
					'signature'      => $sig_hex,
					'signed_at'      => $signed_at ? gmdate( 'Y-m-d\TH:i:s\Z', (int) $signed_at ) : null,
					'public_key_url' => home_url( '/.well-known/ed25519-pubkey.txt' ),
					'key_fingerprint'=> MDSM_Ed25519_Signing::public_key_fingerprint() ?: null,
				);

				if ( $dsse_raw ) {
					$dsse_arr = json_decode( $dsse_raw, true );
					// Only include the Ed25519 signature entry from a potentially
					// multi-sig envelope — avoid duplicating the SLH-DSA entry here.
					if ( is_array( $dsse_arr ) ) {
						$ed_sigs = array_values( array_filter(
							(array) ( $dsse_arr['signatures'] ?? array() ),
							static fn( $s ) => ! isset( $s['alg'] ) || $s['alg'] === 'ed25519'
						) );
						$ed_entry['dsse_envelope'] = array(
							'payload'     => $dsse_arr['payload']     ?? null,
							'payloadType' => $dsse_arr['payloadType'] ?? null,
							'signatures'  => $ed_sigs,
						);
					}
				}

				$block['ed25519'] = $ed_entry;
			} else {
				$block['ed25519'] = array( 'status' => 'unsigned' );
			}
		}

		// ── SLH-DSA ──────────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_SLHDSA_Signing' ) ) {
			$slh_sig   = get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_SIG,       true );
			$slh_at    = get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_SIGNED_AT,  true );
			$slh_param = get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_PARAM,      true );
			$slh_dsse  = get_post_meta( $post_id, MDSM_SLHDSA_Signing::META_DSSE,       true );

			if ( $slh_sig ) {
				$slh_entry = array(
					'algorithm'      => strtoupper( $slh_param ?: MDSM_SLHDSA_Signing::get_param() ),
					'standard'       => 'NIST FIPS 205',
					'signature'      => $slh_sig,
					'signed_at'      => $slh_at ? gmdate( 'Y-m-d\TH:i:s\Z', (int) $slh_at ) : null,
					'public_key_url' => home_url( '/.well-known/slhdsa-pubkey.txt' ),
					'key_fingerprint'=> MDSM_SLHDSA_Signing::public_key_fingerprint() ?: null,
				);

				if ( $slh_dsse ) {
					$slh_dsse_arr = json_decode( $slh_dsse, true );
					if ( is_array( $slh_dsse_arr ) ) {
						$slh_entry['dsse_envelope'] = $slh_dsse_arr;
					}
				}

				$block['slh_dsa'] = $slh_entry;
			} else {
				$block['slh_dsa'] = array( 'status' => 'unsigned' );
			}
		}

		// ── ECDSA P-256 ───────────────────────────────────────────────────────
		if ( class_exists( 'MDSM_ECDSA_Signing' ) ) {
			$ecdsa_sig  = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_SIG,       true );
			$ecdsa_at   = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_SIGNED_AT,  true );
			$ecdsa_dsse = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_DSSE,       true );
			$ecdsa_cert = get_post_meta( $post_id, MDSM_ECDSA_Signing::META_CERT,       true );

			if ( $ecdsa_sig ) {
				$cert_fingerprint = null;
				if ( $ecdsa_cert ) {
					$b64              = preg_replace( '/-----[^-]+-----|\s/', '', $ecdsa_cert );
					$der              = base64_decode( $b64 ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
					$cert_fingerprint = hash( 'sha256', $der );
				}

				$ecdsa_entry = array(
					'algorithm'        => 'ecdsa-p256-sha256',
					'standard'         => 'NIST P-256 / secp256r1, X.509',
					'signature'        => $ecdsa_sig,
					'signed_at'        => $ecdsa_at ? gmdate( 'Y-m-d\TH:i:s\Z', (int) $ecdsa_at ) : null,
					'certificate_url'  => home_url( '/.well-known/ecdsa-cert.pem' ),
					'cert_fingerprint' => $cert_fingerprint,
					'mode'             => 'enterprise_compliance',
				);

				if ( $ecdsa_dsse ) {
					$ecdsa_dsse_arr = json_decode( $ecdsa_dsse, true );
					if ( is_array( $ecdsa_dsse_arr ) ) {
						$display = $ecdsa_dsse_arr;
						if ( isset( $display['signatures'] ) ) {
							foreach ( $display['signatures'] as &$s ) { unset( $s['x5c'] ); }
							unset( $s );
						}
						$ecdsa_entry['dsse_envelope'] = $display;
					}
				}

				$block['ecdsa_p256'] = $ecdsa_entry;
			} else {
				$block['ecdsa_p256'] = array( 'status' => 'unsigned' );
			}
		}

		// ── RSA Compatibility Signing ─────────────────────────────────────────
		if ( class_exists( 'MDSM_RSA_Signing' ) ) {
			$rsa_sig    = get_post_meta( $post_id, MDSM_RSA_Signing::META_SIG,       true );
			$rsa_at     = get_post_meta( $post_id, MDSM_RSA_Signing::META_SIGNED_AT,  true );
			$rsa_scheme = get_post_meta( $post_id, MDSM_RSA_Signing::META_SCHEME,     true );
			$rsa_pubkey = get_post_meta( $post_id, MDSM_RSA_Signing::META_PUBKEY,     true );

			if ( $rsa_sig ) {
				$rsa_entry = array(
					'algorithm'      => strtoupper( $rsa_scheme ?: MDSM_RSA_Signing::get_scheme() ),
					'standard'       => 'PKCS#1 / RSASSA-PSS, SHA-256',
					'signature'      => $rsa_sig,
					'signed_at'      => $rsa_at ? gmdate( 'Y-m-d\TH:i:s\Z', (int) $rsa_at ) : null,
					'public_key_url' => home_url( '/.well-known/rsa-pubkey.pem' ),
					'mode'           => 'legacy_compatibility',
				);
				if ( $rsa_pubkey ) {
					$rsa_entry['pubkey_fingerprint'] = hash( 'sha256', hex2bin( $rsa_pubkey ) );
				}
				$block['rsa'] = $rsa_entry;
			} else {
				$block['rsa'] = array( 'status' => 'unsigned' );
			}
		}

		// ── CMS / PKCS#7 Detached Signature ──────────────────────────────────
		if ( class_exists( 'MDSM_CMS_Signing' ) ) {
			$cms_sig    = get_post_meta( $post_id, MDSM_CMS_Signing::META_SIG,        true );
			$cms_at     = get_post_meta( $post_id, MDSM_CMS_Signing::META_SIGNED_AT,  true );
			$cms_source = get_post_meta( $post_id, MDSM_CMS_Signing::META_KEY_SOURCE, true );

			if ( $cms_sig ) {
				$block['cms_pkcs7'] = array(
					'algorithm'   => 'CMS SignedData (RFC 5652), DER-encoded',
					'standard'    => 'RFC 5652 / PKCS#7',
					'signature'   => $cms_sig,
					'signed_at'   => $cms_at ? gmdate( 'Y-m-d\TH:i:s\Z', (int) $cms_at ) : null,
					'key_source'  => $cms_source ?: null,
					'mode'        => 'enterprise_compatibility',
				);
			} else {
				$block['cms_pkcs7'] = array( 'status' => 'unsigned' );
			}
		}

		// ── JSON-LD / W3C Data Integrity ──────────────────────────────────────
		if ( class_exists( 'MDSM_JSONLD_Signing' ) ) {
			$proof_json = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_PROOF,     true );
			$jsonld_at  = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_SIGNED_AT, true );
			$suite      = get_post_meta( $post_id, MDSM_JSONLD_Signing::META_SUITE,     true );

			if ( $proof_json ) {
				$proof_arr = json_decode( $proof_json, true );
				$block['jsonld_data_integrity'] = array(
					'cryptosuite'  => $suite ?: 'unknown',
					'standard'     => 'W3C Data Integrity 1.0',
					'proof'        => is_array( $proof_arr ) ? $proof_arr : null,
					'signed_at'    => $jsonld_at ? gmdate( 'Y-m-d\TH:i:s\Z', (int) $jsonld_at ) : null,
					'did_url'      => home_url( '/.well-known/did.json' ),
					'spec_url'     => 'https://www.w3.org/TR/vc-data-integrity/',
				);
			} else {
				$block['jsonld_data_integrity'] = array( 'status' => 'unsigned' );
			}
		}

		return $block;
	}


	/**
	 * Generate a signature envelope for an export file and write it as a
	 * sidecar `{filename}.sig.json` in the same temp directory.
	 *
	 * The envelope always contains a SHA-256 integrity hash of the file.
	 * If Ed25519 signing is configured and enabled, a detached signature is
	 * added over a deterministic canonical message that binds the hash to
	 * the export type, filename, timestamp, and site URL — preventing the
	 * signature from being reused against a different file or context.
	 *
	 * Canonical signing message format (newline-separated, UTF-8):
	 *   archiviomd-export-v1
	 *   {export_type}
	 *   {filename}
	 *   {generated_at}    ← ISO 8601 UTC
	 *   {site_url}
	 *   {sha256_hex}      ← SHA-256 of the raw file bytes
	 *
	 * @param  string $filepath    Absolute path to the file on disk.
	 * @param  string $filename    Base filename (used in envelope + canonical message).
	 * @param  string $export_type Short slug: 'metadata_csv', 'compliance_json', or 'backup_zip'.
	 * @return string|false        Absolute path of the written .sig.json, or false on failure.
	 */
	private function sign_export_file( string $filepath, string $filename, string $export_type ) {
		if ( ! file_exists( $filepath ) ) {
			return false;
		}

		$file_bytes   = file_get_contents( $filepath ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$sha256       = hash( 'sha256', $file_bytes );
		$generated_at = gmdate( 'Y-m-d\TH:i:s\Z' );
		$site_url     = get_site_url();
		$current_user = wp_get_current_user();

		// ── Build canonical signing message ─────────────────────────────────
		$canonical = implode( "\n", array(
			'archiviomd-export-v1',
			$export_type,
			$filename,
			$generated_at,
			$site_url,
			$sha256,
		) );

		// ── Assemble the envelope ────────────────────────────────────────────
		$envelope = array(
			'archiviomd_export_sig' => '1',
			'export_type'           => $export_type,
			'filename'              => $filename,
			'generated_at'          => $generated_at,
			'site_url'              => $site_url,
			'plugin_version'        => MDSM_VERSION,
			'generated_by_user_id'  => $current_user instanceof WP_User ? $current_user->ID : 0,
			'file_integrity'        => array(
				'algorithm' => 'sha256',
				'value'     => $sha256,
			),
		);

		// ── Ed25519 signing (optional, degrades gracefully) ──────────────────
		$signing_available = (
			class_exists( 'MDSM_Ed25519_Signing' )
			&& MDSM_Ed25519_Signing::is_sodium_available()
			&& MDSM_Ed25519_Signing::is_private_key_defined()
		);

		if ( $signing_available ) {
			$sig = MDSM_Ed25519_Signing::sign( $canonical );

			if ( ! is_wp_error( $sig ) ) {
				$envelope['ed25519'] = array(
					'signature'      => $sig,
					'signed_at'      => $generated_at,
					'canonical_msg'  => $canonical,
					'public_key_url' => trailingslashit( $site_url ) . '.well-known/ed25519-pubkey.txt',
				);
				$envelope['signing_status'] = 'signed';
			} else {
				$envelope['signing_status']        = 'error';
				$envelope['signing_status_detail'] = $sig->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_Ed25519_Signing' ) && MDSM_Ed25519_Signing::is_mode_enabled() ) {
			// Mode is on but key/sodium is missing — surface it clearly.
			$envelope['signing_status']        = 'unavailable';
			$envelope['signing_status_detail'] = 'Ed25519 mode is enabled but ext-sodium or the private key constant is missing.';
		} else {
			// Ed25519 not configured — integrity hash only (may be upgraded by SLH-DSA below).
			$envelope['signing_status']        = 'unsigned';
			$envelope['signing_status_detail'] = 'Ed25519 signing is not configured.';
		}

		// ── SLH-DSA signing (optional, degrades gracefully) ──────────────────
		// Runs independently of Ed25519.  If both are active the receipt carries
		// two independent quantum-classical signature blocks over the same canonical
		// message — verifiers can check either or both.
		$slhdsa_available = (
			class_exists( 'MDSM_SLHDSA_Signing' )
			&& MDSM_SLHDSA_Signing::is_mode_enabled()
			&& MDSM_SLHDSA_Signing::is_private_key_defined()
		);

		if ( $slhdsa_available ) {
			$slh_sig = MDSM_SLHDSA_Signing::sign( $canonical );

			if ( ! is_wp_error( $slh_sig ) ) {
				$envelope['slh_dsa'] = array(
					'signature'      => $slh_sig,
					'param'          => MDSM_SLHDSA_Signing::get_param(),
					'signed_at'      => $generated_at,
					'canonical_msg'  => $canonical,
					'public_key_url' => trailingslashit( $site_url ) . '.well-known/slhdsa-pubkey.txt',
					'standard'       => 'NIST FIPS 205',
				);
				// Upgrade signing_status to reflect that at least one sig exists.
				if ( $envelope['signing_status'] === 'unsigned' ) {
					$envelope['signing_status']        = 'signed';
					$envelope['signing_status_detail'] = 'Signed with SLH-DSA only (Ed25519 not configured).';
				} else {
					// Both algorithms signed — record it.
					$envelope['signing_status'] = 'signed';
					unset( $envelope['signing_status_detail'] );
				}
			} else {
				$envelope['slh_dsa_error'] = $slh_sig->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_SLHDSA_Signing' ) && MDSM_SLHDSA_Signing::is_mode_enabled() ) {
			$envelope['slh_dsa_status']        = 'unavailable';
			$envelope['slh_dsa_status_detail'] = 'SLH-DSA mode is enabled but the private key constant is missing.';
		}

		// ── ECDSA P-256 signing (optional, degrades gracefully) ───────────────
		// Enterprise / Compliance Mode only. Runs independently of Ed25519 and
		// SLH-DSA. Certificate is validated (including expiry + CA chain) before
		// signing. Nonce generation fully delegated to OpenSSL.
		$ecdsa_available = (
			class_exists( 'MDSM_ECDSA_Signing' )
			&& MDSM_ECDSA_Signing::is_mode_enabled()
			&& MDSM_ECDSA_Signing::is_openssl_available()
		);

		if ( $ecdsa_available ) {
			$ecdsa_sig = MDSM_ECDSA_Signing::sign( $canonical );

			if ( ! is_wp_error( $ecdsa_sig ) ) {
				$cert_info = MDSM_ECDSA_Signing::certificate_info();
				$envelope['ecdsa_p256'] = array(
					'signature'       => $ecdsa_sig,
					'algorithm'       => 'ecdsa-p256-sha256',
					'signed_at'       => $generated_at,
					'canonical_msg'   => $canonical,
					'certificate_url' => trailingslashit( $site_url ) . '.well-known/ecdsa-cert.pem',
					'cert_fingerprint'=> ( ! is_wp_error( $cert_info ) && isset( $cert_info['fingerprint'] ) ) ? $cert_info['fingerprint'] : null,
					'standard'        => 'NIST P-256 / secp256r1, X.509',
					'mode'            => 'enterprise_compliance',
				);
				if ( $envelope['signing_status'] === 'unsigned' ) {
					$envelope['signing_status']        = 'signed';
					$envelope['signing_status_detail'] = 'Signed with ECDSA P-256 only (Ed25519/SLH-DSA not configured).';
				} else {
					$envelope['signing_status'] = 'signed';
					unset( $envelope['signing_status_detail'] );
				}
			} else {
				$envelope['ecdsa_p256_error'] = $ecdsa_sig->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_ECDSA_Signing' ) && MDSM_ECDSA_Signing::is_mode_enabled() ) {
			$envelope['ecdsa_p256_status']        = 'unavailable';
			$envelope['ecdsa_p256_status_detail'] = 'ECDSA mode is enabled but ext-openssl or the certificate is not configured.';
		}

		// ── RSA compatibility signing (optional, degrades gracefully) ─────────
		$rsa_available = (
			class_exists( 'MDSM_RSA_Signing' )
			&& MDSM_RSA_Signing::is_mode_enabled()
			&& MDSM_RSA_Signing::is_openssl_available()
			&& MDSM_RSA_Signing::is_private_key_defined()
		);

		if ( $rsa_available ) {
			$rsa_sig = MDSM_RSA_Signing::sign( $canonical );

			if ( ! is_wp_error( $rsa_sig ) ) {
				$envelope['rsa'] = array(
					'signature'      => $rsa_sig,
					'scheme'         => MDSM_RSA_Signing::get_scheme(),
					'signed_at'      => $generated_at,
					'canonical_msg'  => $canonical,
					'public_key_url' => trailingslashit( $site_url ) . '.well-known/rsa-pubkey.pem',
					'standard'       => 'PKCS#1 / RSASSA-PSS, SHA-256',
					'mode'           => 'legacy_compatibility',
				);
				if ( $envelope['signing_status'] === 'unsigned' ) {
					$envelope['signing_status']        = 'signed';
					$envelope['signing_status_detail'] = 'Signed with RSA only (Ed25519/SLH-DSA/ECDSA not configured).';
				} else {
					$envelope['signing_status'] = 'signed';
					unset( $envelope['signing_status_detail'] );
				}
			} else {
				$envelope['rsa_error'] = $rsa_sig->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_RSA_Signing' ) && MDSM_RSA_Signing::is_mode_enabled() ) {
			$envelope['rsa_status']        = 'unavailable';
			$envelope['rsa_status_detail'] = 'RSA mode is enabled but ext-openssl or the private key is not configured.';
		}

		// ── CMS / PKCS#7 signing (optional, degrades gracefully) ─────────────
		$cms_available = (
			class_exists( 'MDSM_CMS_Signing' )
			&& MDSM_CMS_Signing::is_mode_enabled()
			&& MDSM_CMS_Signing::is_openssl_available()
			&& MDSM_CMS_Signing::is_key_available()
		);

		if ( $cms_available ) {
			$cms_sig = MDSM_CMS_Signing::sign( $canonical );

			if ( ! is_wp_error( $cms_sig ) ) {
				$envelope['cms_pkcs7'] = array(
					'signature'   => $cms_sig,
					'algorithm'   => 'CMS SignedData (RFC 5652), DER base64',
					'signed_at'   => $generated_at,
					'canonical_msg' => $canonical,
					'key_source'  => MDSM_CMS_Signing::get_key_source(),
					'standard'    => 'RFC 5652 / PKCS#7',
					'mode'        => 'enterprise_compatibility',
				);
				if ( $envelope['signing_status'] === 'unsigned' ) {
					$envelope['signing_status']        = 'signed';
					$envelope['signing_status_detail'] = 'Signed with CMS/PKCS#7 only.';
				} else {
					$envelope['signing_status'] = 'signed';
					unset( $envelope['signing_status_detail'] );
				}
			} else {
				$envelope['cms_pkcs7_error'] = $cms_sig->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_CMS_Signing' ) && MDSM_CMS_Signing::is_mode_enabled() ) {
			$envelope['cms_pkcs7_status']        = 'unavailable';
			$envelope['cms_pkcs7_status_detail'] = 'CMS/PKCS#7 mode is enabled but no compatible key (ECDSA P-256 or RSA) is configured.';
		}

		// ── JSON-LD / W3C Data Integrity signing (optional, degrades gracefully) ─
		$jsonld_available = (
			class_exists( 'MDSM_JSONLD_Signing' )
			&& MDSM_JSONLD_Signing::is_mode_enabled()
			&& MDSM_JSONLD_Signing::is_signer_available()
		);

		if ( $jsonld_available ) {
			$suite       = MDSM_JSONLD_Signing::get_active_suites();
			$active_suite = ! empty( $suite ) ? $suite[0] : MDSM_JSONLD_Signing::SUITE_EDDSA;
			$jsonld_proof = MDSM_JSONLD_Signing::sign( $canonical, $active_suite );

			if ( ! is_wp_error( $jsonld_proof ) ) {
				$envelope['jsonld_data_integrity'] = array(
					'proof'        => $jsonld_proof,
					'cryptosuite'  => $active_suite,
					'signed_at'    => $generated_at,
					'canonical_msg'=> $canonical,
					'did_url'      => trailingslashit( $site_url ) . '.well-known/did.json',
					'standard'     => 'W3C Data Integrity 1.0',
					'spec_url'     => 'https://www.w3.org/TR/vc-data-integrity/',
				);
				if ( $envelope['signing_status'] === 'unsigned' ) {
					$envelope['signing_status']        = 'signed';
					$envelope['signing_status_detail'] = 'Signed with JSON-LD Data Integrity only.';
				} else {
					$envelope['signing_status'] = 'signed';
					unset( $envelope['signing_status_detail'] );
				}
			} else {
				$envelope['jsonld_error'] = $jsonld_proof->get_error_message();
			}
		} elseif ( class_exists( 'MDSM_JSONLD_Signing' ) && MDSM_JSONLD_Signing::is_mode_enabled() ) {
			$envelope['jsonld_status']        = 'unavailable';
			$envelope['jsonld_status_detail'] = 'JSON-LD mode is enabled but no compatible signing algorithm (Ed25519 or ECDSA P-256) is active.';
		}

		// ── Write sidecar ────────────────────────────────────────────────────
		$sig_path = $filepath . '.sig.json';
		$written  = file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$sig_path,
			wp_json_encode( $envelope, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
		);

		return $written !== false ? $sig_path : false;
	}

	/**
	 * AJAX: Serve a pre-generated export signature sidecar (.sig.json) and
	 * delete it afterwards.  Mirrors the pattern of ajax_download_csv().
	 */
	public function ajax_download_export_sig() {
		$filename = isset( $_GET['file'] ) ? sanitize_file_name( wp_unslash( $_GET['file'] ) ) : '';
		$nonce    = isset( $_GET['nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['nonce'] ) ) : '';

		if ( empty( $filename ) || ! wp_verify_nonce( $nonce, 'mdsm_download_export_sig_' . $filename ) ) {
			wp_die( esc_html__( 'Invalid request.', 'archiviomd' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'archiviomd' ) );
		}

		// Enforce .sig.json extension — do not serve arbitrary temp files.
		if ( substr( $filename, -9 ) !== '.sig.json' ) {
			wp_die( esc_html__( 'Invalid file type.', 'archiviomd' ) );
		}

		$upload_dir = wp_upload_dir();
		$temp_dir   = $upload_dir['basedir'] . '/archivio-md-temp';
		$filepath   = $temp_dir . '/' . $filename;

		if ( ! self::is_path_confined( $filepath, $temp_dir ) ) {
			wp_die( esc_html__( 'Invalid file path.', 'archiviomd' ) );
		}

		if ( ! file_exists( $filepath ) ) {
			wp_die( esc_html__( 'Signature file not found. Please regenerate the export.', 'archiviomd' ) );
		}

		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . filesize( $filepath ) );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		readfile( $filepath ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		wp_delete_file( $filepath );
		exit;
	}
}
