<?php
/**
 * File Manager Class
 * 
 * Handles file operations: reading, writing, deleting files
 */

if (!defined('ABSPATH')) {
    exit;
}

class MDSM_File_Manager {
    
    /**
     * Get file path based on type and name
     */
    public function get_file_path($file_type, $file_name) {
        $root_path   = ABSPATH . $file_name;
        $upload_dir  = wp_upload_dir();
        $upload_path = $upload_dir['basedir'] . '/meta-docs/' . $file_name;

        // For meta files: check each candidate location for an existing file first,
        // then fall back to writability order for new files.
        if ($file_type === 'meta') {
            $well_known_path = ABSPATH . '.well-known/meta-docs/' . $file_name;

            // 1. Return wherever the file already exists (read path).
            if (file_exists($well_known_path)) {
                return $well_known_path;
            }
            if (file_exists($root_path)) {
                return $root_path;
            }
            if (file_exists($upload_path)) {
                return $upload_path;
            }

            // 2. File does not exist yet — determine best writable location (write path).
            if ($this->ensure_directory(ABSPATH . '.well-known/meta-docs/')) {
                return $well_known_path;
            }
            if (is_writable(ABSPATH)) {
                return $root_path;
            }
            $this->ensure_directory($upload_dir['basedir'] . '/meta-docs/');
            return $upload_path;
        }

        // For SEO files (robots.txt, llms.txt, etc.): root first, uploads fallback.
        if ($file_type === 'seo') {
            // 1. Return wherever the file already exists (read path).
            if (file_exists($root_path)) {
                return $root_path;
            }
            if (file_exists($upload_path)) {
                return $upload_path;
            }

            // 2. File does not exist yet — determine best writable location (write path).
            if (is_writable(ABSPATH)) {
                return $root_path;
            }
            $this->ensure_directory($upload_dir['basedir'] . '/meta-docs/');
            return $upload_path;
        }

        return false;
    }
    
    /**
     * Get file URL
     */
    public function get_file_url($file_type, $file_name) {
        $file_path = $this->get_file_path($file_type, $file_name);
        
        if (!$file_path || !file_exists($file_path)) {
            return false;
        }
        
        // Always return root-level URL - the plugin will serve it if needed
        return get_site_url() . '/' . $file_name;
    }
    
    /**
     * Get file location label
     */
    public function get_file_location($file_type, $file_name) {
        $file_path = $this->get_file_path($file_type, $file_name);
        
        if (!$file_path) {
            return 'Unknown';
        }
        
        if (strpos($file_path, ABSPATH . '.well-known/meta-docs/') === 0) {
            return '/.well-known/meta-docs/';
        }
        
        $upload_dir = wp_upload_dir();
        if (strpos($file_path, ABSPATH) === 0 && strpos($file_path, $upload_dir['basedir']) === false) {
            return '/site-root/';
        }
        
        if (strpos($file_path, $upload_dir['basedir']) === 0) {
            return trailingslashit( $upload_dir['baseurl'] ) . 'meta-docs/';
        }
        
        return 'Unknown';
    }
    
    /**
     * Read file content
     */
    public function read_file($file_type, $file_name) {
        $file_path = $this->get_file_path($file_type, $file_name);
        
        if (!$file_path || !file_exists($file_path)) {
            return '';
        }
        
        return file_get_contents($file_path);
    }
    
    /**
     * Save file
     */
    public function save_file($file_type, $file_name, $content) {
        // If content is empty, delete the file
        if (trim($content) === '') {
            return $this->delete_file($file_type, $file_name);
        }
        
        $file_path = $this->get_file_path($file_type, $file_name);
        
        if (!$file_path) {
            return array(
                'success' => false,
                'message' => 'Could not determine file path'
            );
        }

        // Confine the destination to expected directories — ABSPATH, .well-known,
        // or wp_upload_dir() basedir. Guards against path traversal in $file_name.
        $upload_dir    = wp_upload_dir();
        $allowed_roots = array(
            realpath( ABSPATH ),
            realpath( $upload_dir['basedir'] ),
        );
        $real_dest_dir = realpath( dirname( $file_path ) );
        $confined = false;
        if ( $real_dest_dir ) {
            foreach ( $allowed_roots as $root ) {
                if ( $root && str_starts_with( $real_dest_dir . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR ) ) {
                    $confined = true;
                    break;
                }
            }
        }
        if ( ! $confined ) {
            return array( 'success' => false, 'message' => 'Destination path is outside allowed directories.' );
        }
        
        // Ensure directory exists
        $dir = dirname($file_path);
        if (!$this->ensure_directory($dir)) {
            return array(
                'success' => false,
                'message' => 'Could not create directory: ' . $dir
            );
        }
        
        // Write file
        $result = file_put_contents($file_path, $content);
        
        if ($result === false) {
            return array(
                'success' => false,
                'message' => 'Could not write to file: ' . $file_path
            );
        }
        
        // Set proper permissions
        @chmod($file_path, 0644);
        
        // Update metadata for meta files (Markdown documents)
        $metadata = null;
        if ($file_type === 'meta') {
            $metadata_manager = new MDSM_Document_Metadata();
            $metadata = $metadata_manager->update_metadata($file_name, $content);
            
            // Check if HMAC was unavailable
            if (is_array($metadata) && isset($metadata['error']) && $metadata['error'] === 'hmac_unavailable') {
                return array(
                    'success' => false,
                    'message' => $metadata['message']
                );
            }
        }
        
        return array(
            'success' => true,
            'message' => 'File saved successfully',
            'url' => $this->get_file_url($file_type, $file_name),
            'location' => $this->get_file_location($file_type, $file_name),
            'exists' => true,
            'metadata' => $metadata
        );
    }
    
    /**
     * Delete file
     */
    public function delete_file($file_type, $file_name) {
        $file_path = $this->get_file_path($file_type, $file_name);
        
        if (!$file_path || !file_exists($file_path)) {
            // Clean up metadata even if file doesn't exist
            if ($file_type === 'meta') {
                $metadata_manager = new MDSM_Document_Metadata();
                $metadata_manager->delete_metadata($file_name);
            }
            
            return array(
                'success' => true,
                'message' => 'File does not exist',
                'exists' => false
            );
        }
        
        $result = @unlink($file_path);
        
        if (!$result) {
            return array(
                'success' => false,
                'message' => 'Could not delete file: ' . $file_path
            );
        }
        
        // Delete metadata for meta files
        if ($file_type === 'meta') {
            $metadata_manager = new MDSM_Document_Metadata();
            $metadata_manager->delete_metadata($file_name);
        }
        
        return array(
            'success' => true,
            'message' => 'File deleted successfully',
            'exists' => false
        );
    }
    
    /**
     * Check if file exists
     */
    public function file_exists($file_type, $file_name) {
        $file_path = $this->get_file_path($file_type, $file_name);
        return $file_path && file_exists($file_path);
    }
    
    /**
     * Get file info
     */
    public function get_file_info($file_type, $file_name) {
        $exists = $this->file_exists($file_type, $file_name);
        
        $info = array(
            'name' => $file_name,
            'exists' => $exists,
            'url' => $exists ? $this->get_file_url($file_type, $file_name) : false,
            'location' => $this->get_file_location($file_type, $file_name),
            'content' => $exists ? $this->read_file($file_type, $file_name) : '',
        );
        
        // Add metadata for meta files
        if ($file_type === 'meta' && $exists) {
            $metadata_manager = new MDSM_Document_Metadata();
            $info['metadata'] = $metadata_manager->get_metadata($file_name);
        }
        
        return $info;
    }
    
    /**
     * Ensure directory exists
     */
    private function ensure_directory($dir) {
        if (file_exists($dir)) {
            return is_writable($dir);
        }
        
        return wp_mkdir_p($dir);
    }
    
    /**
     * Get all existing files count
     */
    public function get_existing_files_count($file_type) {
        $count = 0;
        
        if ($file_type === 'meta') {
            $files = mdsm_get_meta_files();
            foreach ($files as $category => $file_list) {
                foreach ($file_list as $file_name => $description) {
                    if ($this->file_exists($file_type, $file_name)) {
                        $count++;
                    }
                }
            }
        } elseif ($file_type === 'seo') {
            $files = mdsm_get_seo_files();
            foreach ($files as $file_name => $description) {
                if ($this->file_exists($file_type, $file_name)) {
                    $count++;
                }
            }
        }
        
        return $count;
    }
}
