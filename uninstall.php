<?php
/**
 * ArchivioMD Uninstall Handler
 * 
 * COMPLIANCE-CRITICAL: This file handles plugin uninstallation with strict
 * audit-ready safeguards. Metadata deletion is OPT-IN ONLY and requires
 * explicit administrator approval.
 * 
 * DEFAULT BEHAVIOR: Preserve all metadata (audit evidence)
 * OPT-IN BEHAVIOR: Delete only ArchivioMD-owned database options
 * NEVER TOUCHES: Markdown files remain untouched under all circumstances
 */

// Exit if not called by WordPress uninstall process
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Uninstall cleanup process
 * 
 * This function implements a conservative, audit-ready approach:
 * 1. Check if metadata cleanup is explicitly enabled (opt-in)
 * 2. If disabled (default), exit immediately - preserve everything
 * 3. If enabled, delete ONLY ArchivioMD database options
 * 4. NEVER delete or modify Markdown files
 */
function archiviomd_uninstall_cleanup() {
    
    // CRITICAL: Check opt-in flag (default: false = preserve metadata)
    $cleanup_enabled = get_option('mdsm_uninstall_cleanup_enabled', false);
    
    if (!$cleanup_enabled) {
        // DEFAULT BEHAVIOR: Preserve all metadata for audit compliance
        // Exit silently without any deletions
        return;
    }
    
    // OPT-IN BEHAVIOR: User explicitly enabled cleanup
    // Delete only ArchivioMD-owned database options
    
    global $wpdb;
    
    // 1. Delete all document metadata (UUIDs, checksums, changelogs)
    //    Pattern: mdsm_doc_meta_*
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $wpdb->esc_like( 'mdsm_doc_meta_' ) . '%'
        )
    );
    
    // 2. Delete plugin configuration options
    $plugin_options = array(
        'mdsm_auto_update_sitemap',
        'mdsm_sitemap_type',
        'mdsm_custom_markdown_files',
        'mdsm_public_index_enabled',
        'mdsm_public_index_page_id',
        'mdsm_public_documents',
        'mdsm_document_descriptions',
        'mdsm_backup_notice_dismissed',
        'mdsm_permalink_notice_dismissed',
        'mdsm_uninstall_cleanup_enabled', // Delete the opt-in flag itself
        'archivio_post_auto_generate',
        'archivio_post_show_badge',
        'archivio_hash_algorithm',
        'archivio_hmac_mode',
        // Ed25519 signing options.
        'archiviomd_ed25519_enabled',
        'archiviomd_ed25519_dsse_enabled',
        'archiviomd_ed25519_post_types',
        // SLH-DSA signing options.
        'archiviomd_slhdsa_enabled',
        'archiviomd_slhdsa_dsse_enabled',
        'archiviomd_slhdsa_param',
        'archiviomd_slhdsa_post_types',
        // ECDSA signing options.
        'archiviomd_ecdsa_enabled',
        'archiviomd_ecdsa_dsse_enabled',
        'archiviomd_ecdsa_post_types',
        'archiviomd_ecdsa_key_path',
        'archiviomd_ecdsa_cert_path',
        'archiviomd_ecdsa_ca_path',
        // RSA compatibility signing options.
        'archiviomd_rsa_enabled',
        'archiviomd_rsa_scheme',
        'archiviomd_rsa_post_types',
        'archiviomd_rsa_key_path',
        'archiviomd_rsa_cert_path',
        // CMS / PKCS#7 signing options.
        'archiviomd_cms_enabled',
        'archiviomd_cms_post_types',
        // JSON-LD / W3C Data Integrity options.
        'archiviomd_jsonld_enabled',
        'archiviomd_jsonld_post_types',
        // DANE / DNS Key Corroboration options.
        'archiviomd_dane_enabled',
        'archiviomd_dane_tlsa_enabled',
        'archiviomd_dane_rotation_mode',
        'archiviomd_dane_rotation_started_at',
        'archiviomd_dane_cron_notice',
    );
    
    foreach ($plugin_options as $option_name) {
        delete_option($option_name);
    }
    
    // 3. Delete Archivio Post metadata and audit table
    // Delete all post meta created by Archivio Post
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta} 
         WHERE meta_key IN ('_archivio_post_hash', '_archivio_post_algorithm', '_archivio_post_author_id', '_archivio_post_timestamp', '_archivio_post_badge_visible', '_archivio_post_mode')"
    );

    // Delete Ed25519 signing post meta.
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta}
         WHERE meta_key IN ('_mdsm_ed25519_sig', '_mdsm_ed25519_signed_at', '_mdsm_ed25519_dsse')"
    );

    // Delete SLH-DSA signing post meta.
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta}
         WHERE meta_key IN ('_mdsm_slhdsa_sig', '_mdsm_slhdsa_signed_at', '_mdsm_slhdsa_dsse', '_mdsm_slhdsa_param')"
    );

    // Delete ECDSA signing post meta.
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta}
         WHERE meta_key IN ('_mdsm_ecdsa_sig', '_mdsm_ecdsa_cert', '_mdsm_ecdsa_signed_at', '_mdsm_ecdsa_dsse')"
    );

    // Delete RSA compatibility signing post meta.
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta}
         WHERE meta_key IN ('_mdsm_rsa_sig', '_mdsm_rsa_signed_at', '_mdsm_rsa_scheme', '_mdsm_rsa_pubkey')"
    );

    // Delete CMS / PKCS#7 signing post meta.
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta}
         WHERE meta_key IN ('_mdsm_cms_sig', '_mdsm_cms_signed_at', '_mdsm_cms_key_source')"
    );

    // Delete JSON-LD / W3C Data Integrity post meta.
    $wpdb->query(
        "DELETE FROM {$wpdb->postmeta}
         WHERE meta_key IN ('_mdsm_jsonld_proof', '_mdsm_jsonld_signed_at', '_mdsm_jsonld_suite')"
    );

    // Securely wipe ECDSA PEM files stored on disk (key, cert, CA bundle).
    $ecdsa_pem_paths = array(
        get_option( 'archiviomd_ecdsa_key_path',  '' ),
        get_option( 'archiviomd_ecdsa_cert_path', '' ),
        get_option( 'archiviomd_ecdsa_ca_path',   '' ),
    );
    foreach ( $ecdsa_pem_paths as $pem_path ) {
        if ( $pem_path && file_exists( $pem_path ) ) {
            $len = filesize( $pem_path );
            if ( $len > 0 ) {
                file_put_contents( $pem_path, str_repeat( "\0", $len ) );
            }
            @unlink( $pem_path );
        }
    }

    // Securely wipe RSA PEM files stored on disk (key, cert).
    $rsa_pem_paths = array(
        get_option( 'archiviomd_rsa_key_path',  '' ),
        get_option( 'archiviomd_rsa_cert_path', '' ),
    );
    foreach ( $rsa_pem_paths as $pem_path ) {
        if ( $pem_path && file_exists( $pem_path ) ) {
            $len = filesize( $pem_path );
            if ( $len > 0 ) {
                file_put_contents( $pem_path, str_repeat( "\0", $len ) );
            }
            @unlink( $pem_path );
        }
    }
    // Remove the PEM storage directory if empty.
    $pem_dir = dirname( wp_upload_dir()['basedir'] ) . '/archiviomd-pem';
    if ( is_dir( $pem_dir ) ) {
        // Only remove if empty (or only contains our .htaccess guard).
        $remaining = array_diff( scandir( $pem_dir ), array( '.', '..', '.htaccess' ) );
        if ( empty( $remaining ) ) {
            @unlink( $pem_dir . '/.htaccess' );
            @rmdir( $pem_dir );
        }
    }
    
    // Delete DANE health-check transients.
    delete_transient( 'archiviomd_dane_health' );
    delete_transient( 'archiviomd_dane_tlsa_health' );

    // Unschedule DANE passive cron check.
    $dane_ts = wp_next_scheduled( 'archiviomd_dane_cron_check' );
    if ( $dane_ts ) {
        wp_unschedule_event( $dane_ts, 'archiviomd_dane_cron_check' );
    }

    // Drop the audit log table
    $audit_table = $wpdb->prefix . 'archivio_post_audit';
    $wpdb->query( $wpdb->prepare( "DROP TABLE IF EXISTS %i", $audit_table ) );
    
    // 5. Delete External Anchoring settings and queue
    delete_option('mdsm_anchor_settings');
    delete_option('mdsm_anchor_queue');
    
    // Drop anchor log table
    MDSM_Anchor_Log::drop_table();
    
    // Unschedule anchoring cron
    $cron_hook = 'mdsm_process_anchor_queue';
    $timestamp  = wp_next_scheduled($cron_hook);
    if ($timestamp) {
        wp_unschedule_event($timestamp, $cron_hook);
    }
    
    // 4. Delete public index page if it was created by the plugin
    $page_id = get_option('mdsm_public_index_page_id');
    if ($page_id) {
        // Force delete (bypass trash)
        wp_delete_post($page_id, true);
    }
    
    // 6. Delete Canary Token settings, log table, and derived user meta.
    //
    // Canary Token options are stored under obfuscated keys (prefix 'ac_')
    // whose exact names are site-specific (seeded from the site URL).
    // We reconstruct the same opt() map here so we delete exactly the right
    // keys without touching any other plugin's options that happen to use
    // the 'ac_' prefix.
    $ct_seed = md5( get_site_url() );
    $ct_logicals = array(
        'enabled', 'contractions', 'synonyms', 'punctuation',
        'spelling', 'hyphenation', 'numbers', 'punctuation2',
        'citation', 'parity', 'wordcount',
        'payload_version', 'key_fingerprint', 'key_rotation_id',
        'cache_health', 'cache_notice_dismissed', 'cache_check_url',
        'cache_check_time', 'db_version',
        'key_rotated', 'key_rotated_from', 'key_warn_dismissed',
    );
    foreach ( $ct_logicals as $ct_logical ) {
        $ct_option = 'ac_' . substr( md5( $ct_seed . ':' . $ct_logical ), 0, 8 );
        delete_option( $ct_option );
    }
    // Also delete DMCA contact fields (stored under plain option names).
    foreach ( array( 'name', 'title', 'company', 'email', 'phone', 'address', 'website' ) as $ct_field ) {
        delete_option( 'archivio_dmca_' . $ct_field );
    }
    // Drop the discovery log table.
    $ct_log_table = $wpdb->prefix . 'archivio_canary_log';
    $wpdb->query( "DROP TABLE IF EXISTS `{$ct_log_table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    // Remove per-user dismiss meta (fallback-key notice and cache notice).
    $wpdb->delete( $wpdb->usermeta, array( 'meta_key' => 'archivio_fallback_key_dismissed' ) );
    $wpdb->delete( $wpdb->usermeta, array( 'meta_key' => 'archivio_cache_notice_dismissed' ) );
    // Remove per-post canary disable flag.
    $wpdb->delete( $wpdb->postmeta, array( 'meta_key' => '_archivio_canary_disabled' ) );


    // IMPORTANT: Generated sitemaps and HTML files are NOT deleted
    // These files are considered site content, not plugin data
    // Administrators must manually delete these files if desired
}

// Execute cleanup
archiviomd_uninstall_cleanup();
