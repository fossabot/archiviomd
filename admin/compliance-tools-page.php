<?php
/**
 * Compliance Tools Admin Page
 * 
 * Provides three compliance-supporting capabilities:
 * 1. Metadata Export (CSV) - Export all metadata on demand
 * 2. Backup & Restore - Manual backup and restore of metadata + files
 * 3. Metadata Verification - Manual checksum verification
 */

if (!defined('ABSPATH')) {
    exit;
}

// Security check
if (!current_user_can('manage_options')) {
    wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'archiviomd' ) );
}

$file_manager = new MDSM_File_Manager();
$metadata_manager = new MDSM_Document_Metadata();

// Get all files with metadata
$meta_files = mdsm_get_meta_files();
$custom_files = mdsm_get_custom_markdown_files();

// Count total documents with metadata
$total_documents = 0;
$documents_with_metadata = array();

foreach ($meta_files as $category => $files) {
    foreach ($files as $file_name => $description) {
        if ($file_manager->file_exists('meta', $file_name)) {
            $metadata = $metadata_manager->get_metadata($file_name);
            if (!empty($metadata['uuid'])) {
                $total_documents++;
                $documents_with_metadata[$file_name] = array(
                    'category' => $category,
                    'description' => $description,
                    'metadata' => $metadata
                );
            }
        }
    }
}

foreach ($custom_files as $file_name => $description) {
    if ($file_manager->file_exists('meta', $file_name)) {
        $metadata = $metadata_manager->get_metadata($file_name);
        if (!empty($metadata['uuid'])) {
            $total_documents++;
            $documents_with_metadata[$file_name] = array(
                'category' => 'Custom Files',
                'description' => $description,
                'metadata' => $metadata
            );
        }
    }
}
?>

<div class="wrap">
    <h1>ArchivioMD Compliance Tools</h1>
    <p>Admin-only tools for compliance, audit readiness, and metadata integrity verification.</p>
    
    <div class="notice notice-info">
        <p><strong>Important:</strong> ArchivioMD stores all metadata (UUIDs, checksums, changelogs) in the WordPress database. 
        Regular WordPress database backups are required for complete data protection. These tools provide additional 
        export and verification capabilities for audit purposes.</p>
    </div>

    <!-- Tool 1: Metadata Export (CSV) -->
    <div class="card" style="margin-top: 20px;">
        <h2>1. Metadata Export (CSV)</h2>
        <p>Export all ArchivioMD metadata to a CSV file for compliance audits and record-keeping.</p>
        <p><strong>Documents with metadata:</strong> <?php echo absint( $total_documents ); ?></p>
        <p><strong>Export includes:</strong> UUID, filename, path, last-modified timestamp (UTC), SHA-256 checksum, changelog count, and full changelog entries.</p>
        
        <form method="post" id="mdsm-export-metadata-form">
            <?php wp_nonce_field('mdsm_export_metadata', 'mdsm_export_metadata_nonce'); ?>
            <input type="hidden" name="action" value="mdsm_export_metadata">
            <button type="submit" class="button button-primary">
                <span class="dashicons dashicons-download" style="margin-top: 3px;"></span>
                Export Metadata to CSV
            </button>
        </form>
        <div id="mdsm-csv-sig-result" style="display:none; margin-top: 12px;"></div>
    </div>

    <!-- Tool 1b: Structured Compliance JSON Export -->
    <div class="card" style="margin-top: 20px;">
        <h2>1b. Structured Compliance Export (JSON)</h2>
        <p>Export a complete, structured evidence package as a single JSON file. Unlike the flat CSV, this export preserves the full relationships between each post or document, its hash history, all anchor log entries, and any RFC&nbsp;3161 timestamp manifests.</p>
        <p><strong>Suitable for:</strong> legal evidence packages, compliance audits, feeding into document management systems or SIEMs.</p>
        <p><strong>Export includes:</strong></p>
        <ul>
            <li><strong>Posts</strong> — title, URL, current hash, full hash history from the Cryptographic Verification log, and all anchoring attempts with TSR manifest data inlined.</li>
            <li><strong>Documents</strong> — UUID, filename, full append-only changelog, and all anchoring attempts.</li>
        </ul>
        <?php wp_nonce_field( 'mdsm_export_compliance_json', 'mdsm_export_compliance_json_nonce' ); ?>
        <button type="button" id="mdsm-export-compliance-json-btn" class="button button-primary">
            <span class="dashicons dashicons-download" style="margin-top: 3px;"></span>
            Export Compliance Package (JSON)
        </button>
        <span id="mdsm-export-compliance-json-status" style="margin-left: 12px; color: #666;"></span>
        <div id="mdsm-json-sig-result" style="display:none; margin-top: 12px;"></div>
    </div>

    <!-- Tool 2: Backup & Restore -->
    <div class="card" style="margin-top: 20px;">
        <h2>2. Document Backup & Restore</h2>
        <p>Create a complete backup archive of all ArchivioMD metadata and Markdown files, or restore from a previous backup.</p>
        
        <div style="border-left: 4px solid #dc3232; padding: 10px; margin: 15px 0; background: #fff;">
            <p style="margin: 0;"><strong>⚠️ Critical Information:</strong></p>
            <ul style="margin: 5px 0;">
                <li>ArchivioMD metadata lives in the WordPress database (wp_options table)</li>
                <li>Regular WordPress database backups are REQUIRED for full data protection</li>
                <li>This backup tool creates portable archives for disaster recovery and migration</li>
                <li>Restore operations require explicit confirmation and show a mandatory dry-run first</li>
            </ul>
        </div>
        
        <h3>Create Backup</h3>
        <p>Generate a downloadable ZIP archive containing:</p>
        <ul>
            <li>All ArchivioMD metadata (JSON format)</li>
            <li>All associated Markdown files</li>
            <li>Manifest file with backup details and checksums</li>
        </ul>
        
        <form method="post" id="mdsm-backup-form">
            <?php wp_nonce_field('mdsm_create_backup', 'mdsm_create_backup_nonce'); ?>
            <input type="hidden" name="action" value="mdsm_create_backup">
            <button type="submit" class="button button-primary">
                <span class="dashicons dashicons-backup" style="margin-top: 3px;"></span>
                Create Backup Archive
            </button>
        </form>
        <div id="mdsm-backup-sig-result" style="display:none; margin-top: 12px;"></div>

        <h3 style="margin-top: 30px;">Restore from Backup</h3>
        <p><strong style="color: #dc3232;">DESTRUCTIVE OPERATION:</strong> Restoring will overwrite existing metadata and files.</p>
        <p>The restore process includes:</p>
        <ol>
            <li><strong>Mandatory Dry Run:</strong> Upload and analyze the backup (read-only)</li>
            <li><strong>Review Report:</strong> See exactly what will be restored, overwritten, or cause conflicts</li>
            <li><strong>Explicit Confirmation:</strong> Only proceeds after you confirm the changes</li>
            <li><strong>Full Restore:</strong> Rehydrates metadata and files without altering UUIDs or content</li>
        </ol>
        
        <div id="mdsm-restore-section">
            <form method="post" id="mdsm-restore-upload-form" enctype="multipart/form-data">
                <?php wp_nonce_field('mdsm_restore_dryrun', 'mdsm_restore_dryrun_nonce'); ?>
                <input type="hidden" name="action" value="mdsm_restore_dryrun">
                <p>
                    <label for="mdsm-backup-file"><strong>Select Backup Archive (.zip):</strong></label><br>
                    <input type="file" name="backup_file" id="mdsm-backup-file" accept=".zip" required>
                </p>
                <button type="submit" class="button button-secondary">
                    <span class="dashicons dashicons-analytics" style="margin-top: 3px;"></span>
                    Analyze Backup (Dry Run)
                </button>
            </form>
            
            <div id="mdsm-dryrun-results" style="display: none; margin-top: 20px;"></div>
        </div>
    </div>

    <!-- Tool 3: Metadata Verification -->
    <div class="card" style="margin-top: 20px; margin-bottom: 20px;">
        <h2>3. Metadata Verification Tool</h2>
        <p>Manually verify document integrity by comparing current file checksums against stored SHA-256 values.</p>
        <p><strong>This tool is:</strong></p>
        <ul>
            <li><strong>Manual:</strong> Verification runs only when you click the button</li>
            <li><strong>Read-only:</strong> No automatic corrections, enforcement, or alerts</li>
            <li><strong>Non-intrusive:</strong> Reports status without modifying files or metadata</li>
        </ul>
        
        <form method="post" id="mdsm-verify-form">
            <?php wp_nonce_field('mdsm_verify_metadata', 'mdsm_verify_metadata_nonce'); ?>
            <input type="hidden" name="action" value="mdsm_verify_metadata">
            <button type="submit" class="button button-secondary">
                <span class="dashicons dashicons-yes-alt" style="margin-top: 3px;"></span>
                Verify All Document Checksums
            </button>
        </form>
        
        <div id="mdsm-verification-results" style="display: none; margin-top: 20px;"></div>
    </div>

    <!-- Tool 4: Metadata Cleanup on Uninstall -->
    <div class="card" style="margin-top: 20px; margin-bottom: 20px; border-left-color: #dc3232;">
        <h2>4. Metadata Cleanup on Uninstall</h2>
        
        <div style="border-left: 4px solid #dc3232; padding: 15px; margin: 15px 0; background: #fff8f8;">
            <p style="margin: 0 0 10px 0;"><strong>⚠️ AUDIT & COMPLIANCE NOTICE</strong></p>
            <p style="margin: 0;"><strong>DEFAULT BEHAVIOR (Recommended):</strong> All metadata (UUIDs, checksums, changelogs) 
            is preserved when the plugin is uninstalled. This metadata constitutes audit evidence and should be retained 
            according to your organization's data retention policies.</p>
        </div>
        
        <p><strong>What is stored in the database:</strong></p>
        <ul>
            <li>Document metadata (UUID identifiers, SHA-256 checksums, timestamps)</li>
            <li>Append-only changelogs (who modified what and when)</li>
            <li>Plugin configuration settings</li>
        </ul>
        
        <p><strong>What is NOT affected by cleanup:</strong></p>
        <ul>
            <li>Markdown files in <code><?php $upload_dir = wp_upload_dir(); echo esc_html( $upload_dir['basedir'] . '/meta-docs/' ); ?></code> (never deleted)</li>
            <li>Generated HTML files (never deleted)</li>
            <li>Generated sitemaps (never deleted)</li>
            <li>WordPress core data, posts, pages, or other plugin data</li>
        </ul>
        
        <?php
        $cleanup_enabled = get_option('mdsm_uninstall_cleanup_enabled', false);
        $current_status = $cleanup_enabled ? 'ENABLED - Metadata will be deleted on uninstall' : 'DISABLED - Metadata will be preserved (default)';
        $status_class = $cleanup_enabled ? 'mdsm-status-mismatch' : 'mdsm-status-verified';
        ?>
        
        <div style="background: #f0f0f1; padding: 15px; margin: 15px 0;">
            <p style="margin: 0;"><strong>Current Status:</strong> 
                <span class="<?php echo esc_attr($status_class); ?>" style="font-size: 14px;">
                    <?php echo esc_html($current_status); ?>
                </span>
            </p>
        </div>
        
        <h3>Enable Metadata Cleanup (Opt-In)</h3>
        <p><strong style="color: #dc3232;">WARNING:</strong> Enabling this option will cause all ArchivioMD metadata 
        to be permanently deleted when you uninstall the plugin. This action is <strong>irreversible</strong>.</p>
        
        <p><strong>Before enabling:</strong></p>
        <ol>
            <li>Verify your organization's data retention and compliance requirements</li>
            <li>Create a backup using the "Document Backup & Restore" tool above</li>
            <li>Understand that metadata deletion cannot be undone</li>
            <li>Confirm that Markdown files will remain intact (they are never deleted)</li>
        </ol>
        
        <form method="post" id="mdsm-uninstall-cleanup-form" style="margin-top: 20px;">
            <?php wp_nonce_field('mdsm_uninstall_cleanup_settings', 'mdsm_uninstall_cleanup_nonce'); ?>
            <input type="hidden" name="action" value="mdsm_save_uninstall_cleanup">
            
            <p>
                <label style="display: flex; align-items: center; gap: 10px;">
                    <input type="checkbox" 
                           name="cleanup_enabled" 
                           id="mdsm-cleanup-checkbox" 
                           value="1" 
                           <?php checked($cleanup_enabled, true); ?>>
                    <strong>Enable metadata deletion on plugin uninstall</strong>
                </label>
            </p>
            
            <div id="mdsm-cleanup-confirmation-section" style="display: <?php echo $cleanup_enabled ? 'block' : 'none'; ?>; margin: 15px 0; padding: 15px; background: #fff4e6; border-left: 4px solid #f0b849;">
                <p style="margin: 0 0 10px 0;"><strong>⚠️ CONFIRMATION REQUIRED</strong></p>
                <p style="margin: 0 0 10px 0;">Type <code>DELETE METADATA</code> in the box below to confirm you understand this action:</p>
                <input type="text" 
                       name="cleanup_confirmation" 
                       id="mdsm-cleanup-confirmation-input"
                       placeholder="DELETE METADATA"
                       style="width: 300px; font-family: monospace;">
            </div>
            
            <p>
                <button type="submit" class="button button-primary" id="mdsm-cleanup-save-btn">
                    <span class="dashicons dashicons-admin-settings" style="margin-top: 3px;"></span>
                    Save Cleanup Settings
                </button>
                
                <?php if ($cleanup_enabled): ?>
                    <button type="button" class="button button-secondary" id="mdsm-cleanup-disable-btn" style="margin-left: 10px;">
                        <span class="dashicons dashicons-shield" style="margin-top: 3px;"></span>
                        Disable Cleanup (Restore Default)
                    </button>
                <?php endif; ?>
            </p>
        </form>
        
        <div id="mdsm-cleanup-status" style="display: none; margin-top: 15px;"></div>
        
        <div style="background: #e7f5e9; padding: 15px; margin: 20px 0 0 0; border-left: 4px solid #008a00;">
            <p style="margin: 0;"><strong>✓ Recommended Practice:</strong> Keep cleanup disabled and rely on regular WordPress 
            database backups. Metadata provides valuable audit trails and can help with compliance, debugging, and content management.</p>
        </div>
    </div>
</div>

<?php
wp_add_inline_style( 'mdsm-compliance-tools', '.card{background:#fff;border:1px solid #ccd0d4;border-left:4px solid #2271b1;padding:20px;box-shadow:0 1px 1px rgba(0,0,0,.04)}.card h2{margin-top:0}.mdsm-status-verified{color:#008a00}.mdsm-status-mismatch{color:#dc3232;font-weight:bold}.mdsm-status-missing{color:#996800}.mdsm-verification-table,.mdsm-dryrun-table{width:100%;border-collapse:collapse;margin-top:10px}.mdsm-verification-table th,.mdsm-verification-table td,.mdsm-dryrun-table th,.mdsm-dryrun-table td{text-align:left;padding:8px;border-bottom:1px solid #ddd}.mdsm-verification-table th,.mdsm-dryrun-table th{background-color:#f0f0f1;font-weight:600}.mdsm-action-restore{background-color:#e7f5e9}.mdsm-action-overwrite{background-color:#fff4e6}.mdsm-action-conflict{background-color:#ffe9e9}' );
?>

<?php
wp_localize_script( 'mdsm-compliance-tools-js', 'mdsmComplianceData', array(
    'executeRestoreNonce' => wp_create_nonce( 'mdsm_execute_restore' ),
) );
// Pass signing availability so the JS helper can label the sig notice correctly.
// True when at least one signing algorithm is fully configured and ready.
$mdsm_ed25519_on = (
	MDSM_Ed25519_Signing::is_mode_enabled() &&
	MDSM_Ed25519_Signing::is_private_key_defined() &&
	MDSM_Ed25519_Signing::is_sodium_available()
);
$mdsm_slhdsa_on = (
	MDSM_SLHDSA_Signing::is_mode_enabled() &&
	MDSM_SLHDSA_Signing::is_private_key_defined()
);
$mdsm_ecdsa_on = MDSM_ECDSA_Signing::status()['ready'];

$mdsm_rsa_on    = class_exists( 'MDSM_RSA_Signing' )    ? MDSM_RSA_Signing::status()['ready']    : false;
$mdsm_cms_on    = class_exists( 'MDSM_CMS_Signing' )    ? MDSM_CMS_Signing::status()['ready']    : false;
$mdsm_jsonld_on = class_exists( 'MDSM_JSONLD_Signing' ) ? MDSM_JSONLD_Signing::status()['ready'] : false;

$mdsm_signing_on    = $mdsm_ed25519_on || $mdsm_slhdsa_on || $mdsm_ecdsa_on || $mdsm_rsa_on || $mdsm_cms_on || $mdsm_jsonld_on;
$mdsm_signing_parts = array();
if ( $mdsm_ed25519_on ) { $mdsm_signing_parts[] = 'Ed25519'; }
if ( $mdsm_slhdsa_on  ) { $mdsm_signing_parts[] = esc_js( MDSM_SLHDSA_Signing::get_param() ); }
if ( $mdsm_ecdsa_on   ) { $mdsm_signing_parts[] = 'ECDSA P-256'; }
if ( $mdsm_rsa_on     ) { $mdsm_signing_parts[] = 'RSA'; }
if ( $mdsm_cms_on     ) { $mdsm_signing_parts[] = 'CMS/PKCS#7'; }
if ( $mdsm_jsonld_on  ) { $mdsm_signing_parts[] = 'JSON-LD'; }
$mdsm_signing_label = implode( ' + ', $mdsm_signing_parts );
wp_add_inline_script(
    'mdsm-compliance-tools-js',
    'window.mdsmSigningEnabled = ' . ( $mdsm_signing_on ? 'true' : 'false' ) . ';'
    . 'window.mdsmSigningLabel = ' . wp_json_encode( $mdsm_signing_label ) . ';',
    'before'
);
?>
<?php
ob_start();
?>
jQuery(document).ready(function($) {

    // ── Shared helper: render a sig-download notice into a container ──────
    function mdsmRenderSigResult( $container, data ) {
        if ( data.sig_url && data.sig_filename ) {
            $container.html(
                '<div style="padding: 10px 14px; background: #e7f5e9; border-left: 4px solid #008a00; display: flex; align-items: center; gap: 12px;">' +
                '<span class="dashicons dashicons-lock" style="color: #008a00; font-size: 18px; flex-shrink: 0;"></span>' +
                '<div style="flex: 1;">' +
                '<strong style="color: #008a00;">' + ( window.mdsmSigningEnabled ? '✓ Export signed with ' + window.mdsmSigningLabel : '✓ Integrity receipt generated' ) + '</strong>' +
                '<p style="margin: 2px 0 0 0; font-size: 12px; color: #555;">' +
                'A <code>.sig.json</code> file has been generated alongside this export. ' +
                'It contains a SHA-256 integrity hash' +
                ( window.mdsmSigningEnabled ? ' and a ' + window.mdsmSigningLabel + ' signature' : '' ) +
                ' binding the filename, export type, site URL, and timestamp. ' +
                'Keep it with the export file for auditable verification.' +
                '</p>' +
                '</div>' +
                '<a href="' + data.sig_url + '" class="button button-secondary" style="flex-shrink: 0; white-space: nowrap;">' +
                '<span class="dashicons dashicons-download" style="margin-top: 3px;"></span> ' +
                'Download Signature' +
                '</a>' +
                '</div>'
            ).show();
        }
    }

    // Export Metadata to CSV
    $('#mdsm-export-metadata-form').on('submit', function(e) {
        e.preventDefault();
        
        var $button = $(this).find('button[type="submit"]');
        var originalText = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Generating CSV...');
        $('#mdsm-csv-sig-result').hide().empty();
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_export_metadata_csv',
                nonce: $('#mdsm_export_metadata_nonce').val()
            },
            success: function(response) {
                if (response.success && response.data.download_url) {
                    window.location.href = response.data.download_url;
                    mdsmRenderSigResult( $('#mdsm-csv-sig-result'), response.data );
                } else {
                    alert('Error: ' + (response.data.message || 'Failed to export metadata'));
                }
            },
            error: function() {
                alert('Error: Failed to export metadata. Please try again.');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalText);
            }
        });
    });
    
    // Create Backup
    $('#mdsm-backup-form').on('submit', function(e) {
        e.preventDefault();
        
        var $button = $(this).find('button[type="submit"]');
        var originalText = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Creating Backup...');
        $('#mdsm-backup-sig-result').hide().empty();
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_create_backup_archive',
                nonce: $('#mdsm_create_backup_nonce').val()
            },
            success: function(response) {
                if (response.success && response.data.download_url) {
                    window.location.href = response.data.download_url;
                    mdsmRenderSigResult( $('#mdsm-backup-sig-result'), response.data );
                } else {
                    alert('Error: ' + (response.data.message || 'Failed to create backup'));
                }
            },
            error: function() {
                alert('Error: Failed to create backup. Please try again.');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalText);
            }
        });
    });
    
    // Restore Dry Run
    $('#mdsm-restore-upload-form').on('submit', function(e) {
        e.preventDefault();
        
        var fileInput = $('#mdsm-backup-file')[0];
        if (!fileInput.files.length) {
            alert('Please select a backup file.');
            return;
        }
        
        var $button = $(this).find('button[type="submit"]');
        var originalText = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Analyzing...');
        
        var formData = new FormData(this);
        formData.append('action', 'mdsm_restore_dryrun');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    displayDryRunResults(response.data);
                } else {
                    alert('Error: ' + (response.data.message || 'Failed to analyze backup'));
                }
            },
            error: function() {
                alert('Error: Failed to analyze backup. Please try again.');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalText);
            }
        });
    });
    
    function displayDryRunResults(data) {
        var html = '<div style="border: 2px solid #2271b1; padding: 15px; background: #f0f6fc;">';
        html += '<h3>Dry Run Analysis Complete</h3>';
        html += '<p><strong>Backup Created:</strong> ' + data.backup_info.created_at + '</p>';
        html += '<p><strong>Documents in Backup:</strong> ' + data.backup_info.document_count + '</p>';
        
        if (data.actions.restore.length > 0 || data.actions.overwrite.length > 0 || data.actions.conflict.length > 0) {
            html += '<h4>Proposed Changes:</h4>';
            html += '<table class="mdsm-dryrun-table">';
            html += '<thead><tr><th>Action</th><th>Filename</th><th>Details</th></tr></thead>';
            html += '<tbody>';
            
            data.actions.restore.forEach(function(item) {
                html += '<tr class="mdsm-action-restore">';
                html += '<td><strong>RESTORE</strong></td>';
                html += '<td>' + item.filename + '</td>';
                html += '<td>New document (UUID: ' + item.uuid.substring(0, 8) + '...)</td>';
                html += '</tr>';
            });
            
            data.actions.overwrite.forEach(function(item) {
                html += '<tr class="mdsm-action-overwrite">';
                html += '<td><strong>OVERWRITE</strong></td>';
                html += '<td>' + item.filename + '</td>';
                html += '<td>Existing: ' + item.existing_checksum.substring(0, 16) + '... → New: ' + item.new_checksum.substring(0, 16) + '...</td>';
                html += '</tr>';
            });
            
            data.actions.conflict.forEach(function(item) {
                html += '<tr class="mdsm-action-conflict">';
                html += '<td><strong>CONFLICT</strong></td>';
                html += '<td>' + item.filename + '</td>';
                html += '<td>' + item.reason + '</td>';
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            
            if (data.actions.conflict.length > 0) {
                html += '<div style="background: #ffe9e9; border: 1px solid #dc3232; padding: 10px; margin-top: 15px;">';
                html += '<strong>⚠️ Conflicts Detected</strong><br>';
                html += 'Some files cannot be restored automatically. Please resolve conflicts manually.';
                html += '</div>';
            }
            
            html += '<div style="margin-top: 20px;">';
            html += '<button type="button" class="button button-primary button-large" id="mdsm-confirm-restore" ';
            if (data.actions.conflict.length > 0) {
                html += 'disabled title="Cannot proceed with conflicts"';
            }
            html += '>Confirm and Execute Restore</button> ';
            html += '<button type="button" class="button button-secondary" onclick="location.reload()">Cancel</button>';
            html += '</div>';
        } else {
            html += '<p><em>No changes needed. All documents in backup match current state.</em></p>';
        }
        
        html += '</div>';
        
        $('#mdsm-dryrun-results').html(html).show();
        
        // Store backup data for actual restore
        $('#mdsm-dryrun-results').data('backup-data', data);
    }
    
    // Confirm and execute restore
    $(document).on('click', '#mdsm-confirm-restore', function() {
        if (!confirm('This will PERMANENTLY overwrite existing files and metadata. Are you absolutely sure?')) {
            return;
        }
        
        var $button = $(this);
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Restoring...');
        
        var backupData = $('#mdsm-dryrun-results').data('backup-data');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_execute_restore',
                nonce: mdsmComplianceData.executeRestoreNonce,
                backup_id: backupData.backup_info.backup_id
            },
            success: function(response) {
                if (response.success) {
                    alert('Restore completed successfully!\n\n' +
                          'Restored: ' + response.data.restored_count + ' documents\n' +
                          'Overwritten: ' + response.data.overwritten_count + ' documents\n' +
                          'Failed: ' + response.data.failed_count + ' documents');
                    location.reload();
                } else {
                    alert('Error: ' + (response.data.message || 'Restore failed'));
                    $button.prop('disabled', false).html('Confirm and Execute Restore');
                }
            },
            error: function() {
                alert('Error: Restore operation failed. Please try again.');
                $button.prop('disabled', false).html('Confirm and Execute Restore');
            }
        });
    });
    
    // Verify Metadata
    $('#mdsm-verify-form').on('submit', function(e) {
        e.preventDefault();
        
        var $button = $(this).find('button[type="submit"]');
        var originalText = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Verifying...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_verify_checksums',
                nonce: $('#mdsm_verify_metadata_nonce').val()
            },
            success: function(response) {
                if (response.success) {
                    displayVerificationResults(response.data);
                } else {
                    alert('Error: ' + (response.data.message || 'Verification failed'));
                }
            },
            error: function() {
                alert('Error: Verification failed. Please try again.');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalText);
            }
        });
    });
    
    function displayVerificationResults(data) {
        var html = '<div style="border: 2px solid #2271b1; padding: 15px; background: #f0f6fc;">';
        html += '<h3>Verification Results</h3>';
        html += '<p><strong>Verified:</strong> <span class="mdsm-status-verified">' + data.verified + '</span> | ';
        html += '<strong>Mismatched:</strong> <span class="mdsm-status-mismatch">' + data.mismatch + '</span> | ';
        html += '<strong>Missing Files:</strong> <span class="mdsm-status-missing">' + data.missing + '</span></p>';
        
        if (data.results.length > 0) {
            html += '<table class="mdsm-verification-table">';
            html += '<thead><tr><th>File</th><th>Status</th><th>Details</th></tr></thead>';
            html += '<tbody>';
            
            data.results.forEach(function(item) {
                var statusClass = '';
                var statusText = '';
                var details = '';
                
                if (item.status === 'verified') {
                    statusClass = 'mdsm-status-verified';
                    statusText = '✓ VERIFIED';
                    details = 'Checksum: ' + item.stored_checksum.substring(0, 16) + '...';
                } else if (item.status === 'mismatch') {
                    statusClass = 'mdsm-status-mismatch';
                    statusText = '✗ MISMATCH';
                    details = 'Stored: ' + item.stored_checksum.substring(0, 16) + '... | Current: ' + item.current_checksum.substring(0, 16) + '...';
                } else if (item.status === 'missing') {
                    statusClass = 'mdsm-status-missing';
                    statusText = '⚠ MISSING FILE';
                    details = 'File not found on disk';
                }
                
                html += '<tr>';
                html += '<td>' + item.filename + '</td>';
                html += '<td class="' + statusClass + '">' + statusText + '</td>';
                html += '<td>' + details + '</td>';
                html += '</tr>';
            });
            
            html += '</tbody></table>';
        }
        
        html += '</div>';
        
        $('#mdsm-verification-results').html(html).show();
    }
    
    // ============================================================================
    // Metadata Cleanup on Uninstall Handlers
    // ============================================================================
    
    // Show/hide confirmation section when checkbox changes
    $('#mdsm-cleanup-checkbox').on('change', function() {
        if ($(this).is(':checked')) {
            $('#mdsm-cleanup-confirmation-section').slideDown();
        } else {
            $('#mdsm-cleanup-confirmation-section').slideUp();
            $('#mdsm-cleanup-confirmation-input').val('');
        }
    });
    
    // Handle cleanup settings form submission
    $('#mdsm-uninstall-cleanup-form').on('submit', function(e) {
        e.preventDefault();
        
        var $form = $(this);
        var $button = $('#mdsm-cleanup-save-btn');
        var cleanupEnabled = $('#mdsm-cleanup-checkbox').is(':checked');
        var confirmationText = $('#mdsm-cleanup-confirmation-input').val().trim();
        
        // If enabling cleanup, require confirmation text
        if (cleanupEnabled && confirmationText !== 'DELETE METADATA') {
            alert('ERROR: You must type "DELETE METADATA" exactly to enable metadata cleanup.');
            $('#mdsm-cleanup-confirmation-input').focus();
            return;
        }
        
        // Double confirmation for enabling cleanup
        if (cleanupEnabled) {
            var confirmMsg = 'FINAL WARNING: You are about to enable metadata deletion on plugin uninstall.\n\n';
            confirmMsg += 'This means all UUIDs, checksums, and changelogs will be permanently deleted when you uninstall ArchivioMD.\n\n';
            confirmMsg += 'This action is irreversible and may impact compliance requirements.\n\n';
            confirmMsg += 'Are you absolutely certain you want to proceed?';
            
            if (!confirm(confirmMsg)) {
                return;
            }
        }
        
        var originalText = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Saving...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_save_uninstall_cleanup',
                nonce: $('#mdsm_uninstall_cleanup_nonce').val(),
                cleanup_enabled: cleanupEnabled ? '1' : '0'
            },
            success: function(response) {
                if (response.success) {
                    var statusHtml = '<div style="border-left: 4px solid #008a00; padding: 15px; background: #e7f5e9;">';
                    statusHtml += '<p style="margin: 0;"><strong>✓ Settings saved successfully!</strong></p>';
                    statusHtml += '<p style="margin: 10px 0 0 0;">' + response.data.message + '</p>';
                    statusHtml += '</div>';
                    
                    $('#mdsm-cleanup-status').html(statusHtml).slideDown();
                    
                    // Reload page after 2 seconds to reflect new state
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                } else {
                    alert('Error: ' + (response.data.message || 'Failed to save settings'));
                }
            },
            error: function() {
                alert('Error: Failed to save settings. Please try again.');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalText);
            }
        });
    });
    
    // Handle disable button (quick restore to default)
    $('#mdsm-cleanup-disable-btn').on('click', function() {
        if (!confirm('Disable metadata cleanup and restore default behavior (preserve metadata on uninstall)?')) {
            return;
        }
        
        var $button = $(this);
        var originalText = $button.html();
        $button.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Disabling...');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_save_uninstall_cleanup',
                nonce: $('#mdsm_uninstall_cleanup_nonce').val(),
                cleanup_enabled: '0'
            },
            success: function(response) {
                if (response.success) {
                    var statusHtml = '<div style="border-left: 4px solid #008a00; padding: 15px; background: #e7f5e9;">';
                    statusHtml += '<p style="margin: 0;"><strong>✓ Cleanup disabled successfully!</strong></p>';
                    statusHtml += '<p style="margin: 10px 0 0 0;">Metadata will be preserved on uninstall (default behavior).</p>';
                    statusHtml += '</div>';
                    
                    $('#mdsm-cleanup-status').html(statusHtml).slideDown();
                    
                    // Reload page after 2 seconds
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                } else {
                    alert('Error: ' + (response.data.message || 'Failed to disable cleanup'));
                }
            },
            error: function() {
                alert('Error: Failed to disable cleanup. Please try again.');
            },
            complete: function() {
                $button.prop('disabled', false).html(originalText);
            }
        });
    });
    // Export Compliance JSON
    $('#mdsm-export-compliance-json-btn').on('click', function() {
        var $btn    = $(this);
        var $status = $('#mdsm-export-compliance-json-status');
        var originalHtml = $btn.html();

        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin" style="margin-top: 3px;"></span> Generating&hellip;');
        $status.text('');
        $('#mdsm-json-sig-result').hide().empty();

        $.ajax({
            url:  ajaxurl,
            type: 'POST',
            data: {
                action: 'mdsm_export_compliance_json',
                nonce:  $('#mdsm_export_compliance_json_nonce').val()
            },
            success: function(response) {
                if (response.success && response.data.download_url) {
                    $status.css('color', '#008a00').text('Export ready — download starting.');
                    window.location.href = response.data.download_url;
                    mdsmRenderSigResult( $('#mdsm-json-sig-result'), response.data );
                } else {
                    $status.css('color', '#dc3232').text('Error: ' + (response.data.message || 'Export failed.'));
                }
            },
            error: function() {
                $status.css('color', '#dc3232').text('Server error — please try again.');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalHtml);
            }
        });
    });

});
<?php
$_mdsm_inline_js = ob_get_clean();
wp_add_inline_script( 'mdsm-compliance-tools-js', $_mdsm_inline_js );
?>
