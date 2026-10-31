<?php

/**
 * Uninstall handler for WP User History Log.
 *
 * History is kept by default so uninstalling the plugin does not erase the audit trail.
 * Set USER_HISTORY_DELETE_DATA_ON_UNINSTALL to true in wp-config.php, or store a truthy
 * user_history_delete_data_on_uninstall option, before deleting the plugin if the
 * operator wants the table and plugin options removed.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Remove plugin tables and options for the current site only when explicitly requested.
 */
function user_history_uninstall_current_site() {
    if (function_exists('wp_unschedule_hook')) {
        wp_unschedule_hook('user_history_prune_history');
    }

    $delete_data = (defined('USER_HISTORY_DELETE_DATA_ON_UNINSTALL') && USER_HISTORY_DELETE_DATA_ON_UNINSTALL)
        || (bool) get_option('user_history_delete_data_on_uninstall');

    if (!$delete_data) {
        return;
    }

    global $wpdb;

    $table_name = $wpdb->prefix . 'user_history';
    if (preg_match('/^[A-Za-z0-9_]+$/', $table_name)) {
        $wpdb->query("DROP TABLE IF EXISTS `{$table_name}`");
    }

    delete_option('user_history_version');
    delete_option('user_history_key_version');
    delete_option('user_history_retired_key_versions');
    delete_option('user_history_crypto_current');
    delete_option('user_history_retention_days');
    delete_option('user_history_delete_data_on_uninstall');
}

if (is_multisite()) {
    $site_ids = get_sites(
        [
            'fields'   => 'ids',
            'number'   => 500,
            'archived' => 0,
            'deleted'  => 0,
            'spam'     => 0,
        ]
    );

    foreach ((array) $site_ids as $site_id) {
        $site_id = (int) $site_id;
        if (!user_history_site_tables_are_available($site_id)) {
            continue;
        }

        switch_to_blog($site_id);
        user_history_uninstall_current_site();
        restore_current_blog();
    }
} else {
    user_history_uninstall_current_site();
}

/**
 * Skip leftover blog records whose tables were already removed.
 */
function user_history_site_tables_are_available($site_id) {
    global $wpdb;

    $site_id = (int) $site_id;
    if ($site_id < 1) {
        return false;
    }

    $table = $wpdb->get_blog_prefix($site_id) . 'options';
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
        return false;
    }

    $previous_suppress = $wpdb->suppress_errors(true);
    $found = $wpdb->get_var("SHOW CREATE TABLE `{$table}`");
    $wpdb->suppress_errors($previous_suppress);

    return is_string($found) && $found !== '';
}
