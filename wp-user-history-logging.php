<?php

/**
 * Plugin Name: WP User History Log
 * Plugin URI: https://github.com/technoogies/wp-user-history-log
 * Description: Tracks changes made to user accounts (name, email, username, nicename, etc.) Adds NiceName edit field and displays a history log on the user edit page.
 * Version: 1.1.0
 * Author: Technoogies / gpt 5.1 codex | from WPZOOM user-history
 * Author URI: https://technoogies.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: user-history-log
 * Requires at least: 6.0
 * Requires PHP: 7.4
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('USER_HISTORY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('USER_HISTORY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('USER_HISTORY_VERSION', get_file_data(__FILE__, ['Version' => 'Version'])['Version']);

/**
 * Main User History Class
 */
class User_History {

    /**
     * Database table name (without prefix)
     */
    const TABLE_NAME = 'user_history';
    const CLEAR_HISTORY_CAPABILITY = 'manage_user_history';

    /**
     * Fields to track in wp_users table
     */
    private $tracked_fields = [
        'user_login'    => 'Username',
        'user_email'    => 'Email',
        'user_pass'     => 'Password',
        'user_nicename' => 'Nicename',
        'display_name'  => 'Display Name',
        'user_url'      => 'Website',
    ];

    /**
     * User meta fields to track (capabilities key is added dynamically in init)
     */
    private $tracked_meta = [
        'first_name'   => 'First Name',
        'last_name'    => 'Last Name',
        'nickname'     => 'Nickname',
        'description'  => 'Biographical Info',
    ];

    /**
     * The capabilities meta key (set dynamically based on table prefix)
     */
    private $capabilities_key = '';

    /**
     * Temporarily store old user data before update
     */
    private $old_user_data = [];
    private $old_user_meta = [];

    /**
     * Track which users have had role changes logged this request
     */
    private $role_logged = [];

    /**
     * Pending role changes to log at shutdown (to capture final state)
     */
    private $pending_role_changes = [];

    /**
     * Derived encryption keys keyed by version.
     *
     * @var array<int,string>
     */
    private $encryption_keys = [];

    private const CRYPTO_ENVELOPE = 'uh1';
    private const CRYPTO_OPTION_VERSION = 'user_history_key_version';
    private const CRYPTO_OPTION_RETIRED = 'user_history_retired_key_versions';
    private const CRYPTO_OPTION_CURRENT = 'user_history_crypto_current';
    private const CRYPTO_DEFAULT_VERSION = 1;
    private const CRYPTO_LEGACY_VERSION = 0;
    private const CRYPTO_MIGRATION_BATCH = 100;

    /**
     * Sensitive fields list
     */
    private $sensitive_fields = [
        'user_login',
        'user_email',
        'first_name',
        'last_name',
        'display_name',
        'nickname',
        'user_url',
        'description',
        'user_nicename',
    ];

    /**
     * Fields eligible for historical searching
     */
    private $searchable_fields = [
        'user_login',
        'user_email',
        'first_name',
        'last_name',
        'display_name',
        'nickname',
    ];

    /**
     * Resource limits for historical search indexing.
     *
     * Values above the byte limit remain saved by WordPress, but the audit log
     * stores a fixed placeholder and does not index the sensitive content.
     */
    private const MAX_SEARCHABLE_VALUE_BYTES = 1024;
    private const MAX_SEARCH_TOKEN_COUNT = 128;
    private const MAX_SEARCH_TOKEN_BYTES = 8192;
    private const MAX_SEARCH_QUERY_TOKENS = 5;
    private const OVERSIZED_VALUE_PLACEHOLDER = '[value omitted: exceeds 1024-byte audit limit]';

    /**
     * Pending sanitized nicenames keyed by user ID
     */
    private $pending_nicename_values = [];

    /**
     * Allowed administrator role slugs
     */
    private $admin_role_slugs = ['administrator', 'admin'];

    /**
     * Singleton instance
     */
    private static $instance = null;

    /**
     * Get singleton instance
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
        register_activation_hook(__FILE__, [$this, 'activate']);
        add_action('plugins_loaded', [$this, 'init']);
    }

    /**
     * Plugin activation
     */
    public function activate() {
        $this->create_table();
        $this->grant_history_management_capability_on_activation();
        $this->maybe_migrate_encryption();
        if ($this->limit_existing_search_tokens()) {
            update_option('user_history_version', USER_HISTORY_VERSION);
        }
    }

    /**
     * Create database table
     */
    private function create_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            changed_by bigint(20) unsigned NOT NULL,
            field_name varchar(100) NOT NULL,
            field_label varchar(100) NOT NULL,
            old_value longtext,
            new_value longtext,
            search_tokens longtext,
            changed_by_details longtext,
            change_type varchar(50) NOT NULL DEFAULT 'update',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY changed_by (changed_by),
            KEY field_name (field_name),
            KEY created_at (created_at),
            KEY old_value_search (field_name, old_value(100))
        ) ENGINE=InnoDB $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
        $this->ensure_history_table_engine();
    }

    /**
     * Initialize plugin
     */
    public function init() {
        global $wpdb;

        $this->capabilities_key = $wpdb->prefix . 'capabilities';
        $this->tracked_meta[$this->capabilities_key] = 'Role';

        if (!in_array($this->capabilities_key, $this->sensitive_fields, true)) {
            $this->sensitive_fields[] = $this->capabilities_key;
        }

        $this->maybe_upgrade();

        add_action('pre_user_query', [$this, 'capture_old_data_on_query']);
        add_filter('wp_pre_insert_user_data', [$this, 'capture_old_user_data'], 10, 4);
        add_action('profile_update', [$this, 'log_user_changes'], 10, 3);
        add_action('update_user_meta', [$this, 'capture_old_meta'], 10, 4);
        add_action('updated_user_meta', [$this, 'log_meta_change'], 10, 4);
        add_action('set_user_role', [$this, 'log_role_change'], 10, 3);
        add_action('shutdown', [$this, 'log_pending_role_changes']);
        add_action('user_register', [$this, 'log_user_creation'], 10, 2);

        add_action('edit_user_profile', [$this, 'display_history_section'], 99);
        add_action('show_user_profile', [$this, 'display_history_section'], 99);
        add_action('edit_user_profile', [$this, 'display_delete_user_button'], 100);
        add_action('show_user_profile', [$this, 'display_delete_user_button'], 100);
		
	/** ( Replaced with line after these two )
    *    add_action('show_user_profile', [$this, 'render_nicename_field'], 25); // Was 20 | Wrong place
    *    add_action('edit_user_profile', [$this, 'render_nicename_field'], 25); // Was 20
	**/
		
		add_action('personal_options', [$this, 'render_nicename_field']); // CLC Added | 2025-12-14 | Originally : add_action('personal_options', [$this, 'render_nicename_field']);
				
        add_action('user_profile_update_errors', [$this, 'validate_nicename_submission'], 10, 3);
        add_action('personal_options_update', [$this, 'save_nicename_field']);
        add_action('edit_user_profile_update', [$this, 'save_nicename_field']);

        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

        add_action('wp_ajax_load_more_user_history', [$this, 'ajax_load_more_history']);
        add_action('wp_ajax_user_history_change_username', [$this, 'ajax_change_username']);
        add_action('wp_ajax_clear_user_history', [$this, 'ajax_clear_history']);
        add_action('user_history_rotate_encryption_key', [$this, 'rotate_encryption_key']);
        add_action('user_history_prune_history', [$this, 'prune_expired_history']);
        add_action('wp_initialize_site', [$this, 'grant_history_capability_for_new_site'], 10, 1);

        add_action('pre_user_query', [$this, 'extend_user_search']);
        add_filter('wp_privacy_personal_data_exporters', [$this, 'register_privacy_exporter']);
        add_filter('wp_privacy_personal_data_erasers', [$this, 'register_privacy_eraser']);

        $this->maybe_schedule_retention_prune();
    }

    /**
     * Maybe upgrade database
     */
    private function maybe_upgrade() {
        $this->grant_history_management_capability();
        $current_version = get_option('user_history_version', '0');

        if (version_compare($current_version, USER_HISTORY_VERSION, '<')) {
            $this->create_table();
            $this->maybe_migrate_encryption();
            if ($this->limit_existing_search_tokens()) {
                update_option('user_history_version', USER_HISTORY_VERSION);
            }
            return;
        }

        $this->maybe_migrate_encryption();
    }

    /**
     * Remove legacy token payloads that exceed the current storage budget.
     */
    private function limit_existing_search_tokens() {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $updated = $wpdb->query(
            $wpdb->prepare(
                "UPDATE $table_name
                SET search_tokens = ''
                WHERE OCTET_LENGTH(search_tokens) > %d",
                self::MAX_SEARCH_TOKEN_BYTES
            )
        );

        return false !== $updated;
    }

    /**
     * Capture old user data before update
     */
    public function capture_old_user_data($data, $update, $user_id, $userdata) {
        if ($update && $user_id) {
            $old_user = get_userdata($user_id);
            if ($old_user) {
                $this->old_user_data[$user_id] = $old_user;

                foreach (array_keys($this->tracked_meta) as $meta_key) {
                    $this->old_user_meta[$user_id][$meta_key] = get_user_meta($user_id, $meta_key, true);
                }
            }
        }
        return $data;
    }

    public function capture_old_data_on_query($query) {
        // Reserved for future use
    }

    /**
     * Extend user search to include historical values
     */
    public function extend_user_search($query) {
        global $wpdb, $pagenow;

        if (!is_admin() || $pagenow !== 'users.php' || !current_user_can('list_users')) {
            return;
        }

        $search = $query->get('search');
        if (empty($search)) {
            return;
        }

        $search_term = trim($search, '*');
        if (empty($search_term)) {
            return;
        }

        $token_hashes = $this->hash_tokens_from_term($search_term);
        if (empty($token_hashes)) {
            return;
        }

        $history_table = $wpdb->prefix . self::TABLE_NAME;

        if (!$this->history_table_exists($history_table)) {
            return;
        }

        $placeholders = [];
        $prepare_args = [];
        foreach ($token_hashes as $hash) {
            $placeholders[] = "COALESCE(search_tokens, '') LIKE %s";
            $prepare_args[] = '%' . $wpdb->esc_like($hash) . '%';
        }

        if (empty($placeholders)) {
            return;
        }

        $searchable_fields = "'" . implode("','", array_map('esc_sql', $this->searchable_fields)) . "'";
        $sql = "
            SELECT DISTINCT user_id
            FROM $history_table
            WHERE field_name IN ($searchable_fields)
            AND (" . implode(' OR ', $placeholders) . ')
        ';

        array_unshift($prepare_args, $sql);
        $prepared_sql = call_user_func_array([$wpdb, 'prepare'], $prepare_args);

        $user_ids_from_history = $wpdb->get_col($prepared_sql);

        if (empty($user_ids_from_history)) {
            return;
        }

        $allowed_ids = array_filter(
            array_map('intval', $user_ids_from_history),
            function ($user_id) {
                return $this->user_can_manage_history($user_id);
            }
        );

        if (empty($allowed_ids)) {
            return;
        }

        $historical_sql = $this->prepare_user_id_in_sql($allowed_ids);
        if ($historical_sql === '') {
            return;
        }

        $updated_where = $this->insert_historical_ids_into_search_group($query->query_where, $historical_sql);
        if ($updated_where === $query->query_where) {
            return;
        }

        $query->query_where = $updated_where;
    }

    /**
     * Keep historical matches inside the WP_User_Query search group.
     *
     * Appending an unparenthesized OR after the complete WHERE clause would
     * let historical IDs bypass exclude, site membership, and other ANDs.
     */
    private function insert_historical_ids_into_search_group($where, $historical_sql) {
        $where = (string) $where;
        $historical_sql = (string) $historical_sql;
        $needle = ' AND (';
        $offset = 0;

        while (($start = strpos($where, $needle, $offset)) !== false) {
            $open = $start + strlen($needle) - 1;
            $close = $this->find_matching_paren($where, $open);

            if (false === $close) {
                break;
            }

            $group = substr($where, $open, $close - $open + 1);
            if ($this->is_user_search_group($group)) {
                return substr($where, 0, $close) . ' OR ' . $historical_sql . substr($where, $close);
            }

            $offset = $start + 1;
        }

        return $where;
    }

    private function is_user_search_group($group) {
        return (bool) preg_match(
            '/\b(?:\w+\.)?(?:user_login|user_email|user_url|user_nicename|display_name)\s+LIKE\b/i',
            (string) $group
        ) || (bool) preg_match('/\b(?:\w+\.)?ID\s*=/i', (string) $group);
    }

    private function find_matching_paren($sql, $open_index) {
        $sql = (string) $sql;
        $length = strlen($sql);
        $depth = 0;
        $quote = '';
        $escaped = false;

        for ($index = (int) $open_index; $index < $length; $index++) {
            $char = $sql[$index];

            if ($quote !== '') {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }

                if ($char === '\\') {
                    $escaped = true;
                    continue;
                }

                if ($char === $quote) {
                    if (($index + 1) < $length && $sql[$index + 1] === $quote) {
                        $index++;
                        continue;
                    }
                    $quote = '';
                }

                continue;
            }

            if ($char === "'" || $char === '"') {
                $quote = $char;
                continue;
            }

            if ($char === '(') {
                $depth++;
                continue;
            }

            if ($char === ')') {
                $depth--;
                if (0 === $depth) {
                    return $index;
                }
            }
        }

        return false;
    }

    private function history_table_exists($table_name) {
        global $wpdb;

        $table_name = (string) $table_name;
        if (!preg_match('/^[A-Za-z0-9_]+$/', $table_name)) {
            return false;
        }

        $previous_suppress = $wpdb->suppress_errors(true);
        $found = $wpdb->get_var("SHOW CREATE TABLE `{$table_name}`");
        $wpdb->suppress_errors($previous_suppress);

        return is_string($found) && $found !== '';
    }

    private function prepare_user_id_in_sql($user_ids) {
        global $wpdb;

        $user_ids = array_values(array_unique(array_filter(array_map('intval', (array) $user_ids))));
        if (empty($user_ids)) {
            return '';
        }

        $placeholders = implode(',', array_fill(0, count($user_ids), '%d'));

        return $wpdb->prepare("{$wpdb->users}.ID IN ($placeholders)", $user_ids);
    }

    /**
     * Capture old meta value before update
     */
    public function capture_old_meta($meta_id, $user_id, $meta_key, $meta_value) {
        if (isset($this->tracked_meta[$meta_key])) {
            if (!isset($this->old_user_meta[$user_id])) {
                $this->old_user_meta[$user_id] = [];
            }
            $this->old_user_meta[$user_id][$meta_key] = get_user_meta($user_id, $meta_key, true);
        }
    }

    /**
     * Log user profile changes
     */
    public function log_user_changes($user_id, $old_user_data_param, $userdata) {
        $old_user = isset($this->old_user_data[$user_id]) ? $this->old_user_data[$user_id] : $old_user_data_param;

        if (!$old_user) {
            return;
        }

        $changed_by = get_current_user_id();

        foreach ($this->tracked_fields as $field => $label) {
            $old_value = '';
            $new_value = '';

            if ($field === 'user_pass') {
                $old_pass = '';
                if (is_object($old_user) && isset($old_user->user_pass)) {
                    $old_pass = $old_user->user_pass;
                } elseif (is_object($old_user) && isset($old_user->data->user_pass)) {
                    $old_pass = $old_user->data->user_pass;
                }

                $new_pass = isset($userdata['user_pass']) ? $userdata['user_pass'] : '';

                if (!empty($new_pass) && $old_pass !== $new_pass) {
                    $this->log_change($user_id, $changed_by, $field, $label, '', '', 'update', ['action' => 'password_change']);
                }
                continue;
            }

            if (is_object($old_user) && isset($old_user->$field)) {
                $old_value = $old_user->$field;
            } elseif (is_object($old_user) && isset($old_user->data->$field)) {
                $old_value = $old_user->data->$field;
            }

            if (isset($userdata[$field])) {
                $new_value = $userdata[$field];
            } else {
                $current_user = get_userdata($user_id);
                if ($current_user && isset($current_user->$field)) {
                    $new_value = $current_user->$field;
                }
            }

            if ($old_value !== $new_value) {
                $this->log_change($user_id, $changed_by, $field, $label, $old_value, $new_value, 'update');
            }
        }

        unset($this->old_user_data[$user_id]);
    }

    /**
     * Log meta field change
     */
    public function log_meta_change($meta_id, $user_id, $meta_key, $meta_value) {
        if (!isset($this->tracked_meta[$meta_key])) {
            return;
        }

        $old_value = isset($this->old_user_meta[$user_id][$meta_key])
            ? $this->old_user_meta[$user_id][$meta_key]
            : '';

        if ($meta_key === $this->capabilities_key) {
            if (isset($this->role_logged[$user_id])) {
                return;
            }

            if (!isset($this->pending_role_changes[$user_id])) {
                $this->pending_role_changes[$user_id] = [
                    'old_value'  => $this->format_capabilities($old_value),
                    'changed_by' => get_current_user_id(),
                ];
            }
            return;
        }

        if ($old_value !== $meta_value) {
            $this->log_change(
                $user_id,
                get_current_user_id(),
                $meta_key,
                $this->tracked_meta[$meta_key],
                is_array($old_value) ? wp_json_encode($old_value) : $old_value,
                is_array($meta_value) ? wp_json_encode($meta_value) : $meta_value,
                'update'
            );
        }

        if (isset($this->old_user_meta[$user_id][$meta_key])) {
            unset($this->old_user_meta[$user_id][$meta_key]);
        }
    }

    private function format_capabilities($caps) {
        if (is_string($caps)) {
            $caps = maybe_unserialize($caps);
        }

        if (!is_array($caps)) {
            return '';
        }

        $roles = array_keys(array_filter($caps));
        return implode(', ', $roles);
    }

    public function log_role_change($user_id, $role, $old_roles) {
        if (isset($this->role_logged[$user_id])) {
            return;
        }

        $old_role = !empty($old_roles) ? implode(', ', $old_roles) : '';
        $new_role = $role;

        if ($old_role === $new_role) {
            return;
        }

        $this->role_logged[$user_id] = true;

        $this->log_change(
            $user_id,
            get_current_user_id(),
            $this->capabilities_key,
            'Role',
            $old_role,
            $new_role,
            'update',
            ['action' => 'role_change']
        );
    }

    public function log_pending_role_changes() {
        foreach ($this->pending_role_changes as $user_id => $data) {
            if (isset($this->role_logged[$user_id])) {
                continue;
            }

            $current_caps = get_user_meta($user_id, $this->capabilities_key, true);
            $new_value = $this->format_capabilities($current_caps);

            if ($data['old_value'] !== $new_value) {
                $this->log_change(
                    $user_id,
                    $data['changed_by'],
                    $this->capabilities_key,
                    'Role',
                    $data['old_value'],
                    $new_value,
                    'update',
                    ['action' => 'role_change_deferred']
                );
            }
        }
    }

    public function log_user_creation($user_id, $userdata = []) {
        $user = get_userdata($user_id);
        if (!$user) {
            return;
        }

        $changed_by = get_current_user_id() ?: $user_id;

        $this->log_change(
            $user_id,
            $changed_by,
            'user_created',
            'Account Created',
            '',
            $user->user_email,
            'create',
            ['action' => 'user_created']
        );
    }

    private function log_change($user_id, $changed_by, $field_name, $field_label, $old_value, $new_value, $change_type = 'update', $context = []) {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $original_field_name = $field_name;
        $sanitized_field_name = sanitize_key($field_name);
        $normalized_label = sanitize_text_field($field_label);
        $sanitized_change_type = sanitize_key($change_type);

        $old_value_prepared = $this->prepare_value_for_storage($original_field_name, $old_value);
        $new_value_prepared = $this->prepare_value_for_storage($original_field_name, $new_value);

        $search_tokens = $this->build_search_tokens($original_field_name, $old_value, $new_value);
        $operator_snapshot = wp_json_encode($this->get_operator_snapshot($changed_by, $context));
        $operator_details = $this->encrypt_value($operator_snapshot);

        if ($this->should_force_log_change_failure($original_field_name, $sanitized_change_type, $context)) {
            error_log('User History: Simulated log insert failure for user ' . (int) $user_id);
            return false;
        }

        $inserted = $wpdb->insert(
            $table_name,
            [
                'user_id'             => (int) $user_id,
                'changed_by'          => (int) $changed_by,
                'field_name'          => $sanitized_field_name,
                'field_label'         => $normalized_label,
                'old_value'           => $old_value_prepared,
                'new_value'           => $new_value_prepared,
                'search_tokens'       => $search_tokens,
                'changed_by_details'  => $operator_details,
                'change_type'         => $sanitized_change_type,
                'created_at'          => current_time('mysql'),
            ],
            ['%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );

        if (false === $inserted) {
            error_log('User History: Failed to log change for user ' . (int) $user_id . ' - ' . $wpdb->last_error);
            return false;
        }

        return (int) $wpdb->insert_id;
    }

    public function get_user_history($user_id, $limit = 50, $offset = 0) {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table_name
                WHERE user_id = %d
                ORDER BY created_at DESC
                LIMIT %d OFFSET %d",
                $user_id,
                $limit,
                $offset
            )
        );

        return $results;
    }

    public function get_user_history_count($user_id) {
        if (!$this->user_can_manage_history($user_id)) {
            return 0;
        }

        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;

        return (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM $table_name WHERE user_id = %d",
                $user_id
            )
        );
    }

    public function enqueue_admin_assets($hook) {
        if (!in_array($hook, ['user-edit.php', 'profile.php'], true)) {
            return;
        }

        wp_enqueue_style(
            'user-history-admin',
            USER_HISTORY_PLUGIN_URL . 'assets/css/admin.css',
            [],
            USER_HISTORY_VERSION
        );

        wp_enqueue_script(
            'user-history-admin',
            USER_HISTORY_PLUGIN_URL . 'assets/js/admin.js',
            ['jquery'],
            USER_HISTORY_VERSION,
            true
        );

        $user_id = isset($_GET['user_id']) ? (int) $_GET['user_id'] : get_current_user_id();

        wp_localize_script('user-history-admin', 'userHistoryData', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('user_history_nonce'),
            'changeUsernameNonce' => wp_create_nonce('user_history_change_username'),
            'clearHistoryNonce' => wp_create_nonce('user_history_clear'),
            'userId'  => $user_id,
            'i18n'    => [
                'change'        => __('Change', 'user-history'),
                'cancel'        => __('Cancel', 'user-history'),
                'pleaseWait'    => __('Please wait...', 'user-history'),
                'errorGeneric'  => __('Something went wrong. Please try again.', 'user-history'),
                'confirmClear'  => __('Are you sure you want to clear all history for this user? This cannot be undone.', 'user-history'),
                'clearing'      => __('Clearing...', 'user-history'),
                'clearLog'      => __('Clear Log', 'user-history'),
                'loading'       => __('Loading...', 'user-history'),
                'loadMore'      => __('Load More', 'user-history'),
                'emptyLog'      => __('No changes have been recorded yet.', 'user-history'),
                'success'       => __('Success.', 'user-history'),
            ],
        ]);
    }

	/**
	* Nicename field rendering - now positioned in Name section after nickname
 	*/
    public function render_nicename_field($user) {
        if (!$this->current_operator_is_admin_role() || !current_user_can('edit_user', $user->ID)) {
            return;
        }

        	?>
				<tr class="user-history-nicename-wrap">
				<th scope="row">
					<label for="user_history_nicename"><?php esc_html_e('Nicename', 'user-history'); ?></label>
				</th>
				<td>
					<input type="text"
						   name="user_nicename"
						   id="user_history_nicename"
						   class="regular-text"
						   value="<?php echo esc_attr($user->user_nicename); ?>"
						   aria-describedby="user-history-nicename-description" />
					<p class="description" id="user-history-nicename-description">
						<?php esc_html_e('Must be unique, URL-friendly, and can only be changed by administrators.', 'user-history'); ?>
					</p>
				</td>
			</tr>

    	<?php
	}

    /**
     * Validate nicename submission
     */
    public function validate_nicename_submission($errors, $update, $user) {
        if (!$update || !isset($_POST['user_nicename'])) {
            return;
        }

        if (!$this->current_operator_is_admin_role() || !current_user_can('edit_user', $user->ID)) {
            $errors->add(
                'user_nicename_permission',
                sprintf(
                    '<strong>%s</strong>: %s',
                    esc_html__('Error', 'user-history'),
                    esc_html__('Only administrators can change the nicename.', 'user-history')
                ),
                ['form-field' => 'user_nicename']
            );
            return;
        }

        $sanitized = $this->sanitize_nicename_value(wp_unslash($_POST['user_nicename']));

        if ($sanitized === '') {
            $errors->add(
                'user_nicename_empty',
                sprintf(
                    '<strong>%s</strong>: %s',
                    esc_html__('Error', 'user-history'),
                    esc_html__('Please enter a nicename.', 'user-history')
                ),
                ['form-field' => 'user_nicename']
            );
            return;
        }

        if (!$this->is_nicename_unique($sanitized, $user->ID)) {
            $errors->add(
                'user_nicename_duplicate',
                sprintf(
                    '<strong>%s</strong>: %s',
                    esc_html__('Error', 'user-history'),
                    esc_html__('That nicename is already in use. Please choose another.', 'user-history')
                ),
                ['form-field' => 'user_nicename']
            );
            return;
        }

        $this->pending_nicename_values[$user->ID] = $sanitized;
    }

    /**
     * Persist nicename after validation
     */
    public function save_nicename_field($user_id) {
        if (!isset($_POST['user_nicename'])) {
            return;
        }

        if (!$this->current_operator_is_admin_role() || !current_user_can('edit_user', $user_id)) {
            return;
        }

        $sanitized = isset($this->pending_nicename_values[$user_id])
            ? $this->pending_nicename_values[$user_id]
            : $this->sanitize_nicename_value(wp_unslash($_POST['user_nicename']));

        if ($sanitized === '') {
            unset($this->pending_nicename_values[$user_id]);
            return;
        }

        if (!$this->is_nicename_unique($sanitized, $user_id)) {
            unset($this->pending_nicename_values[$user_id]);
            return;
        }

        $result = wp_update_user([
            'ID'            => $user_id,
            'user_nicename' => $sanitized,
        ]);

        unset($this->pending_nicename_values[$user_id]);

        if (is_wp_error($result)) {
            error_log('User History: Failed to update nicename for user ' . (int) $user_id . ' - ' . $result->get_error_message());
        }
    }

    /**
     * Display history section
     */
    public function display_history_section($user) {
        if (!$this->user_can_manage_history($user->ID)) {
            return;
        }

        $history = $this->filter_history_results($this->get_user_history($user->ID, 20));
        $total_count = $this->get_user_history_count($user->ID);
        ?>
        <div class="user-history-section">
            <h2><?php esc_html_e('Account History', 'user-history'); ?></h2>
            <p class="description">
                <?php esc_html_e('A log of changes made to this account.', 'user-history'); ?>
                <?php if ($total_count > 0): ?>
                    <span class="user-history-count">
                        <?php printf(
                            esc_html(_n('%d change recorded', '%d changes recorded', $total_count, 'user-history')),
                            (int) $total_count
                        ); ?>
                    </span>
                <?php endif; ?>
            </p>

            <div class="user-history-log" id="user-history-log" data-user-id="<?php echo esc_attr($user->ID); ?>">
                <?php if (empty($history)): ?>
                    <p class="user-history-empty">
                        <?php esc_html_e('No changes have been recorded yet.', 'user-history'); ?>
                    </p>
                <?php else: ?>
                    <table class="widefat user-history-table">
                        <thead>
                            <tr>
                                <th class="column-date"><?php esc_html_e('Date', 'user-history'); ?></th>
                                <th class="column-field"><?php esc_html_e('Field', 'user-history'); ?></th>
                                <th class="column-change"><?php esc_html_e('Change', 'user-history'); ?></th>
                                <th class="column-by"><?php esc_html_e('Changed By', 'user-history'); ?></th>
                            </tr>
                        </thead>
                        <tbody id="user-history-tbody">
                            <?php
                            echo $this->render_history_rows($history); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                            ?>
                        </tbody>
                    </table>

                    <div class="user-history-actions">
                        <?php if ($total_count > 20): ?>
                            <button type="button" class="button" id="user-history-load-more"
                                    data-offset="20" data-total="<?php echo esc_attr($total_count); ?>">
                                <?php esc_html_e('Load More', 'user-history'); ?>
                            </button>
                        <?php endif; ?>
                        <?php if ($this->current_operator_can_clear_history((int) $user->ID)): ?>
                        <button type="button" class="button user-history-clear-log" id="user-history-clear-log">
                            <?php esc_html_e('Clear Log', 'user-history'); ?>
                        </button>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    public function display_delete_user_button($user) {
        if (!$this->user_can_delete_account($user->ID)) {
            return;
        }

        if ($user->ID === get_current_user_id()) {
            return;
        }

        if (is_multisite() && is_super_admin($user->ID)) {
            return;
        }

        $delete_url = wp_nonce_url(
            admin_url('users.php?action=delete&user=' . $user->ID),
            'bulk-users'
        );
        ?>
        <div class="user-history-section user-history-delete-section">
            <h2><?php esc_html_e('Delete User', 'user-history'); ?></h2>
            <p class="description">
                <?php esc_html_e('Permanently delete this user account. You will be able to reassign their content to another user.', 'user-history'); ?>
            </p>
            <p>
                <a href="<?php echo esc_url($delete_url); ?>" class="button button-link-delete">
                    <?php esc_html_e('Delete User', 'user-history'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    public function render_history_rows($history) {
        $output = '';

        foreach ($history as $entry) {
            $changed_by_user = get_userdata($entry->changed_by);
            $changed_by_name = $changed_by_user ? $changed_by_user->display_name : __('Unknown', 'user-history');
            $changed_by_link = $changed_by_user ? get_edit_user_link($entry->changed_by) : '#';

            $is_self = ($entry->user_id == $entry->changed_by);

            $entry = $this->maybe_reencrypt_history_row($entry);
            $old_value = $this->prepare_value_for_display($entry->field_name, $entry->old_value);
            $new_value = $this->prepare_value_for_display($entry->field_name, $entry->new_value);

            $output .= '<tr class="user-history-entry type-' . esc_attr($entry->change_type) . '">';

            $output .= '<td class="column-date">';
            $output .= '<span class="history-date">' . esc_html(date_i18n(get_option('date_format'), strtotime($entry->created_at))) . '</span>';
            $output .= '<span class="history-time">' . esc_html(date_i18n(get_option('time_format'), strtotime($entry->created_at))) . '</span>';
            $output .= '</td>';

            $output .= '<td class="column-field">';
            $output .= '<strong>' . esc_html($entry->field_label) . '</strong>';
            $output .= '</td>';

            $output .= '<td class="column-change">';
            if ($entry->change_type === 'create') {
                $output .= '<span class="history-new-value">' . esc_html($this->truncate_value($new_value)) . '</span>';
            } elseif ($entry->field_name === 'user_pass') {
                $output .= '<span class="history-new-value">' . esc_html__('Changed', 'user-history') . '</span>';
            } else {
                if ($old_value !== '') {
                    $output .= '<span class="history-old-value">' . esc_html($this->truncate_value($old_value)) . '</span>';
                    $output .= ' <span class="history-arrow">&rarr;</span> ';
                }
                $output .= '<span class="history-new-value">' . esc_html($this->truncate_value($new_value)) . '</span>';
            }
            $output .= '</td>';

            $output .= '<td class="column-by">';
            if ($is_self) {
                $output .= '<span class="history-self">' . esc_html__('Self', 'user-history') . '</span>';
            } else {
                $output .= '<a href="' . esc_url($changed_by_link) . '">' . esc_html($changed_by_name) . '</a>';
            }
            $output .= '</td>';

            $output .= '</tr>';
        }

        return $output;
    }

    private function truncate_value($value, $length = 50) {
        if ($value === '') {
            return '';
        }

        if (mb_strlen($value, 'UTF-8') <= $length) {
            return $value;
        }

        return mb_substr($value, 0, $length, 'UTF-8') . '...';
    }

    public function ajax_load_more_history() {
        check_ajax_referer('user_history_nonce', 'nonce');

        if (!current_user_can('edit_users')) {
            wp_send_json_error(['message' => __('Unauthorized', 'user-history')]);
        }

        $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
        $offset = isset($_POST['offset']) ? (int) $_POST['offset'] : 0;

        if (!$user_id || !$this->user_can_manage_history($user_id)) {
            wp_send_json_error(['message' => __('You are not allowed to view this history.', 'user-history')]);
        }

        $history = $this->filter_history_results($this->get_user_history($user_id, 20, $offset));

        if (empty($history)) {
            wp_send_json_success(['html' => '', 'hasMore' => false]);
        }

        $html = $this->render_history_rows($history);
        $total = $this->get_user_history_count($user_id);
        $has_more = ($offset + 20) < $total;

        wp_send_json_success([
            'html'      => $html,
            'hasMore'   => $has_more,
            'newOffset' => $offset + 20,
        ]);
    }

    public function ajax_clear_history() {
        check_ajax_referer('user_history_clear', 'nonce');

        if (!current_user_can('edit_users')) {
            wp_send_json_error(['message' => __('Unauthorized', 'user-history')]);
        }

        $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;

        if (!$user_id || !$this->current_operator_can_clear_history($user_id)) {
            wp_send_json_error(['message' => __('You are not allowed to clear this history.', 'user-history')]);
        }

        if (!$this->history_table_supports_transactions()) {
            wp_send_json_error(['message' => __('History cannot be cleared because transactional storage is unavailable. No changes were saved.', 'user-history')]);
        }

        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;

        $transaction_started = $this->begin_required_transaction();
        if (!$transaction_started) {
            wp_send_json_error(['message' => __('Clearing failed because a transaction could not be started. No changes were saved.', 'user-history')]);
        }

        $deleted = $wpdb->delete(
            $table_name,
            ['user_id' => $user_id],
            ['%d']
        );

        if ($deleted === false) {
            $this->rollback_transaction($transaction_started);
            wp_send_json_error(['message' => __('Failed to clear history', 'user-history')]);
        }

        $log_success = $this->log_change(
            $user_id,
            get_current_user_id(),
            'user_history_maintenance',
            __('History Maintenance', 'user-history'),
            '',
            __('History log cleared by an operator.', 'user-history'),
            'maintenance',
            ['action' => 'history_clear']
        );

        if (!$log_success) {
            $this->rollback_transaction($transaction_started);
            wp_send_json_error(['message' => __('Clearing failed because the audit log could not be updated. No changes were saved.', 'user-history')]);
        }

        if (!$this->commit_transaction($transaction_started)) {
            $this->rollback_transaction($transaction_started);
            wp_send_json_error(['message' => __('Clearing failed because the transaction could not be completed. No changes were saved.', 'user-history')]);
        }

        wp_send_json_success([
            'message' => __('History cleared successfully', 'user-history'),
        ]);
    }

    public function ajax_change_username() {
        $response = [
            'success'   => false,
            'new_nonce' => wp_create_nonce('user_history_change_username'),
        ];

        if (!$this->current_operator_can_change_usernames()) {
            $response['message'] = __('You do not have permission to change usernames.', 'user-history');
            wp_send_json($response);
        }

        if (!check_ajax_referer('user_history_change_username', '_ajax_nonce', false)) {
            $response['message'] = __('Security check failed. Please refresh the page.', 'user-history');
            wp_send_json($response);
        }

        if (empty($_POST['new_username']) || empty($_POST['current_username'])) {
            $response['message'] = __('Invalid request.', 'user-history');
            wp_send_json($response);
        }

        $new_username = sanitize_user(trim(wp_unslash($_POST['new_username'])), true);
        $old_username = sanitize_user(trim(wp_unslash($_POST['current_username'])), true);

        $user_id = username_exists($old_username);
        if (!$user_id || !$this->user_can_manage_history($user_id)) {
            $response['message'] = __('Invalid request.', 'user-history');
            wp_send_json($response);
        }

        if ($new_username === $old_username) {
            $response['success'] = true;
            $response['message'] = __('Username unchanged.', 'user-history');
            wp_send_json($response);
        }

        if (mb_strlen($new_username, 'UTF-8') < 3 || mb_strlen($new_username, 'UTF-8') > 60) {
            $response['message'] = __('Username must be between 3 and 60 characters.', 'user-history');
            wp_send_json($response);
        }

        if (!validate_username($new_username)) {
            $response['message'] = __('This username contains invalid characters.', 'user-history');
            wp_send_json($response);
        }

        $illegal_logins = array_map('strtolower', (array) apply_filters('illegal_user_logins', []));
        if (in_array(strtolower($new_username), $illegal_logins, true)) {
            $response['message'] = __('Sorry, that username is not allowed.', 'user-history');
            wp_send_json($response);
        }

        if (username_exists($new_username)) {
            $response['message'] = sprintf(__('The username "%s" is already taken.', 'user-history'), esc_html($new_username));
            wp_send_json($response);
        }

        $result = $this->change_username($user_id, $old_username, $new_username);

        if (is_wp_error($result)) {
            $response['message'] = $result->get_error_message();
            wp_send_json($response);
        }

        $response['success'] = true;
        $response['message'] = sprintf(__('Username changed to "%s".', 'user-history'), esc_html($new_username));
        wp_send_json($response);
    }

    private function change_username($user_id, $old_username, $new_username) {
        global $wpdb;

        $user = get_userdata($user_id);
        if (!$user) {
            return new WP_Error('user_history_missing_user', __('User not found.', 'user-history'));
        }

        $original_identity = [
            'user_login'    => $user->user_login,
            'user_nicename' => $user->user_nicename,
            'display_name'  => $user->display_name,
        ];
        $expected_identity = [
            'user_login'    => $new_username,
            'user_nicename' => ($user->user_nicename === sanitize_title($old_username))
                ? sanitize_title($new_username)
                : $user->user_nicename,
            'display_name'  => ($user->display_name === $old_username)
                ? $new_username
                : $user->display_name,
        ];

        $mapping = $this->prepare_super_admin_mapping($old_username, $new_username);
        if (is_wp_error($mapping)) {
            return $mapping;
        }

        if (!$this->username_change_tables_support_transactions()) {
            return new WP_Error(
                'user_history_nontransactional',
                __('Username cannot be changed because transactional storage is unavailable.', 'user-history')
            );
        }

        $transaction_started = $this->begin_required_transaction();
        if (!$transaction_started) {
            return new WP_Error(
                'user_history_transaction_begin_failed',
                __('Username cannot be changed because a transaction could not be started.', 'user-history')
            );
        }

        $mapping_attempted = false;
        $identity_written = false;
        $audit_id = 0;

        if ($mapping['needs_update']) {
            $mapping_attempted = true;

            if (
                $this->should_force_username_change_failure('site_admins')
                || !$this->persist_super_admin_mapping($mapping['next'])
            ) {
                return $this->fail_username_change(
                    'user_history_super_admin_failed',
                    __('Failed to update super administrator mapping.', 'user-history'),
                    $transaction_started,
                    $user_id,
                    $original_identity,
                    $mapping,
                    $mapping_attempted,
                    $identity_written,
                    $audit_id
                );
            }
        }

        if ($this->should_force_username_change_failure('user_login')) {
            return $this->fail_username_change(
                'user_history_username_failed',
                __('Failed to update username.', 'user-history'),
                $transaction_started,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                $identity_written,
                $audit_id
            );
        }

        $updated = $wpdb->update(
            $wpdb->users,
            ['user_login' => $new_username],
            ['ID' => $user_id],
            ['%s'],
            ['%d']
        );

        if ($updated === false) {
            return $this->fail_username_change(
                'user_history_username_failed',
                __('Failed to update username.', 'user-history'),
                $transaction_started,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                $identity_written,
                $audit_id
            );
        }
        $identity_written = true;

        if ($expected_identity['user_nicename'] !== $original_identity['user_nicename']) {
            if ($this->should_force_username_change_failure('user_nicename')) {
                return $this->fail_username_change(
                    'user_history_nicename_failed',
                    __('Failed to update nicename.', 'user-history'),
                    $transaction_started,
                    $user_id,
                    $original_identity,
                    $mapping,
                    $mapping_attempted,
                    $identity_written,
                    $audit_id
                );
            }

            $nicename_update = $wpdb->update(
                $wpdb->users,
                ['user_nicename' => $expected_identity['user_nicename']],
                [
                    'ID'            => $user_id,
                    'user_nicename' => $original_identity['user_nicename'],
                ],
                ['%s'],
                ['%d', '%s']
            );

            if ($nicename_update === false) {
                return $this->fail_username_change(
                    'user_history_nicename_failed',
                    __('Failed to update nicename.', 'user-history'),
                    $transaction_started,
                    $user_id,
                    $original_identity,
                    $mapping,
                    $mapping_attempted,
                    $identity_written,
                    $audit_id
                );
            }
        }

        if ($expected_identity['display_name'] !== $original_identity['display_name']) {
            if ($this->should_force_username_change_failure('display_name')) {
                return $this->fail_username_change(
                    'user_history_display_failed',
                    __('Failed to update display name.', 'user-history'),
                    $transaction_started,
                    $user_id,
                    $original_identity,
                    $mapping,
                    $mapping_attempted,
                    $identity_written,
                    $audit_id
                );
            }

            $display_update = $wpdb->update(
                $wpdb->users,
                ['display_name' => $expected_identity['display_name']],
                [
                    'ID'           => $user_id,
                    'display_name' => $original_identity['display_name'],
                ],
                ['%s'],
                ['%d', '%s']
            );

            if ($display_update === false) {
                return $this->fail_username_change(
                    'user_history_display_failed',
                    __('Failed to update display name.', 'user-history'),
                    $transaction_started,
                    $user_id,
                    $original_identity,
                    $mapping,
                    $mapping_attempted,
                    $identity_written,
                    $audit_id
                );
            }
        }

        if ($this->should_force_username_change_failure('audit')) {
            return $this->fail_username_change(
                'user_history_log_failed',
                __('Unable to record audit trail. Username change aborted.', 'user-history'),
                $transaction_started,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                $identity_written,
                $audit_id
            );
        }

        $audit_id = $this->log_change(
            $user_id,
            get_current_user_id(),
            'user_login',
            'Username',
            $old_username,
            $new_username,
            'update',
            ['action' => 'username_change']
        );

        if (!$audit_id) {
            return $this->fail_username_change(
                'user_history_log_failed',
                __('Unable to record audit trail. Username change aborted.', 'user-history'),
                $transaction_started,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                $identity_written,
                $audit_id
            );
        }

        if (
            !$this->user_identity_matches($user_id, $expected_identity)
            || ($mapping['needs_update'] && !$this->super_admin_mapping_matches($mapping['next']))
        ) {
            return $this->fail_username_change(
                'user_history_verify_failed',
                __('Username change could not be verified and was reversed.', 'user-history'),
                $transaction_started,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                $identity_written,
                $audit_id
            );
        }

        if (!$this->commit_transaction($transaction_started)) {
            return $this->fail_username_change(
                'user_history_commit_failed',
                __('Username change could not be completed because the transaction failed and was reversed.', 'user-history'),
                $transaction_started,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                $identity_written,
                $audit_id
            );
        }

        if (
            !$this->user_identity_matches($user_id, $expected_identity)
            || ($mapping['needs_update'] && !$this->super_admin_mapping_matches($mapping['next']))
        ) {
            return $this->fail_username_change(
                'user_history_commit_verify_failed',
                __('Username change could not be verified and was reversed.', 'user-history'),
                false,
                $user_id,
                $original_identity,
                $mapping,
                $mapping_attempted,
                true,
                $audit_id
            );
        }

        clean_user_cache($user_id);

        do_action('user_history_username_changed', $user_id, $old_username, $new_username);

        return true;
    }

    /**
     * Build the intended super-administrator login list before mutating identity.
     */
    private function prepare_super_admin_mapping($old_username, $new_username) {
        if (!is_multisite()) {
            return [
                'needs_update' => false,
                'original'     => [],
                'next'         => [],
            ];
        }

        unset($GLOBALS['super_admins']);

        $original = array_values((array) get_site_option('site_admins', ['admin']));
        $key = array_search($old_username, $original, true);

        if ($key === false) {
            return [
                'needs_update' => false,
                'original'     => $original,
                'next'         => $original,
            ];
        }

        if (in_array($new_username, $original, true)) {
            return new WP_Error(
                'user_history_super_admin_conflict',
                __('That username is already listed as a super administrator.', 'user-history')
            );
        }

        $next = $original;
        $next[$key] = $new_username;

        return [
            'needs_update' => true,
            'original'     => $original,
            'next'         => array_values($next),
        ];
    }

    private function persist_super_admin_mapping($admins) {
        unset($GLOBALS['super_admins']);
        $admins = array_values((array) $admins);

        update_site_option('site_admins', $admins);
        $this->remember_super_admin_mapping($admins);

        return $this->super_admin_mapping_matches($admins);
    }

    private function remember_super_admin_mapping($admins) {
        $network_id = function_exists('get_current_network_id') ? get_current_network_id() : 1;
        $cache_key = $network_id . ':site_admins';

        wp_cache_delete($cache_key, 'site-options');
        wp_cache_set($cache_key, array_values((array) $admins), 'site-options');
    }

    private function super_admin_mapping_matches($expected) {
        unset($GLOBALS['super_admins']);

        $current = array_values((array) get_site_option('site_admins', ['admin']));
        $expected = array_values((array) $expected);

        return $current === $expected;
    }

    private function user_identity_matches($user_id, $expected) {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT user_login, user_nicename, display_name FROM {$wpdb->users} WHERE ID = %d",
                $user_id
            ),
            ARRAY_A
        );

        return is_array($row)
            && $row['user_login'] === $expected['user_login']
            && $row['user_nicename'] === $expected['user_nicename']
            && $row['display_name'] === $expected['display_name'];
    }

    private function restore_user_identity($user_id, $identity) {
        global $wpdb;

        $wpdb->update(
            $wpdb->users,
            [
                'user_login'    => $identity['user_login'],
                'user_nicename' => $identity['user_nicename'],
                'display_name'  => $identity['display_name'],
            ],
            ['ID' => $user_id],
            ['%s', '%s', '%s'],
            ['%d']
        );
    }

    private function delete_history_row($history_id) {
        global $wpdb;

        if ((int) $history_id < 1) {
            return;
        }

        $wpdb->delete(
            $wpdb->prefix . self::TABLE_NAME,
            ['id' => (int) $history_id],
            ['%d']
        );
    }

    private function should_force_username_change_failure($stage) {
        return (bool) apply_filters('user_history_force_username_change_failure', false, $stage);
    }

    private function should_force_log_change_failure($field_name, $change_type, $context) {
        return (bool) apply_filters('user_history_force_log_change_failure', false, $field_name, $change_type, $context);
    }

    private function should_force_transaction_failure($stage) {
        return (bool) apply_filters('user_history_force_transaction_failure', false, $stage);
    }

    private function fail_username_change(
        $code,
        $message,
        $transaction_started,
        $user_id,
        $original_identity,
        $mapping,
        $mapping_attempted,
        $identity_written,
        $audit_id
    ) {
        if (!$this->rollback_transaction($transaction_started) && $transaction_started) {
            error_log('User History: ROLLBACK failed while reversing a username change for user ' . (int) $user_id);
        }

        if ($audit_id && !$transaction_started) {
            $this->delete_history_row($audit_id);
        }

        if ($identity_written || $transaction_started) {
            $this->restore_user_identity($user_id, $original_identity);
        }

        if ($mapping_attempted) {
            $this->persist_super_admin_mapping($mapping['original']);
        }

        clean_user_cache($user_id);

        return new WP_Error($code, $message);
    }

    private function user_can_manage_history($user_id) {
        return current_user_can('edit_user', $user_id);
    }

    private function current_operator_can_clear_history($user_id) {
        return current_user_can(self::CLEAR_HISTORY_CAPABILITY)
            && current_user_can('edit_users')
            && $this->user_can_manage_history($user_id);
    }

    public function grant_history_capability_for_new_site($new_site) {
        $site_id = is_object($new_site) && isset($new_site->id) ? (int) $new_site->id : 0;
        if ($site_id < 1) {
            return;
        }

        switch_to_blog($site_id);
        $this->grant_history_management_capability();
        restore_current_blog();
    }

    private function grant_history_management_capability_on_activation() {
        if (is_multisite() && function_exists('get_sites')) {
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
                if (!$this->site_tables_are_available($site_id)) {
                    continue;
                }

                switch_to_blog($site_id);
                $this->grant_history_management_capability();
                restore_current_blog();
            }

            $this->grant_history_management_capability();
            return;
        }

        $this->grant_history_management_capability();
    }

    private function site_tables_are_available($site_id) {
        global $wpdb;

        $site_id = (int) $site_id;
        if ($site_id < 1) {
            return false;
        }

        return $this->history_table_exists($wpdb->get_blog_prefix($site_id) . 'options');
    }

    private function grant_history_management_capability() {
        $role = get_role('administrator');
        if ($role && !$role->has_cap(self::CLEAR_HISTORY_CAPABILITY)) {
            $role->add_cap(self::CLEAR_HISTORY_CAPABILITY);
        }
    }

    private function should_collect_operator_ip() {
        $collect = true;
        if (defined('USER_HISTORY_COLLECT_IP')) {
            $collect = (bool) USER_HISTORY_COLLECT_IP;
        }

        return (bool) apply_filters('user_history_collect_ip', $collect);
    }

    private function get_retention_days() {
        $days = (int) get_option('user_history_retention_days', 0);
        $days = (int) apply_filters('user_history_retention_days', $days);

        return max(0, $days);
    }

    private function maybe_schedule_retention_prune() {
        $hook = 'user_history_prune_history';
        $days = $this->get_retention_days();

        if ($days < 1) {
            $next = wp_next_scheduled($hook);
            if ($next) {
                wp_unschedule_event($next, $hook);
            }
            return;
        }

        if (!wp_next_scheduled($hook)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', $hook);
        }
    }

    /**
     * Remove history rows older than the configured retention window.
     *
     * Disabled unless user_history_retention_days or the matching filter is a positive integer.
     */
    public function prune_expired_history() {
        $days = $this->get_retention_days();
        if ($days < 1) {
            return 0;
        }

        if (!$this->history_table_supports_transactions()) {
            error_log('User History: Retention pruning skipped because transactional storage is unavailable.');
            return 0;
        }

        $transaction_started = $this->begin_required_transaction();
        if (!$transaction_started) {
            error_log('User History: Retention pruning skipped because a transaction could not be started.');
            return 0;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $cutoff = date('Y-m-d H:i:s', current_time('timestamp') - ($days * DAY_IN_SECONDS));

        $user_ids = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT DISTINCT user_id FROM $table_name WHERE created_at < %s",
                $cutoff
            )
        );

        $removed = 0;
        foreach (array_map('intval', (array) $user_ids) as $user_id) {
            if ($user_id < 1) {
                continue;
            }

            $deleted = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM $table_name WHERE user_id = %d AND created_at < %s",
                    $user_id,
                    $cutoff
                )
            );

            if ($deleted === false) {
                $this->rollback_transaction($transaction_started);
                error_log('User History: Retention pruning failed while deleting expired rows.');
                return 0;
            }

            if ((int) $deleted < 1) {
                continue;
            }

            $removed += (int) $deleted;
            $logged = $this->log_change(
                $user_id,
                get_current_user_id(),
                'user_history_maintenance',
                __('History Maintenance', 'user-history'),
                '',
                sprintf(
                    /* translators: %d: number of removed history rows */
                    _n('%d expired history record removed.', '%d expired history records removed.', (int) $deleted, 'user-history'),
                    (int) $deleted
                ),
                'maintenance',
                ['action' => 'history_retention']
            );

            if (!$logged) {
                $this->rollback_transaction($transaction_started);
                error_log('User History: Retention pruning failed because a maintenance event could not be written.');
                return 0;
            }
        }

        if (!$this->commit_transaction($transaction_started)) {
            $this->rollback_transaction($transaction_started);
            return 0;
        }

        return $removed;
    }

    public function register_privacy_exporter($exporters) {
        $exporters['user-history-log'] = [
            'exporter_friendly_name' => __('Account History', 'user-history'),
            'callback'               => [$this, 'export_personal_data'],
        ];

        return $exporters;
    }

    public function register_privacy_eraser($erasers) {
        $erasers['user-history-log'] = [
            'eraser_friendly_name' => __('Account History', 'user-history'),
            'callback'             => [$this, 'erase_personal_data'],
        ];

        return $erasers;
    }

    public function export_personal_data($email_address, $page = 1) {
        $user = get_user_by('email', $email_address);
        if (!$user) {
            return [
                'data' => [],
                'done' => true,
            ];
        }

        $page = max(1, (int) $page);
        $per_page = 50;
        $history = $this->get_user_history($user->ID, $per_page, ($page - 1) * $per_page);
        $data = [];

        foreach ((array) $history as $entry) {
            $old_value = $this->prepare_value_for_display($entry->field_name, $entry->old_value);
            $new_value = $this->prepare_value_for_display($entry->field_name, $entry->new_value);
            $data[] = [
                'group_id'    => 'user-history-log',
                'group_label' => __('Account History', 'user-history'),
                'item_id'     => 'user-history-' . (int) $entry->id,
                'data'        => [
                    [
                        'name'  => __('Field', 'user-history'),
                        'value' => (string) $entry->field_label,
                    ],
                    [
                        'name'  => __('Previous value', 'user-history'),
                        'value' => $old_value,
                    ],
                    [
                        'name'  => __('New value', 'user-history'),
                        'value' => $new_value,
                    ],
                    [
                        'name'  => __('Changed at', 'user-history'),
                        'value' => (string) $entry->created_at,
                    ],
                ],
            ];
        }

        return [
            'data' => $data,
            'done' => count($history) < $per_page,
        ];
    }

    public function erase_personal_data($email_address, $page = 1) {
        unset($page);

        $user = get_user_by('email', $email_address);
        if (!$user) {
            return [
                'items_removed'  => false,
                'items_retained' => false,
                'messages'       => [],
                'done'           => true,
            ];
        }

        if (!(bool) apply_filters('user_history_erase_personal_data', false, $user->ID, $email_address)) {
            return [
                'items_removed'  => false,
                'items_retained' => true,
                'messages'       => [
                    __('Account history is retained as an audit record unless an operator explicitly allows personal-data erasure.', 'user-history'),
                ],
                'done'           => true,
            ];
        }

        $removed = $this->erase_user_history_for_privacy((int) $user->ID);

        return [
            'items_removed'  => $removed > 0,
            'items_retained' => false,
            'messages'       => [],
            'done'           => true,
        ];
    }

    private function erase_user_history_for_privacy($user_id) {
        if (!$this->history_table_supports_transactions()) {
            return 0;
        }

        $transaction_started = $this->begin_required_transaction();
        if (!$transaction_started) {
            return 0;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $deleted = $wpdb->delete($table_name, ['user_id' => (int) $user_id], ['%d']);

        if ($deleted === false) {
            $this->rollback_transaction($transaction_started);
            return 0;
        }

        $logged = $this->log_change(
            $user_id,
            get_current_user_id(),
            'user_history_maintenance',
            __('History Maintenance', 'user-history'),
            '',
            __('History log erased through a personal-data request.', 'user-history'),
            'maintenance',
            ['action' => 'history_privacy_erase']
        );

        if (!$logged || !$this->commit_transaction($transaction_started)) {
            $this->rollback_transaction($transaction_started);
            return 0;
        }

        return (int) $deleted;
    }

    /**
     * Username changes affect the network-global users table on multisite.
     */
    private function current_operator_can_change_usernames() {
        if (!current_user_can('edit_users')) {
            return false;
        }

        if (!is_multisite()) {
            return true;
        }

        return is_super_admin(get_current_user_id()) && current_user_can('manage_network_users');
    }

    private function user_can_delete_account($user_id) {
        return current_user_can('delete_user', $user_id) && $this->user_can_manage_history($user_id);
    }

    private function filter_history_results($history) {
        if (empty($history) || !is_array($history)) {
            return [];
        }

        return array_values(array_filter($history, function ($entry) {
            return isset($entry->user_id) && $this->user_can_manage_history((int) $entry->user_id);
        }));
    }

    /**
     * Convert the plugin history table to InnoDB when the live engine is not transactional.
     */
    private function ensure_history_table_engine() {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;
        if ($this->table_uses_required_engine($table_name, false)) {
            return true;
        }

        if (!preg_match('/^[A-Za-z0-9_]+$/', $table_name)) {
            error_log('User History: Refusing to alter history table with unexpected name.');
            return false;
        }

        $wpdb->query("ALTER TABLE `{$table_name}` ENGINE=InnoDB");

        if (!$this->table_uses_required_engine($table_name, false)) {
            error_log('User History: History table is not using InnoDB. Destructive actions will be refused.');
            return false;
        }

        return true;
    }

    private function history_table_supports_transactions() {
        global $wpdb;

        $this->ensure_history_table_engine();

        return $this->table_uses_required_engine($wpdb->prefix . self::TABLE_NAME);
    }

    private function username_change_tables_support_transactions() {
        global $wpdb;

        $this->ensure_history_table_engine();

        return $this->table_uses_required_engine($wpdb->prefix . self::TABLE_NAME)
            && $this->table_uses_required_engine($wpdb->users);
    }

    private function table_uses_required_engine($table_name, $apply_filter = true) {
        return (strcasecmp($this->get_table_engine($table_name, $apply_filter), 'InnoDB') === 0);
    }

    private function get_table_engine($table_name, $apply_filter = true) {
        global $wpdb;

        $engine = '';

        if (preg_match('/^[A-Za-z0-9_]+$/', (string) $table_name)) {
            $previous_suppress = $wpdb->suppress_errors(true);
            $create_table = $wpdb->get_row("SHOW CREATE TABLE `{$table_name}`", ARRAY_N);
            $wpdb->suppress_errors($previous_suppress);

            if (is_array($create_table) && isset($create_table[1]) && is_string($create_table[1])) {
                if (preg_match('/\bENGINE=([A-Za-z0-9_]+)/i', $create_table[1], $matches)) {
                    $engine = $matches[1];
                }
            }
        }

        if ($engine === '') {
            $status = $wpdb->get_row(
                $wpdb->prepare('SHOW TABLE STATUS WHERE Name = %s', $table_name)
            );
            if (is_object($status) && isset($status->Engine) && is_string($status->Engine)) {
                $engine = $status->Engine;
            }
        }

        if ($engine === '') {
            $engine = $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s LIMIT 1',
                    $table_name
                )
            );
            $engine = is_string($engine) ? $engine : '';
        }

        if ($apply_filter) {
            $engine = apply_filters('user_history_table_engine', $engine, $table_name);
        }

        return is_string($engine) ? $engine : '';
    }

    private function begin_required_transaction() {
        if ($this->should_force_transaction_failure('begin')) {
            return false;
        }

        global $wpdb;
        $result = $wpdb->query('START TRANSACTION');
        return (false !== $result);
    }

    private function commit_transaction($transaction_started) {
        if (!$transaction_started) {
            return false;
        }

        if ($this->should_force_transaction_failure('commit')) {
            return false;
        }

        global $wpdb;
        $result = $wpdb->query('COMMIT');
        if (false === $result) {
            error_log('User History: COMMIT failed - ' . $wpdb->last_error);
            return false;
        }

        return true;
    }

    private function rollback_transaction($transaction_started) {
        if (!$transaction_started) {
            return false;
        }

        global $wpdb;
        $result = $wpdb->query('ROLLBACK');
        if (false === $result) {
            error_log('User History: ROLLBACK failed - ' . $wpdb->last_error);
            return false;
        }

        return true;
    }

    private function is_field_sensitive($field_name) {
        $field = sanitize_key($field_name);
        return in_array($field, $this->sensitive_fields, true);
    }

    private function normalize_for_storage($value) {
        if (is_array($value)) {
            $value = wp_json_encode($value);
        }

        $value = (string) $value;
        $value = wp_unslash($value);
        $normalized = preg_replace('/\s+/u', ' ', trim($value));

        return is_string($normalized) ? $normalized : '';
    }

    private function normalize_for_display($value) {
        $value = (string) $value;
        return preg_replace('/\s+/u', ' ', trim($value));
    }

    private function prepare_value_for_storage($field_name, $value) {
        if ($value === null || $value === '') {
            return '';
        }

        if ($this->is_searchable_field($field_name) && !$this->search_value_is_within_limit($value)) {
            $normalized = self::OVERSIZED_VALUE_PLACEHOLDER;
        } else {
            $normalized = $this->normalize_for_storage($value);
        }

        if ($normalized === '') {
            return '';
        }

        if ($this->is_field_sensitive($field_name)) {
            return $this->encrypt_value($normalized);
        }

        return $normalized;
    }

    private function prepare_value_for_display($field_name, $value) {
        if ($value === null || $value === '') {
            return '';
        }

        $prepared = $value;

        if ($this->is_field_sensitive($field_name)) {
            $prepared = $this->decrypt_value($value);
        }

        return $this->normalize_for_display($prepared);
    }

    private function encrypt_value($value) {
        $value = $this->normalize_for_storage($value);

        if ($value === '') {
            return '';
        }

        $version = $this->get_current_key_version();
        $key = $this->get_encryption_key_for_version($version);
        $backend = $this->preferred_crypto_backend();
        $payload = '';

        if ($backend === 'nacl') {
            $payload = $this->encrypt_secretbox($value, $key);
        } elseif ($backend === 'gcm') {
            $payload = $this->encrypt_aes_gcm($value, $key);
        }

        if ($payload === '') {
            error_log('User History: Authenticated encryption failed.');
            return '';
        }

        return $this->format_crypto_envelope($backend, $version, $payload);
    }

    private function decrypt_value($value) {
        $opened = $this->open_stored_ciphertext($value);

        if ($opened['status'] === 'empty') {
            return '';
        }

        if ($opened['status'] === 'ok') {
            return $opened['plain'];
        }

        return $this->crypto_failure_placeholder($opened['status']);
    }

    /**
     * Increment the stored key version and keep the previous version for decrypt only.
     */
    public function rotate_encryption_key() {
        $this->ensure_encryption_key_version();

        $current = $this->get_stored_key_version();
        $retired = $this->get_retired_key_versions();
        $retired[] = $current;
        update_option(self::CRYPTO_OPTION_RETIRED, array_values(array_unique($retired)));
        update_option(self::CRYPTO_OPTION_VERSION, $current + 1);
        delete_option(self::CRYPTO_OPTION_CURRENT);
        $this->encryption_keys = [];
        $this->maybe_migrate_encryption();

        return $this->get_stored_key_version();
    }

    private function maybe_migrate_encryption() {
        $this->ensure_encryption_key_version();

        $generation = $this->crypto_generation_token();
        if (get_option(self::CRYPTO_OPTION_CURRENT, '') === $generation) {
            return;
        }

        for ($batch = 0; $batch < 20; $batch++) {
            $processed = $this->reencrypt_stale_history_rows(self::CRYPTO_MIGRATION_BATCH);
            if (0 === $processed) {
                update_option(self::CRYPTO_OPTION_CURRENT, $generation);
                return;
            }
        }
    }

    private function ensure_encryption_key_version() {
        $version = (int) get_option(self::CRYPTO_OPTION_VERSION, 0);
        if ($version < self::CRYPTO_DEFAULT_VERSION) {
            update_option(self::CRYPTO_OPTION_VERSION, self::CRYPTO_DEFAULT_VERSION);
        }
    }

    private function get_stored_key_version() {
        $version = (int) get_option(self::CRYPTO_OPTION_VERSION, self::CRYPTO_DEFAULT_VERSION);
        return $version >= self::CRYPTO_DEFAULT_VERSION ? $version : self::CRYPTO_DEFAULT_VERSION;
    }

    private function get_current_key_version() {
        $this->ensure_encryption_key_version();
        return $this->get_stored_key_version();
    }

    private function get_retired_key_versions() {
        return array_values(array_unique(array_map('intval', (array) get_option(self::CRYPTO_OPTION_RETIRED, []))));
    }

    private function known_key_versions() {
        $known = array_merge(
            [self::CRYPTO_LEGACY_VERSION, $this->get_stored_key_version()],
            $this->get_retired_key_versions()
        );

        return array_values(array_unique(array_map('intval', (array) apply_filters('user_history_known_key_versions', $known))));
    }

    private function is_known_key_version($version) {
        return in_array((int) $version, $this->known_key_versions(), true);
    }

    private function crypto_generation_token() {
        return $this->preferred_crypto_backend() . ':' . $this->get_stored_key_version();
    }

    private function preferred_crypto_backend() {
        $forced = apply_filters('user_history_encryption_backend', '');
        if ($forced === 'nacl' && $this->supports_secretbox()) {
            return 'nacl';
        }
        if ($forced === 'gcm' && $this->supports_aes_gcm()) {
            return 'gcm';
        }

        if ($this->supports_secretbox()) {
            return 'nacl';
        }

        if ($this->supports_aes_gcm()) {
            return 'gcm';
        }

        return '';
    }

    private function supports_secretbox() {
        return function_exists('sodium_crypto_secretbox')
            && function_exists('sodium_crypto_secretbox_open')
            && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')
            && defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES');
    }

    private function supports_aes_gcm() {
        if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt') || !function_exists('openssl_get_cipher_methods')) {
            return false;
        }

        $methods = array_map('strtolower', openssl_get_cipher_methods());
        return in_array('aes-256-gcm', $methods, true);
    }

    private function format_crypto_envelope($cipher, $version, $payload) {
        return self::CRYPTO_ENVELOPE . ':' . $cipher . ':' . (int) $version . ':' . $payload;
    }

    private function open_stored_ciphertext($value) {
        if ($value === null || $value === '') {
            return ['status' => 'empty'];
        }

        $value = (string) $value;
        if (strpos($value, self::CRYPTO_ENVELOPE . ':') === 0) {
            $parts = explode(':', $value, 4);
            if (count($parts) !== 4 || $parts[0] !== self::CRYPTO_ENVELOPE || $parts[3] === '' || !preg_match('/^\d+$/', $parts[2])) {
                return ['status' => 'decrypt'];
            }

            $cipher = $parts[1];
            $version = (int) $parts[2];
            if (!$this->is_known_key_version($version)) {
                return ['status' => 'unknown_key'];
            }

            $plain = $this->decrypt_authenticated_payload($cipher, $parts[3], $this->get_encryption_key_for_version($version));
            if ($plain === false) {
                return ['status' => 'decrypt'];
            }

            return [
                'status'    => 'ok',
                'plain'     => $plain,
                'reencrypt' => ($version !== $this->get_current_key_version() || $cipher !== $this->preferred_crypto_backend()),
            ];
        }

        $plain = $this->decrypt_legacy_cbc($value);
        if ($plain === false) {
            return ['status' => 'decrypt'];
        }

        return [
            'status'    => 'ok',
            'plain'     => $plain,
            'reencrypt' => true,
        ];
    }

    private function encrypt_secretbox($value, $key) {
        if (!$this->supports_secretbox() || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return '';
        }

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        } catch (Exception $e) {
            error_log('User History encryption error: ' . $e->getMessage());
            return '';
        }

        $cipher = sodium_crypto_secretbox((string) $value, $nonce, $key);
        return base64_encode($nonce . $cipher);
    }

    private function encrypt_aes_gcm($value, $key) {
        if (!$this->supports_aes_gcm()) {
            return '';
        }

        $iv_length = openssl_cipher_iv_length('aes-256-gcm');
        if (!$iv_length) {
            return '';
        }

        try {
            $iv = random_bytes($iv_length);
        } catch (Exception $e) {
            error_log('User History encryption error: ' . $e->getMessage());
            return '';
        }

        $tag = '';
        $encrypted = openssl_encrypt($value, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false || $tag === '') {
            return '';
        }

        return base64_encode($iv . $tag . $encrypted);
    }

    private function decrypt_authenticated_payload($cipher, $payload, $key) {
        $decoded = base64_decode($payload, true);
        if ($decoded === false || $decoded === '') {
            return false;
        }

        if ($cipher === 'nacl') {
            return $this->decrypt_secretbox($decoded, $key);
        }

        if ($cipher === 'gcm') {
            return $this->decrypt_aes_gcm($decoded, $key);
        }

        return false;
    }

    private function decrypt_secretbox($decoded, $key) {
        if (!$this->supports_secretbox() || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return false;
        }

        $nonce_length = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
        if (strlen($decoded) <= $nonce_length) {
            return false;
        }

        $nonce = substr($decoded, 0, $nonce_length);
        $cipher = substr($decoded, $nonce_length);
        $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);

        return $plain === false ? false : $plain;
    }

    private function decrypt_aes_gcm($decoded, $key) {
        if (!$this->supports_aes_gcm()) {
            return false;
        }

        $iv_length = openssl_cipher_iv_length('aes-256-gcm');
        $tag_length = 16;
        if (!$iv_length || strlen($decoded) <= ($iv_length + $tag_length)) {
            return false;
        }

        $iv = substr($decoded, 0, $iv_length);
        $tag = substr($decoded, $iv_length, $tag_length);
        $cipher = substr($decoded, $iv_length + $tag_length);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

        return $plain === false ? false : $plain;
    }

    private function decrypt_legacy_cbc($value) {
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            return false;
        }

        $iv_length = openssl_cipher_iv_length('aes-256-cbc');
        if (!$iv_length || strlen($decoded) <= $iv_length) {
            return false;
        }

        $iv = substr($decoded, 0, $iv_length);
        $cipher = substr($decoded, $iv_length);
        $plain = openssl_decrypt($cipher, 'aes-256-cbc', $this->get_encryption_key_for_version(self::CRYPTO_LEGACY_VERSION), OPENSSL_RAW_DATA, $iv);

        return $plain === false ? false : $plain;
    }

    private function get_legacy_derived_key() {
        $salt = wp_salt('auth');
        $site_key = get_site_option('siteurl', home_url('/'));

        return hash('sha256', $salt . 'user-history' . $site_key, true);
    }

    private function get_versioned_key_material() {
        if (defined('USER_HISTORY_ENCRYPTION_KEY') && is_string(USER_HISTORY_ENCRYPTION_KEY) && USER_HISTORY_ENCRYPTION_KEY !== '') {
            return USER_HISTORY_ENCRYPTION_KEY;
        }

        return wp_salt('auth') . 'user-history' . get_site_option('siteurl', home_url('/'));
    }

    private function get_encryption_key_for_version($version) {
        $version = (int) $version;
        if (isset($this->encryption_keys[$version])) {
            return $this->encryption_keys[$version];
        }

        if ($version === self::CRYPTO_LEGACY_VERSION) {
            $this->encryption_keys[$version] = $this->get_legacy_derived_key();
            return $this->encryption_keys[$version];
        }

        $this->encryption_keys[$version] = hash('sha256', $this->get_versioned_key_material() . '|k' . $version, true);
        return $this->encryption_keys[$version];
    }

    private function crypto_failure_placeholder($reason) {
        if ($reason === 'unknown_key') {
            return __('[history unavailable: unknown key version]', 'user-history');
        }

        return __('[history unavailable: decryption failed]', 'user-history');
    }

    private function maybe_reencrypt_history_row($entry) {
        if (!is_object($entry)) {
            return $entry;
        }

        $updates = [];
        $fields = [
            'old_value'           => $this->is_field_sensitive(isset($entry->field_name) ? $entry->field_name : ''),
            'new_value'           => $this->is_field_sensitive(isset($entry->field_name) ? $entry->field_name : ''),
            'changed_by_details'  => true,
        ];

        foreach ($fields as $column => $eligible) {
            if (!$eligible || !isset($entry->{$column}) || $entry->{$column} === '') {
                continue;
            }

            $opened = $this->open_stored_ciphertext($entry->{$column});
            if ($opened['status'] !== 'ok' || empty($opened['reencrypt'])) {
                continue;
            }

            $reencrypted = $this->encrypt_value($opened['plain']);
            if ($reencrypted === '' || $reencrypted === $entry->{$column}) {
                continue;
            }

            $entry->{$column} = $reencrypted;
            $updates[$column] = $reencrypted;
        }

        if (empty($updates) || empty($entry->id)) {
            return $entry;
        }

        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . self::TABLE_NAME,
            $updates,
            ['id' => (int) $entry->id],
            array_fill(0, count($updates), '%s'),
            ['%d']
        );

        return $entry;
    }

    private function reencrypt_stale_history_rows($limit = 100) {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $version = $this->get_current_key_version();
        $nacl_prefix = $wpdb->esc_like($this->format_crypto_envelope('nacl', $version, '')) . '%';
        $gcm_prefix = $wpdb->esc_like($this->format_crypto_envelope('gcm', $version, '')) . '%';

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id, field_name, old_value, new_value, changed_by_details
                FROM $table_name
                WHERE changed_by_details != ''
                  AND changed_by_details NOT LIKE %s
                  AND changed_by_details NOT LIKE %s
                ORDER BY id ASC
                LIMIT %d",
                $nacl_prefix,
                $gcm_prefix,
                (int) $limit
            )
        );

        if (empty($rows)) {
            return 0;
        }

        foreach ($rows as $row) {
            $this->maybe_reencrypt_history_row($row);
        }

        return count($rows);
    }

    private function build_search_tokens($field_name, $old_value, $new_value) {
        if (!$this->is_searchable_field($field_name)) {
            return '';
        }

        $token_sets = [
            $this->tokenize_for_search($old_value, self::MAX_SEARCH_TOKEN_COUNT),
            $this->tokenize_for_search($new_value, self::MAX_SEARCH_TOKEN_COUNT),
        ];
        $hashed_tokens = [];
        $serialized_bytes = 0;

        for ($index = 0; $index < self::MAX_SEARCH_TOKEN_COUNT; $index++) {
            $found_token = false;
            foreach ($token_sets as $tokens) {
                if (!isset($tokens[$index])) {
                    continue;
                }

                $found_token = true;
                $token = $tokens[$index];
                $hash = $this->hash_token($token);

                if (isset($hashed_tokens[$hash])) {
                    continue;
                }

                $separator_bytes = empty($hashed_tokens) ? 0 : 1;
                $additional_bytes = $separator_bytes + strlen($hash);

                if (
                    count($hashed_tokens) >= self::MAX_SEARCH_TOKEN_COUNT
                    || $serialized_bytes + $additional_bytes > self::MAX_SEARCH_TOKEN_BYTES
                ) {
                    break 2;
                }

                $hashed_tokens[$hash] = true;
                $serialized_bytes += $additional_bytes;
            }

            if (!$found_token) {
                break;
            }
        }

        return implode('|', array_keys($hashed_tokens));
    }

    private function hash_tokens_from_term($term) {
        $tokens = $this->tokenize_for_search($term, self::MAX_SEARCH_QUERY_TOKENS);

        if (empty($tokens)) {
            return [];
        }

        return array_map([$this, 'hash_token'], $tokens);
    }

    private function tokenize_for_search($value, $max_tokens = self::MAX_SEARCH_TOKEN_COUNT) {
        if ($max_tokens < 1 || !$this->search_value_is_within_limit($value)) {
            return [];
        }

        $normalized = mb_strtolower($this->normalize_for_storage($value), 'UTF-8');

        if ($normalized === '') {
            return [];
        }

        $tokens = [];
        $tokens[$normalized] = true;

        $words = preg_split('/\s+/u', $normalized);
        foreach ($words as $word) {
            $word = trim($word);
            if ($word === '') {
                continue;
            }

            $tokens[$word] = true;
            if (count($tokens) >= $max_tokens) {
                break;
            }

            $length = mb_strlen($word, 'UTF-8');
            for ($i = 0; $i <= $length - 3; $i++) {
                $tokens[mb_substr($word, $i, 3, 'UTF-8')] = true;
                if (count($tokens) >= $max_tokens) {
                    break 2;
                }
            }
        }

        return array_keys($tokens);
    }

    private function is_searchable_field($field_name) {
        return in_array(sanitize_key($field_name), $this->searchable_fields, true);
    }

    private function search_value_is_within_limit($value) {
        if (!is_scalar($value)) {
            return false;
        }

        return strlen((string) $value) <= self::MAX_SEARCHABLE_VALUE_BYTES;
    }

    private function hash_token($token) {
        return hash('sha256', $this->get_legacy_derived_key() . '|' . $token);
    }

    private function get_operator_snapshot($user_id, $context = []) {
        $snapshot = [
            'operator_id' => (int) $user_id,
            'timestamp'   => current_time('mysql'),
            'ip'          => $this->should_collect_operator_ip() && isset($_SERVER['REMOTE_ADDR'])
                ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']))
                : '',
        ];

        if ($user_id) {
            $user = get_userdata($user_id);
            if ($user) {
                $snapshot['user_login'] = $user->user_login;
                $snapshot['display_name'] = $user->display_name;
                $snapshot['roles'] = $user->roles;
            }
        } else {
            $snapshot['user_login'] = 'system';
        }

        return array_merge($snapshot, $context);
    }

    /**
     * Determine if current operator has administrator role
     */
    private function current_operator_is_admin_role() {
        $user = wp_get_current_user();
        if (!$user || empty($user->roles)) {
            return false;
        }

        $roles = array_map('strtolower', (array) $user->roles);
        $allowed = array_map('strtolower', $this->admin_role_slugs);

        return (bool) array_intersect($allowed, $roles);
    }

    /**
     * Sanitize nicename value
     */
    private function sanitize_nicename_value($value) {
        if ($value === null) {
            return '';
        }

        $sanitized = sanitize_title($value);
        return trim($sanitized);
    }

    /**
     * Check nicename uniqueness
     */
    private function is_nicename_unique($nicename, $user_id) {
        global $wpdb;

        $existing = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT ID FROM $wpdb->users WHERE user_nicename = %s AND ID <> %d",
                $nicename,
                $user_id
            )
        );

        return empty($existing);
    }
}

// Initialize the plugin
User_History::get_instance();
