<?php

use PHPUnit\Framework\TestCase;

final class PluginSourceSecurityTest extends TestCase
{
    private string $source;

    protected function setUp(): void
    {
        $this->source = file_get_contents(dirname(__DIR__, 2) . '/wp-user-history-logging.php');
    }

    public function test_direct_web_access_is_blocked_before_plugin_code_runs(): void
    {
        $guard_position = strpos($this->source, "if (!defined('ABSPATH'))");
        $class_position = strpos($this->source, 'class User_History');

        $this->assertNotFalse($guard_position);
        $this->assertNotFalse($class_position);
        $this->assertLessThan($class_position, $guard_position);
    }

    public function test_ajax_actions_are_authenticated_only(): void
    {
        $this->assertStringContainsString('wp_ajax_load_more_user_history', $this->source);
        $this->assertStringContainsString('wp_ajax_user_history_change_username', $this->source);
        $this->assertStringContainsString('get_admin_username_error', $this->source);
        $this->assertStringContainsString('wp_ajax_clear_user_history', $this->source);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $this->source);

        $settings = $this->settingsSource();
        $this->assertStringContainsString('wp_ajax_user_history_clear_all_logs', $settings);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $settings);

        $lock = $this->lockSource();
        $this->assertStringContainsString("wp_ajax_' . self::AJAX_ACTION", $lock);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $lock);
        $this->assertStringNotContainsString('ipinfo.io', $lock);
        $this->assertStringNotContainsString('TRUNCATE', $lock);
        $this->assertStringContainsString("defined('WP_CLI') && WP_CLI", $lock);
        $this->assertStringContainsString('current_operator_can_lock_user', $lock);

        $login = $this->loginSource();
        $this->assertStringContainsString("wp_ajax_' . self::DESTROY_ACTION", $login);
        $this->assertStringContainsString("wp_ajax_' . self::LOAD_PAGES_ACTION", $login);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $login);
        $this->assertStringContainsString('attach_session_information', $login);
        $this->assertStringContainsString('set_logged_in_cookie', $login);
        $this->assertStringContainsString('HTTP_CF_CONNECTING_IP', $login);
        $this->assertStringContainsString('HTTP_X_REAL_IP', $login);
        $this->assertStringContainsString('HTTP_X_FORWARDED_FOR', $login);
        $this->assertStringContainsString('FILTER_FLAG_NO_PRIV_RANGE', $login);
        $this->assertStringNotContainsString('user_history_collect_ip', $login);
        $this->assertStringNotContainsString('ipinfo.io', $login);
        $this->assertStringNotContainsString('TRUNCATE', $login);
        $this->assertStringContainsString("get_option(self::OPTION_KEY, '0')", $login);
        $this->assertStringContainsString('current_operator_can_destroy_sessions', $login);
        $this->assertStringContainsString('parse_user_agent', $login);

        $dashboard = $this->dashboardSource();
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $dashboard);
        $this->assertStringNotContainsString('ipinfo.io', $dashboard);
        $this->assertStringNotContainsString('TRUNCATE', $dashboard);
        $this->assertStringNotContainsString('is_plugin_active', $dashboard);
        $this->assertStringContainsString("get_option(self::OPTION_ENABLED, '0')", $dashboard);
        $this->assertStringContainsString('current_operator_can_enable', $dashboard);
        $this->assertStringContainsString("current_user_can('manage_options')", $dashboard);
        $this->assertStringContainsString('maybe_import_rda_settings', $dashboard);
        $this->assertStringContainsString('should_restrict_ajax_request', $dashboard);
        $this->assertStringContainsString('request_matches_allowlist', $dashboard);

        $usernames = $this->usernameSource();
        $this->assertStringContainsString("wp_ajax_' . self::TEST_ACTION", $usernames);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $usernames);
        $this->assertStringNotContainsString('ipinfo.io', $usernames);
        $this->assertStringNotContainsString('TRUNCATE', $usernames);
        $this->assertStringNotContainsString('is_plugin_active', $usernames);
        $this->assertStringContainsString("get_option(self::OPTION_ENABLED, '0')", $usernames);
        $this->assertStringContainsString("apply_filters('user_history_validate_username'", $usernames);
        $this->assertStringContainsString('get_admin_username_error', $usernames);
        $this->assertStringContainsString('maybe_import_restrict_usernames_settings', $usernames);
        $this->assertStringContainsString('createTextNode', $usernames);
        $this->assertStringNotContainsString('innerHTML', $usernames);

        $newNicename = $this->newUserNicenameSource();
        $this->assertStringContainsString("if (!defined('ABSPATH'))", $newNicename);
        $this->assertStringContainsString("add_filter('wp_pre_insert_user_data'", $newNicename);
        $this->assertStringContainsString('if ($update || !is_array($data))', $newNicename);
        $this->assertStringContainsString('sanitize_nicename_value', $newNicename);
        $this->assertStringContainsString('is_nicename_unique', $newNicename);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $newNicename);
        $this->assertStringNotContainsString('TRUNCATE', $newNicename);
        $this->assertStringNotContainsString('ipinfo.io', $newNicename);
        $this->assertStringNotContainsString('wp_update_user', $newNicename);
        $this->assertStringNotContainsString('get_users', $newNicename);
        $this->assertStringContainsString('nicename_for_existing_user', $newNicename);

        $rewrite = $this->nicenameRewriteSource();
        $this->assertStringContainsString("if (!defined('ABSPATH'))", $rewrite);
        $this->assertStringContainsString("current_user_can('edit_users')", $rewrite);
        $this->assertStringContainsString("current_user_can('manage_network_users')", $rewrite);
        $this->assertStringContainsString("current_user_can('edit_user'", $rewrite);
        $this->assertStringContainsString('wp_verify_nonce', $rewrite);
        $this->assertStringContainsString('user_history_nicename_rewrite_preview', $rewrite);
        $this->assertStringContainsString('user_history_nicename_rewrite_confirm', $rewrite);
        $this->assertStringContainsString("add_action('load-users.php'", $rewrite);
        $this->assertStringContainsString('REQUEST_METHOD', $rewrite);
        $this->assertStringContainsString('nicename_matches_login', $rewrite);
        $this->assertStringContainsString('nicename_for_existing_user', $rewrite);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $rewrite);
        $this->assertStringNotContainsString('TRUNCATE', $rewrite);
        $this->assertStringNotContainsString('innerHTML', $rewrite);
        $this->assertStringNotContainsString('ipinfo.io', $rewrite);
        $this->assertStringContainsString('boot_nicename_rewrite', $this->source);
        $this->assertStringContainsString('class-nicename-rewrite.php', $this->source);

        $activity = $this->activitySource();
        $this->assertStringContainsString("wp_ajax_' . self::CLEAR_ACTION", $activity);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $activity);
        $this->assertStringNotContainsString('ipinfo.io', $activity);
        $this->assertStringNotContainsString('TRUNCATE', $activity);
        $this->assertStringContainsString("get_option(self::OPTION_ENABLED, '0')", $activity);
        $this->assertStringContainsString('ENGINE=InnoDB', $activity);
        $this->assertStringContainsString('user_history_user_locked', $activity);
        $this->assertStringContainsString('user_history_user_unlocked', $activity);
        $this->assertStringContainsString('user_history_username_changed', $activity);
        $this->assertStringContainsString('REMOTE_ADDR', $activity);
        $this->assertStringNotContainsString('HTTP_X_FORWARDED_FOR', $activity);
        $this->assertStringNotContainsString('HTTP_CF_CONNECTING_IP', $activity);
        $this->assertStringNotContainsString('HTTP_X_REAL_IP', $activity);
        $this->assertStringNotContainsString('HTTP_X_FORWARDED_FOR', $this->source);
        $this->assertStringNotContainsString('HTTP_CF_CONNECTING_IP', $this->source);
        $this->assertStringNotContainsString('HTTP_X_REAL_IP', $this->source);
        $this->assertStringNotContainsString('innerHTML', $activity);

        $updater = $this->updaterSource();
        $this->assertStringContainsString("if (!defined('ABSPATH'))", $updater);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $updater);
        $this->assertStringNotContainsString('->setAuthentication(', $updater);
        $this->assertStringNotContainsString('TRUNCATE', $updater);
        $this->assertStringContainsString('https://github.com/technoogies/wp-user-history-log', $updater);
    }

    public function test_plugin_has_no_outbound_http_calls(): void
    {
        $http_pattern = '/\b(?:wp_remote_(?:get|post|request)|curl_exec|file_get_contents\s*\(\s*[\'"]https?:)/';
        $this->assertDoesNotMatchRegularExpression($http_pattern, $this->source);

        $root = dirname(__DIR__, 2);
        $first_party = array_merge(
            [$root . '/uninstall.php'],
            glob($root . '/includes/*.php') ?: []
        );

        foreach ($first_party as $file) {
            $contents = file_get_contents($file);
            $this->assertNotFalse($contents);
            $this->assertDoesNotMatchRegularExpression(
                $http_pattern,
                $contents,
                basename($file) . ' must not add outbound HTTP calls'
            );
        }
    }

    public function test_history_table_creation_requires_innodb(): void
    {
        $this->assertMatchesRegularExpression('/CREATE TABLE[\s\S]*ENGINE=InnoDB/', $this->source);
        $this->assertStringContainsString('ensure_history_table_engine', $this->source);
        $this->assertStringContainsString('begin_required_transaction', $this->source);
        $this->assertStringNotContainsString('maybe_begin_transaction', $this->source);
    }

    public function test_historical_search_does_not_append_an_outer_or(): void
    {
        $this->assertStringContainsString('insert_historical_ids_into_search_group', $this->source);
        $this->assertStringNotContainsString('$query->query_where .= " OR', $this->source);
    }

    public function test_new_history_writes_use_authenticated_encryption(): void
    {
        $this->assertStringContainsString('sodium_crypto_secretbox', $this->source);
        $this->assertStringContainsString('aes-256-gcm', $this->source);
        $this->assertStringContainsString("CRYPTO_ENVELOPE = 'uh1'", $this->source);
        $this->assertStringContainsString('decrypt_legacy_cbc', $this->source);
    }

    public function test_clear_history_requires_dedicated_capability(): void
    {
        $this->assertStringContainsString("CLEAR_HISTORY_CAPABILITY = 'manage_user_history'", $this->source);
        $this->assertStringContainsString('current_operator_can_clear_history', $this->source);
        $this->assertStringContainsString('grant_history_management_capability', $this->source);
        $this->assertStringContainsString('wp_privacy_personal_data_exporters', $this->source);
        $this->assertStringContainsString('wp_privacy_personal_data_erasers', $this->source);
        $this->assertStringContainsString("apply_filters('user_history_erase_personal_data', false", $this->source);
        $this->assertStringContainsString("get_option('user_history_retention_days', 0)", $this->source);
        $this->assertDoesNotMatchRegularExpression(
            "/get_option\(\s*'user_history_retention_days'\s*,\s*30/",
            $this->source
        );
        $this->assertStringNotContainsString('TRUNCATE', $this->source);
    }

    public function test_settings_module_keeps_fork_defaults_and_clear_all_guards(): void
    {
        $settings = $this->settingsSource();

        $this->assertStringContainsString("if (!defined('ABSPATH'))", $settings);
        $this->assertMatchesRegularExpression("/'default'\s*=>\s*0/", $settings);
        $this->assertDoesNotMatchRegularExpression(
            "/user_history_retention_days',\s*30/",
            $settings
        );
        $this->assertStringNotContainsString('TRUNCATE', $settings);
        $this->assertStringContainsString("MENU_SLUG = 'user-history'", $settings);
        $this->assertStringContainsString('User_History_Activity_Log::MENU_SLUG', $settings);
        $this->assertStringContainsString('User_History_Dashboard_Access::MENU_SLUG', $settings);
        $this->assertStringContainsString('User_History_Username_Restrictions::MENU_SLUG', $settings);
        $this->assertStringContainsString('CLEAR_HISTORY_CAPABILITY', $settings);
        $this->assertStringContainsString('0 means keep history forever', $settings);
        $this->assertStringContainsString("get_option('user_history_collect_ip', '1')", $settings);
        $this->assertStringContainsString("get_option(User_History_Login_Tracker::OPTION_KEY, '0')", $settings);
        $this->assertDoesNotMatchRegularExpression(
            "/user_history_login_tracking_enabled',\s*'1'/",
            $settings
        );
        $this->assertStringNotContainsString('user_history_disable_staff_gravatar', $settings);
        $this->assertStringNotContainsString('Turn off Gravatar and profile photos for staff', $settings);
    }

    public function test_profile_photo_is_per_user_and_off_until_checked(): void
    {
        $photos = $this->profilePhotoSource();

        $this->assertStringContainsString("if (!defined('ABSPATH'))", $photos);
        $this->assertStringContainsString("META_KEY = 'user_history_disable_gravatar'", $photos);
        $this->assertStringContainsString('get_user_meta($user_id, self::META_KEY, true)', $photos);
        $this->assertStringContainsString("apply_filters('user_history_disable_gravatar'", $photos);
        $this->assertStringContainsString("includes_url('images/blank.gif')", $photos);
        $this->assertStringContainsString("add_action('show_user_profile'", $photos);
        $this->assertStringContainsString("add_action('edit_user_profile'", $photos);
        $this->assertStringContainsString("current_user_can('edit_user', \$user_id)", $photos);
        $this->assertStringNotContainsString('CREATE TABLE', $photos);
        $this->assertStringNotContainsString('TRUNCATE', $photos);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $photos);
        $this->assertStringNotContainsString('gravatar.com', $photos);
        $this->assertStringNotContainsString('add_role', $photos);
        $this->assertStringNotContainsString('is_staff', $photos);
        $this->assertStringContainsString('boot_profile_photo', $this->source);
        $this->assertStringContainsString('class-profile-photo.php', $this->source);
        $this->assertStringNotContainsString('boot_staff_avatars', $this->source);
        $this->assertStringNotContainsString('class-staff-avatars.php', $this->source);

        $uninstall = file_get_contents(dirname(__DIR__, 2) . '/uninstall.php');
        $this->assertNotFalse($uninstall);
        $this->assertStringContainsString("delete_metadata('user', 0, 'user_history_disable_gravatar', '', true)", $uninstall);
        $this->assertStringNotContainsString('user_history_disable_staff_gravatar', $uninstall);
    }

    public function test_staff_notes_are_private_user_meta_without_a_new_table(): void
    {
        $notes = $this->staffNotesSource();

        $this->assertStringContainsString("if (!defined('ABSPATH'))", $notes);
        $this->assertStringContainsString("META_NOTE = 'user_history_staff_note'", $notes);
        $this->assertStringContainsString("META_TAG = 'user_history_staff_tag'", $notes);
        $this->assertStringContainsString("current_user_can('edit_users')", $notes);
        $this->assertStringContainsString("current_user_can('edit_user', \$user_id)", $notes);
        $this->assertStringContainsString("add_filter('views_users'", $notes);
        $this->assertStringContainsString("add_filter('users_list_table_query_args'", $notes);
        $this->assertStringContainsString('wp_privacy_personal_data_exporters', $notes);
        $this->assertStringContainsString('wp_privacy_personal_data_erasers', $notes);
        $this->assertStringNotContainsString('CREATE TABLE', $notes);
        $this->assertStringNotContainsString('TRUNCATE', $notes);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $notes);
        $this->assertStringNotContainsString('wp_ajax_', $notes);
        $this->assertStringNotContainsString('ipinfo.io', $notes);
        $this->assertStringContainsString('boot_staff_notes', $this->source);
        $this->assertStringContainsString('class-staff-notes.php', $this->source);
        $this->assertStringContainsString('boot_profile_photo', $this->source);
        $this->assertStringContainsString('boot_nicename_rewrite', $this->source);

        $uninstall = file_get_contents(dirname(__DIR__, 2) . '/uninstall.php');
        $this->assertNotFalse($uninstall);
        $this->assertStringContainsString("delete_metadata('user', 0, 'user_history_staff_note', '', true)", $uninstall);
        $this->assertStringContainsString("delete_metadata('user', 0, 'user_history_staff_tag', '', true)", $uninstall);
        $this->assertStringContainsString("delete_metadata('user', 0, 'user_history_disable_gravatar', '', true)", $uninstall);
    }

    public function test_user_directory_is_read_only_and_capability_gated(): void
    {
        $directory = $this->userDirectorySource();

        $this->assertStringContainsString("if (!defined('ABSPATH'))", $directory);
        $this->assertStringContainsString("META_LAST_LOGIN = 'user_history_last_login'", $directory);
        $this->assertStringContainsString("add_action('wp_login'", $directory);
        $this->assertStringContainsString('update_user_meta($user_id, self::META_LAST_LOGIN', $directory);
        $this->assertSame(1, substr_count($directory, 'update_user_meta('));
        $this->assertStringContainsString("add_filter('manage_users_columns'", $directory);
        $this->assertStringContainsString('function query_site_users(', $directory);
        $this->assertStringContainsString('return $this->query_site_users();', $directory);
        $this->assertStringContainsString('$rows = $this->query_site_users();', $directory);
        $this->assertStringContainsString('$this->send_csv($this->export_rows());', $directory);
        $this->assertStringContainsString('current_operator_can_export', $directory);
        $this->assertStringContainsString('User_History::CLEAR_HISTORY_CAPABILITY', $directory);
        $this->assertStringContainsString("current_user_can('list_users')", $directory);
        $this->assertStringContainsString('wp_verify_nonce', $directory);
        $this->assertStringContainsString("'blog_id' => get_current_blog_id()", $directory);
        $this->assertStringContainsString("admin_post_' . self::EXPORT_ACTION", $directory);
        $this->assertStringNotContainsString('admin_post_nopriv_', $directory);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $directory);
        $this->assertStringNotContainsString('wp_ajax_', $directory);
        $this->assertStringNotContainsString('user_history_login_tracking_enabled', $directory);
        $this->assertStringContainsString("\$key === 'user_history_locked'", $directory);
        $this->assertStringNotContainsString('user_history_toggle_lock', $directory);
        $this->assertStringNotContainsString('user_pass', $directory);
        $this->assertStringNotContainsString('user_history_staff_note', $directory);
        $this->assertStringNotContainsString('wp_update_user', $directory);
        $this->assertStringNotContainsString('wp_delete_user', $directory);
        $this->assertStringNotContainsString('wp_insert_user', $directory);
        $this->assertStringNotContainsString('CREATE TABLE', $directory);
        $this->assertStringNotContainsString('TRUNCATE', $directory);
        $this->assertStringNotContainsString('ipinfo.io', $directory);
        $this->assertStringNotContainsString('innerHTML', $directory);
        $this->assertStringNotContainsString('HTTP_X_FORWARDED_FOR', $directory);
        $this->assertStringContainsString('wp_privacy_personal_data_exporters', $directory);
        $this->assertStringContainsString('wp_privacy_personal_data_erasers', $directory);
        $this->assertStringContainsString('delete_user_meta($user_id, self::META_LAST_LOGIN)', $directory);
        $this->assertStringContainsString('boot_user_directory', $this->source);
        $this->assertStringContainsString('class-user-directory.php', $this->source);
        $this->assertStringContainsString('boot_staff_notes', $this->source);
        $this->assertStringContainsString('boot_profile_photo', $this->source);
        $this->assertStringContainsString('boot_nicename_rewrite', $this->source);

        $uninstall = file_get_contents(dirname(__DIR__, 2) . '/uninstall.php');
        $this->assertNotFalse($uninstall);
        $this->assertStringContainsString("delete_metadata('user', 0, 'user_history_last_login', '', true)", $uninstall);
    }

    public function test_uninstall_does_not_wipe_history_by_default(): void
    {
        $uninstall = file_get_contents(dirname(__DIR__, 2) . '/uninstall.php');

        $this->assertNotFalse($uninstall);
        $this->assertStringContainsString("if (!defined('WP_UNINSTALL_PLUGIN'))", $uninstall);
        $this->assertStringContainsString('USER_HISTORY_DELETE_DATA_ON_UNINSTALL', $uninstall);
        $this->assertStringContainsString('user_history_delete_data_on_uninstall', $uninstall);
        $this->assertStringContainsString('if (!$delete_data)', $uninstall);
    }

    public function test_nicename_policy_uses_capabilities_instead_of_role_slugs(): void
    {
        $this->assertStringContainsString('current_operator_can_change_nicename', $this->source);
        $this->assertStringContainsString("current_user_can('edit_users')", $this->source);
        $this->assertStringNotContainsString('admin_role_slugs', $this->source);
        $this->assertStringNotContainsString('current_operator_is_admin_role', $this->source);
        $this->assertDoesNotMatchRegularExpression(
            "/array_intersect\s*\(\s*\$allowed/",
            $this->source
        );
    }

    public function test_raw_error_details_are_only_logged_through_the_debug_helper(): void
    {
        $this->assertStringContainsString('log_internal_event', $this->source);
        $this->assertDoesNotMatchRegularExpression(
            '/error_log\([^;]*\$wpdb->last_error/',
            $this->source
        );
        $this->assertDoesNotMatchRegularExpression(
            '/error_log\([^;]*get_error_message\s*\(/',
            $this->source
        );
        $this->assertDoesNotMatchRegularExpression(
            '/error_log\([^;]*getMessage\s*\(/',
            $this->source
        );
    }

    public function test_plugin_header_version_matches_readme_stable_tag(): void
    {
        $readme = file_get_contents(dirname(__DIR__, 2) . '/readme.txt');

        $this->assertNotFalse($readme);
        $this->assertSame(1, preg_match('/^\s*\*\s*Version:\s*(.+)$/m', $this->source, $plugin));
        $this->assertSame(1, preg_match('/^Stable tag:\s*(.+)$/m', $readme, $stable));
        $this->assertSame(trim($plugin[1]), trim($stable[1]));
    }

    public function test_empty_history_notice_uses_text_nodes_instead_of_html_sink(): void
    {
        $script = file_get_contents(dirname(__DIR__, 2) . '/assets/js/admin.js');

        $this->assertNotFalse($script);
        $this->assertStringContainsString('createTextNode', $script);
        $this->assertStringContainsString("createElement('p')", $script);
        $this->assertStringNotContainsString('.html(', $script);
        $this->assertStringNotContainsString('innerHTML', $script);
    }

    public function test_nicename_field_is_placed_under_nickname(): void
    {
        $script = file_get_contents(dirname(__DIR__, 2) . '/assets/js/admin.js');
        $styles = file_get_contents(dirname(__DIR__, 2) . '/assets/css/admin.css');

        $this->assertNotFalse($script);
        $this->assertNotFalse($styles);
        $this->assertStringContainsString("add_action('personal_options'", $this->source);
        $this->assertStringContainsString('user-history-nicename-wrap', $this->source);
        $this->assertStringContainsString('placeNicenameField', $script);
        $this->assertStringContainsString('user-nickname-wrap', $script);
        $this->assertStringContainsString('insertAfter', $script);
        $this->assertStringContainsString('.user-history-nicename-wrap:not(.user-history-nicename-placed)', $styles);
        $this->assertStringContainsString('initClearAllLogs', $script);
        $this->assertStringContainsString('initClearActivityLog', $script);
        $this->assertStringContainsString('user_history_clear_all_logs', $script);
        $this->assertStringContainsString('user_history_clear_activity_log', $script);
        $this->assertStringContainsString('placeNicenameField', $script);
        $this->assertStringContainsString('initLockToggle', $script);
        $this->assertStringContainsString('initHistoryTabs', $script);
        $this->assertStringContainsString('initDestroySessions', $script);
        $this->assertStringContainsString('placeNicenameField', $script);
        $this->assertStringContainsString('User_History_New_User_Nicename', $this->source);
        $this->assertStringContainsString('boot_new_user_nicename', $this->source);
        $this->assertStringContainsString('User_History_Update_Checker', $this->source);
        $this->assertStringContainsString('boot_update_checker', $this->source);
    }

    private function settingsSource(): string
    {
        $settings = file_get_contents(dirname(__DIR__, 2) . '/includes/class-settings.php');
        $this->assertNotFalse($settings);

        return $settings;
    }

    private function lockSource(): string
    {
        $lock = file_get_contents(dirname(__DIR__, 2) . '/includes/class-lock.php');
        $this->assertNotFalse($lock);

        return $lock;
    }

    private function loginSource(): string
    {
        $login = file_get_contents(dirname(__DIR__, 2) . '/includes/class-login-tracker.php');
        $this->assertNotFalse($login);

        return $login;
    }

    private function dashboardSource(): string
    {
        $dashboard = file_get_contents(dirname(__DIR__, 2) . '/includes/class-dashboard-access.php');
        $this->assertNotFalse($dashboard);

        return $dashboard;
    }

    private function usernameSource(): string
    {
        $usernames = file_get_contents(dirname(__DIR__, 2) . '/includes/class-username-restrictions.php');
        $this->assertNotFalse($usernames);

        return $usernames;
    }

    private function activitySource(): string
    {
        $activity = file_get_contents(dirname(__DIR__, 2) . '/includes/class-activity-log.php');
        $this->assertNotFalse($activity);

        return $activity;
    }

    private function nicenameRewriteSource(): string
    {
        $rewrite = file_get_contents(dirname(__DIR__, 2) . '/includes/class-nicename-rewrite.php');
        $this->assertNotFalse($rewrite);

        return $rewrite;
    }

    private function newUserNicenameSource(): string
    {
        $nicename = file_get_contents(dirname(__DIR__, 2) . '/includes/class-new-user-nicename.php');
        $this->assertNotFalse($nicename);

        return $nicename;
    }

    private function profilePhotoSource(): string
    {
        $photos = file_get_contents(dirname(__DIR__, 2) . '/includes/class-profile-photo.php');
        $this->assertNotFalse($photos);

        return $photos;
    }

    private function staffNotesSource(): string
    {
        $notes = file_get_contents(dirname(__DIR__, 2) . '/includes/class-staff-notes.php');
        $this->assertNotFalse($notes);

        return $notes;
    }

    private function userDirectorySource(): string
    {
        $directory = file_get_contents(dirname(__DIR__, 2) . '/includes/class-user-directory.php');
        $this->assertNotFalse($directory);

        return $directory;
    }

    private function updaterSource(): string
    {
        $updater = file_get_contents(dirname(__DIR__, 2) . '/includes/class-update-checker.php');
        $this->assertNotFalse($updater);

        return $updater;
    }
}
