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
        $this->assertStringContainsString('wp_ajax_clear_user_history', $this->source);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $this->source);
    }

    public function test_plugin_has_no_outbound_http_calls(): void
    {
        $this->assertDoesNotMatchRegularExpression(
            '/\b(?:wp_remote_(?:get|post|request)|curl_exec|file_get_contents\s*\(\s*[\'"]https?:)/',
            $this->source
        );
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
}
