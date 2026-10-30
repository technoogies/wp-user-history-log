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
}
