<?php

final class UsernameChangeAtomicityTest extends WP_Ajax_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        User_History::get_instance()->activate();
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_audit_write_failure_leaves_single_site_identity_unchanged(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $target = self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_login'    => 'single-audit-target',
                'display_name'  => 'single-audit-target',
                'user_nicename' => 'single-audit-target',
            ]
        );

        wp_set_current_user($administrator);
        $original_identity = $this->identity($target);
        $original_history = $this->usernameHistoryCount($target);

        $filter = static function ($force, $stage) {
            return $stage === 'audit' ? true : $force;
        };
        add_filter('user_history_force_username_change_failure', $filter, 10, 2);

        try {
            $response = $this->changeUsername('single-audit-target', 'single-audit-renamed');
        } finally {
            remove_filter('user_history_force_username_change_failure', $filter, 10);
        }

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_history, $this->usernameHistoryCount($target));
        $this->assertFalse(username_exists('single-audit-renamed'));
    }

    public function test_login_write_failure_leaves_single_site_identity_unchanged(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $target = self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_login'    => 'single-login-target',
                'display_name'  => 'single-login-target',
                'user_nicename' => 'single-login-target',
            ]
        );

        wp_set_current_user($administrator);
        $original_identity = $this->identity($target);

        $filter = static function ($force, $stage) {
            return $stage === 'user_login' ? true : $force;
        };
        add_filter('user_history_force_username_change_failure', $filter, 10, 2);

        try {
            $response = $this->changeUsername('single-login-target', 'single-login-renamed');
        } finally {
            remove_filter('user_history_force_username_change_failure', $filter, 10);
        }

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($target));
        $this->assertFalse(username_exists('single-login-renamed'));
    }

    private function changeUsername($current_username, $new_username): array
    {
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => wp_create_nonce('user_history_change_username'),
            'current_username' => $current_username,
            'new_username'     => $new_username,
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    private function identity($user_id): array
    {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT user_login, user_nicename, display_name FROM {$wpdb->users} WHERE ID = %d",
                $user_id
            ),
            ARRAY_A
        );
    }

    private function usernameHistoryCount($user_id): int
    {
        global $wpdb;

        return (int) $wpdb->get_var(
            $wpdb->prepare(
                'SELECT COUNT(*) FROM ' . $wpdb->prefix . User_History::TABLE_NAME . ' WHERE user_id = %d AND field_name = %s',
                $user_id,
                'user_login'
            )
        );
    }
}
