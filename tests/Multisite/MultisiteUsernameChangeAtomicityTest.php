<?php

final class MultisiteUsernameChangeAtomicityTest extends WP_Ajax_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        User_History::get_instance()->activate();
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_super_admin_rename_updates_mapping_and_keeps_privilege(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login'    => 'mapped-super-admin',
                'display_name'  => 'mapped-super-admin',
                'user_nicename' => 'mapped-super-admin',
            ]
        );
        grant_super_admin($target);

        wp_set_current_user($operator);
        $original_mapping = $this->currentMapping();

        $response = $this->changeUsername('mapped-super-admin', 'mapped-super-renamed');

        $this->assertTrue($response['success']);
        $this->assertSame('mapped-super-renamed', $this->identity($target)['user_login']);
        $this->assertSame('mapped-super-renamed', $this->identity($target)['display_name']);
        $this->assertSame('mapped-super-renamed', $this->identity($target)['user_nicename']);
        $this->assertFalse(username_exists('mapped-super-admin'));
        $this->assertContains('mapped-super-renamed', $this->currentMapping());
        $this->assertNotContains('mapped-super-admin', $this->currentMapping());
        $this->assertTrue(is_super_admin($target));
        $this->assertSame(count($original_mapping), count($this->currentMapping()));
        $this->assertGreaterThan(0, $this->usernameHistoryCount($target));
    }

    public function test_non_super_admin_rename_leaves_mapping_unchanged(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login'    => 'ordinary-network-user',
                'display_name'  => 'ordinary-network-user',
                'user_nicename' => 'ordinary-network-user',
            ]
        );

        wp_set_current_user($operator);
        $original_mapping = $this->currentMapping();

        $response = $this->changeUsername('ordinary-network-user', 'ordinary-network-renamed');

        $this->assertTrue($response['success']);
        $this->assertSame('ordinary-network-renamed', $this->identity($target)['user_login']);
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertFalse(is_super_admin($target));
        $this->assertFalse(username_exists('ordinary-network-user'));
    }

    public function test_site_admins_update_failure_leaves_identity_mapping_and_audit_unchanged(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login'    => 'mapping-failure-admin',
                'display_name'  => 'mapping-failure-admin',
                'user_nicename' => 'mapping-failure-admin',
            ]
        );
        grant_super_admin($target);

        wp_set_current_user($operator);
        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();
        $original_history = $this->usernameHistoryCount($target);

        $this->withForcedFailure('site_admins', function () {
            $response = $this->changeUsername('mapping-failure-admin', 'mapping-failure-renamed');
            $this->assertFalse($response['success']);
        });

        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertSame($original_history, $this->usernameHistoryCount($target));
        $this->assertTrue(is_super_admin($target));
        $this->assertFalse(username_exists('mapping-failure-renamed'));
    }

    public function test_user_login_write_failure_restores_super_admin_mapping(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login'    => 'login-failure-admin',
                'display_name'  => 'login-failure-admin',
                'user_nicename' => 'login-failure-admin',
            ]
        );
        grant_super_admin($target);

        wp_set_current_user($operator);
        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();
        $original_history = $this->usernameHistoryCount($target);

        $this->withForcedFailure('user_login', function () {
            $response = $this->changeUsername('login-failure-admin', 'login-failure-renamed');
            $this->assertFalse($response['success']);
        });

        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertSame($original_history, $this->usernameHistoryCount($target));
        $this->assertTrue(is_super_admin($target));
        $this->assertFalse(username_exists('login-failure-renamed'));
    }

    public function test_audit_write_failure_restores_identity_and_mapping(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login'    => 'audit-failure-admin',
                'display_name'  => 'audit-failure-admin',
                'user_nicename' => 'audit-failure-admin',
            ]
        );
        grant_super_admin($target);

        wp_set_current_user($operator);
        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();
        $original_history = $this->usernameHistoryCount($target);

        $this->withForcedFailure('audit', function () {
            $response = $this->changeUsername('audit-failure-admin', 'audit-failure-renamed');
            $this->assertFalse($response['success']);
        });

        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertSame($original_history, $this->usernameHistoryCount($target));
        $this->assertTrue(is_super_admin($target));
        $this->assertFalse(username_exists('audit-failure-renamed'));
    }

    public function test_nicename_write_failure_restores_identity_and_mapping(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login'    => 'nicename-failure-admin',
                'display_name'  => 'nicename-failure-admin',
                'user_nicename' => 'nicename-failure-admin',
            ]
        );
        grant_super_admin($target);

        wp_set_current_user($operator);
        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();

        $this->withForcedFailure('user_nicename', function () {
            $response = $this->changeUsername('nicename-failure-admin', 'nicename-failure-renamed');
            $this->assertFalse($response['success']);
        });

        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertFalse(username_exists('nicename-failure-renamed'));
    }

    private function createNetworkOperator(): int
    {
        $operator = self::factory()->user->create(
            [
                'user_login' => 'atomic-network-operator-' . wp_generate_password(6, false),
            ]
        );
        grant_super_admin($operator);

        return $operator;
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

    private function withForcedFailure($stage, $callback): void
    {
        $filter = static function ($force, $failure_stage) use ($stage) {
            return $failure_stage === $stage ? true : $force;
        };

        add_filter('user_history_force_username_change_failure', $filter, 10, 2);

        try {
            $callback();
        } finally {
            remove_filter('user_history_force_username_change_failure', $filter, 10);
        }
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

    private function currentMapping(): array
    {
        unset($GLOBALS['super_admins']);

        return array_values((array) get_site_option('site_admins', ['admin']));
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
