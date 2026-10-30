<?php

final class MultisiteTransactionalStorageTest extends WP_Ajax_UnitTestCase
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

    public function test_audit_insert_failure_leaves_identity_mapping_and_history_unchanged(): void
    {
        $operator = $this->createNetworkOperator();
        $target = $this->createMappedSuperAdmin('ms-txn-insert-admin');
        wp_set_current_user($operator);

        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();
        $original_history = $this->historySnapshot($target);

        $response = $this->withForcedLogFailure(function () {
            return $this->changeUsername('ms-txn-insert-admin', 'ms-txn-insert-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertSame($original_history, $this->historySnapshot($target));
        $this->assertFalse(username_exists('ms-txn-insert-renamed'));
        $this->assertTrue(is_super_admin($target));
    }

    public function test_nontransactional_history_table_refuses_username_change(): void
    {
        $operator = $this->createNetworkOperator();
        $target = $this->createMappedSuperAdmin('ms-txn-history-admin');
        wp_set_current_user($operator);

        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();

        $response = $this->withForcedEngine($this->historyTable(), 'MyISAM', function () {
            return $this->changeUsername('ms-txn-history-admin', 'ms-txn-history-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertStringContainsString('transactional storage is unavailable', $response['message']);
        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertFalse(username_exists('ms-txn-history-renamed'));
        $this->assertTrue(is_super_admin($target));
    }

    public function test_nontransactional_users_table_refuses_username_change(): void
    {
        global $wpdb;

        $operator = $this->createNetworkOperator();
        $target = $this->createMappedSuperAdmin('ms-txn-users-admin');
        wp_set_current_user($operator);

        $original_identity = $this->identity($target);
        $original_mapping = $this->currentMapping();

        $response = $this->withForcedEngine($wpdb->users, 'MyISAM', function () {
            return $this->changeUsername('ms-txn-users-admin', 'ms-txn-users-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($target));
        $this->assertSame($original_mapping, $this->currentMapping());
        $this->assertFalse(username_exists('ms-txn-users-renamed'));
        $this->assertTrue(is_super_admin($target));
    }

    public function test_clear_history_rolls_back_when_maintenance_insert_fails(): void
    {
        $operator = $this->createNetworkOperator();
        $target = self::factory()->user->create(
            [
                'user_login' => 'ms-txn-clear-target',
            ]
        );
        wp_set_current_user($operator);
        $this->seedHistory($target, 'ms-before-clear');
        $original = $this->historySnapshot($target);

        $filter = static function () {
            return true;
        };
        add_filter('user_history_force_log_change_failure', $filter, 10, 4);

        try {
            $response = $this->clearHistory($target);
        } finally {
            remove_filter('user_history_force_log_change_failure', $filter, 10);
        }

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($target));
    }

    private function createNetworkOperator(): int
    {
        $operator = self::factory()->user->create(
            [
                'user_login' => 'ms-txn-operator-' . wp_generate_password(6, false),
            ]
        );
        grant_super_admin($operator);

        return $operator;
    }

    private function createMappedSuperAdmin($login): int
    {
        $target = self::factory()->user->create(
            [
                'user_login'    => $login,
                'display_name'  => $login,
                'user_nicename' => $login,
            ]
        );
        grant_super_admin($target);

        return $target;
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

    private function clearHistory($user_id): array
    {
        $_POST = [
            'action'  => 'clear_user_history',
            'nonce'   => wp_create_nonce('user_history_clear'),
            'user_id' => (int) $user_id,
        ];

        try {
            $this->_handleAjax('clear_user_history');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    private function withForcedLogFailure($callback)
    {
        $filter = static function () {
            return true;
        };
        add_filter('user_history_force_log_change_failure', $filter, 10, 4);

        try {
            return $callback();
        } finally {
            remove_filter('user_history_force_log_change_failure', $filter, 10);
        }
    }

    private function withForcedEngine($table_name, $engine, $callback)
    {
        $filter = static function ($current, $table) use ($table_name, $engine) {
            return $table === $table_name ? $engine : $current;
        };
        add_filter('user_history_table_engine', $filter, 10, 2);

        try {
            return $callback();
        } finally {
            remove_filter('user_history_table_engine', $filter, 10);
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

    private function historySnapshot($user_id): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT id, field_name, old_value, new_value, change_type FROM ' . $this->historyTable() . ' WHERE user_id = %d ORDER BY id ASC',
                $user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    private function seedHistory($user_id, $marker): void
    {
        global $wpdb;

        $wpdb->insert(
            $this->historyTable(),
            [
                'user_id'            => (int) $user_id,
                'changed_by'         => (int) $user_id,
                'field_name'         => 'first_name',
                'field_label'        => 'First Name',
                'old_value'          => $marker . '-old',
                'new_value'          => $marker . '-new',
                'search_tokens'      => '',
                'changed_by_details' => '',
                'change_type'        => 'update',
                'created_at'         => current_time('mysql'),
            ],
            ['%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    private function historyTable(): string
    {
        global $wpdb;

        return $wpdb->prefix . User_History::TABLE_NAME;
    }
}
