<?php

final class TransactionalStorageTest extends WP_Ajax_UnitTestCase
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

    public function test_activation_creates_an_innodb_history_table(): void
    {
        $this->assertSame('innodb', strtolower($this->realEngine($this->historyTable())));
    }

    public function test_activation_converts_a_myisam_history_table_to_innodb(): void
    {
        global $wpdb;

        $table = $this->historyTable();
        $wpdb->query("ALTER TABLE {$table} ENGINE=MyISAM");

        if (strcasecmp($this->realEngine($table), 'MyISAM') !== 0) {
            $this->markTestSkipped('MyISAM is not available in this environment.');
        }

        User_History::get_instance()->activate();

        $this->assertSame('innodb', strtolower($this->realEngine($table)));
    }

    public function test_clear_history_rolls_back_when_maintenance_insert_fails(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'before-clear');
        $original = $this->historySnapshot($subject);

        $response = $this->withForcedLogFailure(function () use ($subject) {
            return $this->clearHistory($subject);
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($subject));
    }

    public function test_clear_history_rolls_back_when_commit_fails(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'commit-clear');
        $original = $this->historySnapshot($subject);

        $response = $this->withForcedTransactionFailure('commit', function () use ($subject) {
            return $this->clearHistory($subject);
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($subject));
    }

    public function test_clear_history_refuses_a_nontransactional_history_table(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'myisam-clear');
        $original = $this->historySnapshot($subject);

        $response = $this->withForcedEngine($this->historyTable(), 'MyISAM', function () use ($subject) {
            return $this->clearHistory($subject);
        });

        $this->assertFalse($response['success']);
        $this->assertStringContainsString('transactional storage is unavailable', $response['data']['message']);
        $this->assertSame($original, $this->historySnapshot($subject));
    }

    public function test_clear_history_refuses_when_a_transaction_cannot_start(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'begin-clear');
        $original = $this->historySnapshot($subject);

        $response = $this->withForcedTransactionFailure('begin', function () use ($subject) {
            return $this->clearHistory($subject);
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($subject));
    }

    public function test_username_change_rolls_back_when_audit_insert_fails(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject('txn-insert-target');
        wp_set_current_user($administrator);
        $original_identity = $this->identity($subject);
        $original_history = $this->historySnapshot($subject);

        $response = $this->withForcedLogFailure(function () {
            return $this->changeUsername('txn-insert-target', 'txn-insert-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($subject));
        $this->assertSame($original_history, $this->historySnapshot($subject));
        $this->assertFalse(username_exists('txn-insert-renamed'));
    }

    public function test_username_change_rolls_back_when_login_update_is_forced_to_fail(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject('txn-update-target');
        wp_set_current_user($administrator);
        $original_identity = $this->identity($subject);
        $original_history = $this->historySnapshot($subject);

        $filter = static function ($force, $stage) {
            return $stage === 'user_login' ? true : $force;
        };
        add_filter('user_history_force_username_change_failure', $filter, 10, 2);

        try {
            $response = $this->changeUsername('txn-update-target', 'txn-update-renamed');
        } finally {
            remove_filter('user_history_force_username_change_failure', $filter, 10);
        }

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($subject));
        $this->assertSame($original_history, $this->historySnapshot($subject));
        $this->assertFalse(username_exists('txn-update-renamed'));
    }

    public function test_username_change_refuses_a_nontransactional_history_table(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject('txn-history-target');
        wp_set_current_user($administrator);
        $original_identity = $this->identity($subject);

        $response = $this->withForcedEngine($this->historyTable(), 'MyISAM', function () {
            return $this->changeUsername('txn-history-target', 'txn-history-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertStringContainsString('transactional storage is unavailable', $response['message']);
        $this->assertSame($original_identity, $this->identity($subject));
        $this->assertFalse(username_exists('txn-history-renamed'));
    }

    public function test_username_change_rolls_back_when_commit_fails(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject('txn-commit-target');
        wp_set_current_user($administrator);
        $original_identity = $this->identity($subject);
        $original_history = $this->historySnapshot($subject);

        $response = $this->withForcedTransactionFailure('commit', function () {
            return $this->changeUsername('txn-commit-target', 'txn-commit-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($subject));
        $this->assertSame($original_history, $this->historySnapshot($subject));
        $this->assertFalse(username_exists('txn-commit-renamed'));
    }

    public function test_username_change_refuses_when_a_transaction_cannot_start(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject('txn-begin-target');
        wp_set_current_user($administrator);
        $original_identity = $this->identity($subject);

        $response = $this->withForcedTransactionFailure('begin', function () {
            return $this->changeUsername('txn-begin-target', 'txn-begin-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertSame($original_identity, $this->identity($subject));
        $this->assertFalse(username_exists('txn-begin-renamed'));
    }

    public function test_username_change_refuses_a_nontransactional_users_table(): void
    {
        global $wpdb;

        [$administrator, $subject] = $this->createActorAndSubject('txn-users-target');
        wp_set_current_user($administrator);
        $original_identity = $this->identity($subject);

        $response = $this->withForcedEngine($wpdb->users, 'MyISAM', function () {
            return $this->changeUsername('txn-users-target', 'txn-users-renamed');
        });

        $this->assertFalse($response['success']);
        $this->assertStringContainsString('transactional storage is unavailable', $response['message']);
        $this->assertSame($original_identity, $this->identity($subject));
        $this->assertFalse(username_exists('txn-users-renamed'));
    }

    public function test_username_change_still_succeeds_on_innodb(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject('txn-happy-target');
        wp_set_current_user($administrator);

        $response = $this->changeUsername('txn-happy-target', 'txn-happy-renamed');

        $this->assertTrue($response['success']);
        $this->assertSame('txn-happy-renamed', $this->identity($subject)['user_login']);
        $this->assertFalse(username_exists('txn-happy-target'));
        $this->assertGreaterThan(0, count($this->historySnapshot($subject)));
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createActorAndSubject($login = ''): array
    {
        $login = $login !== '' ? $login : 'txn-subject-' . wp_generate_password(8, false);
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_login'    => $login,
                'display_name'  => $login,
                'user_nicename' => $login,
            ]
        );

        $this->assertIsInt($subject);

        return [$administrator, $subject];
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

    private function withForcedTransactionFailure($stage, $callback)
    {
        $filter = static function ($force, $failure_stage) use ($stage) {
            return $failure_stage === $stage ? true : $force;
        };
        add_filter('user_history_force_transaction_failure', $filter, 10, 2);

        try {
            return $callback();
        } finally {
            remove_filter('user_history_force_transaction_failure', $filter, 10);
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

    private function historySnapshot($user_id): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT id, field_name, old_value, new_value, change_type FROM ' . $this->historyTable() . ' WHERE user_id = %d ORDER BY id ASC',
                (int) $user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
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

    private function realEngine($table_name): string
    {
        global $wpdb;

        $create_table = $wpdb->get_row("SHOW CREATE TABLE `{$table_name}`", ARRAY_N);
        if (is_array($create_table) && isset($create_table[1]) && preg_match('/\bENGINE=([A-Za-z0-9_]+)/i', $create_table[1], $matches)) {
            return $matches[1];
        }

        return '';
    }

    private function historyTable(): string
    {
        global $wpdb;

        return $wpdb->prefix . User_History::TABLE_NAME;
    }
}
