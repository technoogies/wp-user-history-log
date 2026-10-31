<?php

final class AuditGovernanceTest extends WP_Ajax_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_activation_grants_manage_user_history_to_administrators(): void
    {
        $role = get_role('administrator');

        $this->assertNotNull($role);
        $this->assertTrue($role->has_cap(User_History::CLEAR_HISTORY_CAPABILITY));
    }

    public function test_upgrade_grants_manage_user_history_when_missing(): void
    {
        $role = get_role('administrator');
        $this->assertNotNull($role);
        $role->remove_cap(User_History::CLEAR_HISTORY_CAPABILITY);
        $this->assertFalse($role->has_cap(User_History::CLEAR_HISTORY_CAPABILITY));

        $method = new ReflectionMethod(User_History::class, 'maybe_upgrade');
        $method->setAccessible(true);
        $method->invoke($this->plugin);

        $this->assertTrue($role->has_cap(User_History::CLEAR_HISTORY_CAPABILITY));
    }

    public function test_account_editor_without_manage_user_history_cannot_clear_history(): void
    {
        [$editor, $subject] = $this->createEditorAndSubject();
        wp_set_current_user($editor);
        $this->seedHistory($subject, 'keep-me');
        $original = $this->historySnapshot($subject);

        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('edit_user', $subject));
        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertSame(count($original), $this->plugin->get_user_history_count($subject));
        $this->assertGreaterThan(0, count($original));

        $response = $this->clearHistory($subject);

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($subject));
        $this->assertSame(count($original), $this->plugin->get_user_history_count($subject));
    }

    public function test_account_editor_without_manage_user_history_can_still_view_history(): void
    {
        [$editor, $subject] = $this->createEditorAndSubject();
        wp_set_current_user($editor);
        $this->seedHistory($subject, 'visible');

        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertGreaterThan(0, $this->plugin->get_user_history_count($subject));

        $view = $this->loadMoreHistory($subject);

        $this->assertTrue($view['success']);
        $this->assertNotEmpty($view['data']['html']);
    }

    public function test_administrator_with_manage_user_history_can_clear_history(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'clear-me');

        $this->assertTrue(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));

        $response = $this->clearHistory($subject);

        $this->assertTrue($response['success']);
        $rows = $this->historySnapshot($subject);
        $this->assertCount(1, $rows);
        $this->assertSame('user_history_maintenance', $rows[0]['field_name']);
    }

    public function test_default_retention_does_not_prune_old_records(): void
    {
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        $this->seedHistory($subject, 'old-record', '2001-01-01 00:00:00');
        $original = $this->historySnapshot($subject);

        $removed = $this->plugin->prune_expired_history();

        $this->assertSame(0, $removed);
        $this->assertSame($original, $this->historySnapshot($subject));
        $this->assertContains('old-record-new', array_column($original, 'new_value'));
    }

    public function test_enabled_retention_removes_only_eligible_records_and_writes_maintenance(): void
    {
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        $this->seedHistory($subject, 'expired', '2001-01-01 00:00:00');
        $this->seedHistory($subject, 'recent', current_time('mysql'));

        $filter = static function () {
            return 30;
        };
        add_filter('user_history_retention_days', $filter);

        try {
            $removed = $this->plugin->prune_expired_history();
        } finally {
            remove_filter('user_history_retention_days', $filter);
        }

        $this->assertSame(1, $removed);
        $rows = $this->historySnapshot($subject);
        $fields = array_column($rows, 'field_name');
        $values = array_column($rows, 'new_value');
        $this->assertContains('user_history_maintenance', $fields);
        $this->assertNotContains('expired-new', $values);
        $this->assertContains('recent-new', $values);
    }

    public function test_privacy_exporter_returns_decrypted_history(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);
        wp_update_user(
            [
                'ID'         => $subject,
                'first_name' => 'Exportable Name',
            ]
        );

        $result = $this->plugin->export_personal_data(get_userdata($subject)->user_email);

        $this->assertTrue($result['done']);
        $this->assertNotEmpty($result['data']);
        $exported = wp_json_encode($result['data']);
        $this->assertStringContainsString('Exportable Name', $exported);
    }

    public function test_privacy_eraser_keeps_history_unless_explicitly_allowed(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'privacy-keep');
        $original = $this->historySnapshot($subject);

        $result = $this->plugin->erase_personal_data(get_userdata($subject)->user_email);

        $this->assertFalse($result['items_removed']);
        $this->assertTrue($result['items_retained']);
        $this->assertSame($original, $this->historySnapshot($subject));
    }

    public function test_privacy_eraser_can_remove_history_when_explicitly_allowed(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'privacy-erase');

        $filter = static function () {
            return true;
        };
        add_filter('user_history_erase_personal_data', $filter, 10, 3);

        try {
            $result = $this->plugin->erase_personal_data(get_userdata($subject)->user_email);
        } finally {
            remove_filter('user_history_erase_personal_data', $filter, 10);
        }

        $this->assertTrue($result['items_removed']);
        $rows = $this->historySnapshot($subject);
        $this->assertCount(1, $rows);
        $this->assertSame('user_history_maintenance', $rows[0]['field_name']);
    }

    public function test_ip_collection_can_be_disabled_without_changing_the_default(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.10';
        $method = new ReflectionMethod(User_History::class, 'get_operator_snapshot');
        $method->setAccessible(true);

        $default = $method->invoke($this->plugin, 0, []);
        $this->assertSame('203.0.113.10', $default['ip']);

        $filter = static function () {
            return false;
        };
        add_filter('user_history_collect_ip', $filter);

        try {
            $disabled = $method->invoke($this->plugin, 0, []);
        } finally {
            remove_filter('user_history_collect_ip', $filter);
        }

        $this->assertSame('', $disabled['ip']);
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createEditorAndSubject(): array
    {
        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        $editor_user->add_cap('list_users');
        $subject = self::factory()->user->create(['role' => 'subscriber']);

        return [$editor, $subject];
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createAdministratorAndSubject(): array
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);

        return [$administrator, $subject];
    }

    private function seedHistory($user_id, $marker, $created_at = ''): void
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
                'created_at'         => $created_at !== '' ? $created_at : current_time('mysql'),
            ]
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

    private function loadMoreHistory($user_id): array
    {
        $_POST = [
            'action'  => 'load_more_user_history',
            'nonce'   => wp_create_nonce('user_history_nonce'),
            'user_id' => (int) $user_id,
            'offset'  => 0,
        ];

        try {
            $this->_handleAjax('load_more_user_history');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
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

    private function historyTable(): string
    {
        global $wpdb;

        return $wpdb->prefix . User_History::TABLE_NAME;
    }
}
