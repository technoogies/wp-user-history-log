<?php

final class SettingsAdminTest extends WP_Ajax_UnitTestCase
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
        global $menu, $submenu;

        $menu = [];
        $submenu = [];
        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_retention_settings_default_is_keep_forever(): void
    {
        $settings = User_History_Settings::get_instance();

        $this->assertSame(0, $settings->sanitize_retention_days(''));
        $this->assertSame(0, $settings->sanitize_retention_days('0'));
        $this->assertSame(400, $settings->sanitize_retention_days('400'));
        $this->assertSame(0, (int) get_option('user_history_retention_days', 0));

        $removed = $this->plugin->prune_expired_history();
        $this->assertSame(0, $removed);
    }

    public function test_ip_collection_stays_on_until_the_settings_option_is_off(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.20';
        $method = new ReflectionMethod(User_History::class, 'get_operator_snapshot');
        $method->setAccessible(true);

        $default = $method->invoke($this->plugin, 0, []);
        $this->assertSame('203.0.113.20', $default['ip']);

        update_option('user_history_collect_ip', '0');

        try {
            $disabled = $method->invoke($this->plugin, 0, []);
        } finally {
            delete_option('user_history_collect_ip');
        }

        $this->assertSame('', $disabled['ip']);
    }

    public function test_administrator_with_manage_user_history_can_clear_all_logs(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($administrator);
        $this->seedHistory($subject, 'clear-all');

        $this->assertTrue(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));

        $response = $this->clearAllLogs();

        $this->assertTrue($response['success']);
        $this->assertSame([], $this->historySnapshot($subject));

        $maintenance = $this->historySnapshot(0);
        $this->assertCount(1, $maintenance);
        $this->assertSame('user_history_maintenance', $maintenance[0]['field_name']);
        $this->assertSame('maintenance', $maintenance[0]['change_type']);
    }

    public function test_account_editor_without_manage_user_history_cannot_clear_all_logs(): void
    {
        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        $editor_user->add_cap('list_users');
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($editor);
        $this->seedHistory($subject, 'keep-all');
        $original = $this->historySnapshot($subject);

        $this->assertTrue(current_user_can('edit_users'));
        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));

        $response = $this->clearAllLogs();

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($subject));
        $this->assertSame([], $this->historySnapshot(0));
    }

    public function test_settings_menu_is_registered_for_manage_user_history_only(): void
    {
        global $menu, $submenu;

        if (!function_exists('add_menu_page')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        if (!function_exists('add_menu_page')) {
            $this->markTestSkipped('Admin menu APIs are unavailable.');
        }

        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);
        $this->registerAdminMenus();

        $this->assertTrue(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertNotFalse($this->findMenuSlug($menu, 'user-history'));
        $this->assertArrayHasKey('user-history', $submenu);
        $this->assertSame('Settings', $submenu['user-history'][0][0]);

        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        wp_set_current_user($editor);
        $this->registerAdminMenus();

        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertFalse($this->findMenuSlug($menu, 'user-history'));
    }

    /**
     * @param array<int,array<int,mixed>> $menu
     * @return array<int,mixed>|false
     */
    private function findMenuSlug($menu, $slug)
    {
        foreach ((array) $menu as $item) {
            if (isset($item[2]) && $item[2] === $slug) {
                return $item;
            }
        }

        return false;
    }

    private function registerAdminMenus(): void
    {
        global $menu, $submenu;

        $menu = [];
        $submenu = [];
        do_action('admin_menu');
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
            ]
        );
    }

    private function clearAllLogs(): array
    {
        $_POST = [
            'action' => 'user_history_clear_all_logs',
            'nonce'  => wp_create_nonce('user_history_clear_all_logs'),
        ];

        try {
            $this->_handleAjax('user_history_clear_all_logs');
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
