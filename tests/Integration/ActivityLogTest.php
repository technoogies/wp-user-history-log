<?php

final class ActivityLogTest extends WP_Ajax_UnitTestCase
{
    private User_History $plugin;
    private User_History_Activity_Log $activity;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->activity = User_History_Activity_Log::get_instance($this->plugin);
        $this->resetActivityOptions();
    }

    protected function tearDown(): void
    {
        $this->resetActivityOptions();
        delete_option('user_history_retention_days');
        delete_option('user_history_collect_ip');
        delete_option(User_History_Login_Tracker::OPTION_KEY);
        $_POST = [];
        $_SERVER['REMOTE_ADDR'] = '';
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_activity_log_is_off_by_default_and_records_nothing(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);

        $this->assertFalse($this->activity->is_enabled());
        $this->assertSame('0', (string) get_option(User_History_Activity_Log::OPTION_ENABLED, '0'));

        $post_id = self::factory()->post->create(['post_status' => 'publish', 'post_title' => 'Quiet post']);
        $this->assertIsInt($post_id);
        $this->assertSame([], $this->activityActions());

        $this->assertFalse($this->activity->should_record_action('post_published'));
        $this->assertFalse($this->activity->log('post_published', 'post', $post_id, 'Quiet post'));
        $this->assertSame([], $this->activityActions());
    }

    public function test_content_group_logs_posts_but_not_media(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);
        $this->enableActivity(['content']);

        $this->assertTrue($this->activity->should_record_action('post_published'));
        $this->assertFalse($this->activity->should_record_action('attachment_uploaded'));

        $post_id = self::factory()->post->create(['post_status' => 'publish', 'post_title' => 'Logged post']);
        $this->assertContains('post_published', $this->activityActions());

        $this->assertFalse($this->activity->log('attachment_uploaded', 'attachment', $post_id, 'photo.jpg'));
        $this->assertNotContains('attachment_uploaded', $this->activityActions());
    }

    public function test_users_and_logins_appear_in_activity_and_account_history(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($administrator);
        $this->enableActivity(['users', 'logins']);
        update_option(User_History_Login_Tracker::OPTION_KEY, '1');

        $lock = User_History_Lock::get_instance($this->plugin);
        $this->assertTrue($lock->lock_user($subject));

        $subject_user = get_userdata($subject);
        do_action('wp_login', $subject_user->user_login, $subject_user);

        $actions = $this->activityActions();
        $this->assertContains('user_locked', $actions);
        $this->assertContains('user_login', $actions);

        $history = $this->historySnapshot($subject);
        $history_fields = array_column($history, 'field_name');
        $history_types = array_column($history, 'change_type');
        $this->assertContains('account_locked', $history_fields);
        $this->assertContains(User_History_Login_Tracker::FIELD_NAME, $history_fields);
        $this->assertContains('login', $history_types);
    }

    public function test_editor_without_manage_user_history_cannot_clear_activity_log(): void
    {
        $this->enableActivity(['content']);
        $this->seedActivity('post_published', 'Stay');

        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        wp_set_current_user($editor);

        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $original = $this->activitySnapshot();

        $response = $this->clearActivityLog();

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->activitySnapshot());
    }

    public function test_administrator_can_clear_activity_log_transactionally(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);
        $this->enableActivity(['content']);
        $this->seedActivity('post_published', 'Gone');

        $this->assertTrue(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));

        $response = $this->clearActivityLog();

        $this->assertTrue($response['success']);
        $this->assertSame([], $this->activitySnapshot());

        $maintenance = $this->historySnapshot($administrator);
        $this->assertNotEmpty($maintenance);
        $this->assertSame('user_history_maintenance', $maintenance[count($maintenance) - 1]['field_name']);
        $this->assertSame('maintenance', $maintenance[count($maintenance) - 1]['change_type']);
    }

    public function test_retention_zero_keeps_old_activity_rows(): void
    {
        $this->enableActivity(['content']);
        $this->seedActivity('post_published', 'Keep forever', '2001-01-01 00:00:00');
        $original = $this->activitySnapshot();

        $removed = $this->plugin->prune_expired_history();

        $this->assertSame(0, $removed);
        $this->assertSame($original, $this->activitySnapshot());
    }

    public function test_retention_one_day_prunes_only_old_activity_and_writes_maintenance(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);
        $this->enableActivity(['content']);
        $this->seedActivity('post_published', 'Expired post', '2001-01-01 00:00:00');
        $this->seedActivity('post_updated', 'Recent post', current_time('mysql'));

        $filter = static function () {
            return 1;
        };
        add_filter('user_history_retention_days', $filter);

        try {
            $removed = $this->plugin->prune_expired_history();
        } finally {
            remove_filter('user_history_retention_days', $filter);
        }

        $this->assertSame(1, $removed);
        $names = array_column($this->activitySnapshot(), 'object_name');
        $this->assertNotContains('Expired post', $names);
        $this->assertContains('Recent post', $names);

        $maintenance = $this->historySnapshot($administrator);
        $this->assertNotEmpty($maintenance);
        $this->assertSame('user_history_maintenance', $maintenance[count($maintenance) - 1]['field_name']);
    }

    public function test_ip_collection_follows_the_privacy_option(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);
        $this->enableActivity(['content']);
        $_SERVER['REMOTE_ADDR'] = '203.0.113.40';

        $this->activity->log('post_published', 'post', 1, 'With IP');
        $this->assertSame('203.0.113.40', $this->activitySnapshot()[0]['ip_address']);

        update_option('user_history_collect_ip', '0');
        $this->activity->log('post_updated', 'post', 1, 'Without IP');

        $rows = $this->activitySnapshot();
        $this->assertSame('', $rows[count($rows) - 1]['ip_address']);
    }

    public function test_describe_builds_a_language_neutral_row_into_html(): void
    {
        $row = (object) [
            'action'      => 'post_published',
            'object_type' => 'post',
            'object_id'   => 0,
            'object_name' => 'Hello <em>world</em>',
            'context'     => wp_json_encode(['type_label' => 'post', 'status' => 'publish']),
        ];

        $html = $this->activity->describe($row);
        $this->assertStringContainsString('Published', $html);
        $this->assertStringContainsString('Hello &lt;em&gt;world&lt;/em&gt;', $html);
        $this->assertStringNotContainsString('<em>world</em>', $html);
    }

    public function test_failed_login_logs_unknown_usernames_when_logins_are_on(): void
    {
        $this->enableActivity(['logins']);
        $this->activity->on_login_failed('nobody-here');

        $rows = $this->activitySnapshot();
        $this->assertCount(1, $rows);
        $this->assertSame('login_failed', $rows[0]['action']);
        $this->assertSame('nobody-here', $rows[0]['object_name']);
        $this->assertSame('0', (string) $rows[0]['user_id']);
    }

    /**
     * @param string[] $groups
     */
    private function enableActivity(array $groups): void
    {
        update_option(User_History_Activity_Log::OPTION_ENABLED, '1');
        update_option(User_History_Activity_Log::OPTION_EVENTS, $groups);
    }

    private function resetActivityOptions(): void
    {
        delete_option(User_History_Activity_Log::OPTION_ENABLED);
        delete_option(User_History_Activity_Log::OPTION_EVENTS);
        $this->activity->delete_all_rows();
    }

    private function seedActivity($action, $name, $created_at = null): void
    {
        global $wpdb;

        $wpdb->insert(
            $this->activityTable(),
            [
                'user_id'     => get_current_user_id(),
                'action'      => $action,
                'object_type' => 'post',
                'object_id'   => 1,
                'object_name' => $name,
                'context'     => '',
                'ip_address'  => '',
                'created_at'  => $created_at ?: current_time('mysql'),
            ]
        );
    }

    private function clearActivityLog(): array
    {
        $_POST = [
            'action' => 'user_history_clear_activity_log',
            'nonce'  => wp_create_nonce('user_history_clear_activity_log'),
        ];

        try {
            $this->_handleAjax('user_history_clear_activity_log');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    /**
     * @return string[]
     */
    private function activityActions(): array
    {
        return array_column($this->activitySnapshot(), 'action');
    }

    private function activitySnapshot(): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            'SELECT id, user_id, action, object_name, ip_address, created_at FROM ' . $this->activityTable() . ' ORDER BY id ASC',
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    private function historySnapshot($user_id): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT id, field_name, change_type FROM ' . $wpdb->prefix . User_History::TABLE_NAME . ' WHERE user_id = %d ORDER BY id ASC',
                $user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    private function activityTable(): string
    {
        return $this->activity->table_name();
    }
}
