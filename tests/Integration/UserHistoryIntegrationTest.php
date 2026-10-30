<?php

final class UserHistoryIntegrationTest extends WP_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->clearHistoryTable();
    }

    protected function tearDown(): void
    {
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_activation_creates_history_table(): void
    {
        global $wpdb;

        $table = $wpdb->prefix . User_History::TABLE_NAME;
        $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));

        $this->assertSame($table, $found);
    }

    public function test_sensitive_profile_change_is_encrypted_and_displayed_as_plain_text(): void
    {
        global $wpdb;

        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);

        $result = wp_update_user(
            [
                'ID'         => $subject,
                'first_name' => 'Security Baseline',
            ]
        );

        $this->assertSame($subject, $result);

        $entry = $wpdb->get_row(
            $wpdb->prepare(
                'SELECT * FROM ' . $this->historyTable() . ' WHERE user_id = %d AND field_name = %s ORDER BY id DESC LIMIT 1',
                $subject,
                'first_name'
            )
        );

        $this->assertNotNull($entry);
        $this->assertNotSame('Security Baseline', $entry->new_value);
        $this->assertNotSame('', $entry->new_value);
        $this->assertStringContainsString('Security Baseline', $this->plugin->render_history_rows([$entry]));
    }

    public function test_password_change_event_stores_no_password_values(): void
    {
        global $wpdb;

        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);

        $result = wp_update_user(
            [
                'ID'        => $subject,
                'user_pass' => 'Temporary-Test-Password-42!',
            ]
        );

        $this->assertSame($subject, $result);

        $entry = $wpdb->get_row(
            $wpdb->prepare(
                'SELECT * FROM ' . $this->historyTable() . ' WHERE user_id = %d AND field_name = %s ORDER BY id DESC LIMIT 1',
                $subject,
                'user_pass'
            )
        );

        $this->assertNotNull($entry);
        $this->assertSame('', $entry->old_value);
        $this->assertSame('', $entry->new_value);
    }

    public function test_history_values_are_escaped_when_rendered(): void
    {
        $payload = '<script>alert("history")</script>';
        $entry = (object) [
            'user_id'     => 10,
            'changed_by'  => 20,
            'field_name'  => 'custom_note',
            'field_label' => '<img src=x onerror=alert(1)>',
            'old_value'   => '',
            'new_value'   => $payload,
            'change_type' => 'update',
            'created_at'  => '2026-01-01 12:00:00',
        ];

        $html = $this->plugin->render_history_rows([$entry]);

        $this->assertStringNotContainsString($payload, $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringContainsString('&lt;img src=x onerror=alert(1)&gt;', $html);
    }

    public function test_user_without_permission_cannot_count_another_users_history(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);
        wp_update_user(
            [
                'ID'         => $subject,
                'first_name' => 'Private History',
            ]
        );

        $subscriber = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($subscriber);

        $this->assertSame(0, $this->plugin->get_user_history_count($subject));
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createActorAndSubject(): array
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        $this->clearHistoryTable();

        return [$administrator, $subject];
    }

    private function clearHistoryTable(): void
    {
        global $wpdb;

        $wpdb->query('DELETE FROM ' . $this->historyTable());
    }

    private function historyTable(): string
    {
        global $wpdb;

        return $wpdb->prefix . User_History::TABLE_NAME;
    }
}
