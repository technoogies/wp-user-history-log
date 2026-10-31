<?php

final class MultisiteHistoryEncryptionTest extends WP_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subsite_history_survives_key_rotation(): void
    {
        $site_id = self::factory()->blog->create();
        $operator = self::factory()->user->create();
        grant_super_admin($operator);

        switch_to_blog($site_id);
        $this->plugin->activate();
        wp_set_current_user($operator);

        $subject = self::factory()->user->create(
            [
                'first_name' => 'Network Before',
            ]
        );
        $updated = wp_update_user(
            [
                'ID'         => $subject,
                'first_name' => 'Network After',
            ]
        );
        $this->assertSame($subject, $updated);

        $this->plugin->rotate_encryption_key();

        global $wpdb;
        $row = $wpdb->get_row(
            $wpdb->prepare(
                'SELECT * FROM ' . $wpdb->prefix . User_History::TABLE_NAME . ' WHERE user_id = %d AND field_name = %s ORDER BY id DESC LIMIT 1',
                $subject,
                'first_name'
            )
        );

        $this->assertNotNull($row);
        $this->assertStringStartsWith('uh1:', $row->new_value);
        $this->assertStringContainsString('Network After', $this->plugin->render_history_rows([$row]));
    }
}
