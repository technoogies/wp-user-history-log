<?php

final class MultisiteUserDirectoryTest extends WP_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        $_REQUEST = [];
        wp_set_current_user(0);
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        $_REQUEST = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_duplicate_query_stays_on_the_current_site(): void
    {
        $outsider = (int) self::factory()->user->create(['role' => 'subscriber']);
        $site_id = (int) self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $local_a = (int) self::factory()->user->create(['role' => 'subscriber']);
        $local_b = (int) self::factory()->user->create(['role' => 'subscriber']);
        add_user_to_blog($site_id, $local_a, 'subscriber');
        add_user_to_blog($site_id, $local_b, 'subscriber');

        $this->forceEmail($outsider, 'shared-network@example.com');
        $this->forceEmail($local_a, 'shared-network@example.com');
        $this->forceEmail($local_b, 'Shared-Network@example.com');

        $directory = User_History_User_Directory::get_instance();
        $report = $directory->directory_report();
        $ids = array_map('intval', array_column($report['rows'], 'id'));

        $this->assertContains($local_a, $ids);
        $this->assertContains($local_b, $ids);
        $this->assertNotContains($outsider, $ids);

        $grouped = [];
        foreach ($report['groups']['email'] as $group) {
            foreach ($group['users'] as $row) {
                $grouped[] = (int) $row['id'];
            }
        }
        sort($grouped);
        $expected = [$local_a, $local_b];
        sort($expected);
        $this->assertSame($expected, $grouped);
    }

    public function test_subsite_account_editor_cannot_export_users(): void
    {
        $site_id = (int) self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $editor = (int) self::factory()->user->create(['role' => 'editor']);
        add_user_to_blog($site_id, $editor, 'editor');
        $editor_user = get_userdata($editor);
        $this->assertInstanceOf(WP_User::class, $editor_user);
        $editor_user->add_cap('list_users');
        $editor_user->add_cap('edit_users');

        wp_set_current_user($editor);
        $directory = User_History_User_Directory::get_instance();

        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertFalse($directory->current_operator_can_export());
    }

    /**
     * @param int    $user_id User ID.
     * @param string $email   Email address.
     */
    private function forceEmail($user_id, $email): void
    {
        global $wpdb;

        $wpdb->update($wpdb->users, ['user_email' => $email], ['ID' => (int) $user_id]);
        clean_user_cache((int) $user_id);
    }
}
