<?php

final class MultisiteStaffNotesTest extends WP_UnitTestCase
{
    private int $granted_super_admin = 0;

    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        $_POST = [];
        wp_set_current_user(0);
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        if ($this->granted_super_admin > 0 && function_exists('revoke_super_admin')) {
            revoke_super_admin($this->granted_super_admin);
            $this->granted_super_admin = 0;
        }

        $_POST = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subsite_administrator_cannot_see_or_save_staff_notes(): void
    {
        $site_id = (int) self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $admin = (int) self::factory()->user->create(['role' => 'administrator']);
        $subject = (int) self::factory()->user->create(['role' => 'subscriber']);
        add_user_to_blog($site_id, $admin, 'administrator');
        add_user_to_blog($site_id, $subject, 'subscriber');
        if (is_super_admin($admin)) {
            revoke_super_admin($admin);
        }

        wp_set_current_user($admin);
        $notes = User_History_Staff_Notes::get_instance();

        $this->assertFalse(current_user_can('edit_users'));
        $this->assertFalse($notes->current_operator_can_manage($subject));
        $this->assertSame('', $this->renderProfile($notes, $subject));

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Subsite secret';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $notes->save_profile_fields($subject);

        $this->assertSame('', $notes->get_note($subject));
        $this->assertSame([], $notes->get_tags($subject));
    }

    public function test_super_admin_can_save_a_staff_note_for_a_site_user(): void
    {
        $site_id = (int) self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $super = (int) self::factory()->user->create(['role' => 'administrator']);
        $subject = (int) self::factory()->user->create(['role' => 'subscriber']);
        grant_super_admin($super);
        $this->granted_super_admin = $super;
        add_user_to_blog($site_id, $super, 'administrator');
        add_user_to_blog($site_id, $subject, 'subscriber');

        wp_set_current_user($super);
        $notes = User_History_Staff_Notes::get_instance();

        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue($notes->current_operator_can_manage($subject));

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Network note';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'VIP, needs follow up';
        $notes->save_profile_fields($subject);

        $this->assertSame('Network note', $notes->get_note($subject));
        $this->assertSame(['vip', 'needs-follow-up'], $notes->get_tags($subject));
        $this->assertStringContainsString('Network note', $this->renderProfile($notes, $subject));
    }

    private function renderProfile(User_History_Staff_Notes $notes, int $user_id): string
    {
        $user = get_userdata($user_id);
        $this->assertInstanceOf(WP_User::class, $user);

        ob_start();
        $notes->render_profile_fields($user);

        return (string) ob_get_clean();
    }
}
