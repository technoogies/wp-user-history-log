<?php

final class MultisiteNicenameCapabilityTest extends WP_UnitTestCase
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
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subsite_role_with_edit_users_can_change_nicename_without_administrator_slug(): void
    {
        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        add_role(
            'account_manager',
            'Account Manager',
            [
                'read'       => true,
                'list_users' => true,
                'edit_users' => true,
            ]
        );

        $manager = self::factory()->user->create(['role' => 'account_manager']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        add_user_to_blog($site_id, $manager, 'account_manager');
        add_user_to_blog($site_id, $subject, 'subscriber');
        $manager_user = get_userdata($manager);
        $manager_user->add_cap('manage_network_users');
        wp_set_current_user($manager);

        $this->assertFalse(in_array('administrator', (array) wp_get_current_user()->roles, true));
        $this->assertTrue(current_user_can('edit_users'));

        $method = new ReflectionMethod(User_History::class, 'current_operator_can_change_nicename');
        $method->setAccessible(true);
        $this->assertTrue($method->invoke(User_History::get_instance(), $subject));

        $_POST['user_nicename'] = 'ms-capability-nicename';
        $errors = new WP_Error();
        User_History::get_instance()->validate_nicename_submission($errors, true, get_userdata($subject));
        $this->assertEmpty($errors->get_error_codes());
        User_History::get_instance()->save_nicename_field($subject);

        $this->assertSame('ms-capability-nicename', get_userdata($subject)->user_nicename);

        remove_role('account_manager');
    }
}
