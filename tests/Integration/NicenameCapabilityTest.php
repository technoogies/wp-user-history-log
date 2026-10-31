<?php

final class NicenameCapabilityTest extends WP_UnitTestCase
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
        wp_set_current_user(0);
        remove_role('account_manager');
        parent::tearDown();
    }

    public function test_custom_role_with_edit_users_can_change_nicename_without_administrator_slug(): void
    {
        $this->registerAccountManagerRole();
        $manager = self::factory()->user->create(['role' => 'account_manager']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($manager);

        $this->assertFalse(in_array('administrator', (array) wp_get_current_user()->roles, true));
        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue($this->canChangeNicename($subject));

        $_POST['user_nicename'] = 'capability-nicename';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($subject));
        $this->assertEmpty($errors->get_error_codes());

        $this->plugin->save_nicename_field($subject);

        $this->assertSame('capability-nicename', get_userdata($subject)->user_nicename);
    }

    public function test_editor_without_edit_users_cannot_change_nicename(): void
    {
        $editor = self::factory()->user->create(['role' => 'editor']);
        $subject = self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_nicename' => 'keep-this-nicename',
            ]
        );
        wp_set_current_user($editor);

        $this->assertFalse(current_user_can('edit_users'));
        $this->assertFalse($this->canChangeNicename($subject));

        $_POST['user_nicename'] = 'hijacked-nicename';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($subject));
        $this->assertContains('user_nicename_permission', $errors->get_error_codes());

        $this->plugin->save_nicename_field($subject);

        $this->assertSame('keep-this-nicename', get_userdata($subject)->user_nicename);
    }

    public function test_subscriber_cannot_change_their_own_nicename(): void
    {
        $subscriber = self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_nicename' => 'self-nicename',
            ]
        );
        wp_set_current_user($subscriber);

        $this->assertTrue(current_user_can('edit_user', $subscriber));
        $this->assertFalse($this->canChangeNicename($subscriber));

        $_POST['user_nicename'] = 'self-hijack';
        $this->plugin->save_nicename_field($subscriber);

        $this->assertSame('self-nicename', get_userdata($subscriber)->user_nicename);
    }

    public function test_administrator_can_still_change_nicename(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($administrator);

        $this->assertTrue($this->canChangeNicename($subject));

        $_POST['user_nicename'] = 'admin-updated-nicename';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($subject));
        $this->assertEmpty($errors->get_error_codes());
        $this->plugin->save_nicename_field($subject);

        $this->assertSame('admin-updated-nicename', get_userdata($subject)->user_nicename);
    }

    private function canChangeNicename($user_id): bool
    {
        $method = new ReflectionMethod(User_History::class, 'current_operator_can_change_nicename');
        $method->setAccessible(true);

        return (bool) $method->invoke($this->plugin, (int) $user_id);
    }

    private function registerAccountManagerRole(): void
    {
        add_role(
            'account_manager',
            'Account Manager',
            [
                'read'       => true,
                'list_users' => true,
                'edit_users' => true,
            ]
        );
    }
}
