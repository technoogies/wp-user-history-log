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

    public function test_subscriber_can_edit_only_their_own_nicename(): void
    {
        $subscriber = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_email' => 'self.nicename@example.com',
            ]
        );
        $other = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_email' => 'other.nicename@example.com',
            ]
        );
        $this->pinNicename($subscriber, 'self-nicename');
        $this->pinNicename($other, 'other-nicename');
        $subscriber_email = get_userdata($subscriber)->user_email;
        $other_email = get_userdata($other)->user_email;
        wp_set_current_user($subscriber);

        $this->assertFalse(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('edit_user', $subscriber));
        $this->assertFalse(current_user_can('edit_user', $other));
        $this->assertTrue($this->canChangeNicename($subscriber));
        $this->assertFalse($this->canChangeNicename($other));

        ob_start();
        $this->plugin->render_nicename_field(get_userdata($subscriber));
        $own_field = ob_get_clean();
        $this->assertStringContainsString('name="user_nicename"', $own_field);
        $this->assertStringContainsString('user-history-nicename-wrap', $own_field);

        ob_start();
        $this->plugin->render_nicename_field(get_userdata($other));
        $this->assertSame('', ob_get_clean());

        $_POST['user_nicename'] = get_userdata($other)->user_nicename;
        $_POST['email'] = 'hijack@example.com';
        $_POST['role'] = 'administrator';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($subscriber));
        $this->assertContains('user_nicename_duplicate', $errors->get_error_codes());
        $this->plugin->save_nicename_field($subscriber);
        $this->assertSame('self-nicename', get_userdata($subscriber)->user_nicename);

        $_POST['user_nicename'] = 'self-chosen';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($subscriber));
        $this->assertEmpty($errors->get_error_codes());
        $this->plugin->save_nicename_field($subscriber);

        $saved = get_userdata($subscriber);
        $this->assertSame('self-chosen', $saved->user_nicename);
        $this->assertSame('subscriber', $saved->roles[0]);
        $this->assertSame($subscriber_email, $saved->user_email);
        $this->assertFalse(user_can($subscriber, 'edit_users'));

        $_POST['user_nicename'] = 'other-hijack';
        $_POST['email'] = 'other-hijack@example.com';
        $_POST['role'] = 'administrator';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($other));
        $this->assertContains('user_nicename_permission', $errors->get_error_codes());
        $this->plugin->save_nicename_field($other);

        $untouched = get_userdata($other);
        $this->assertSame('other-nicename', $untouched->user_nicename);
        $this->assertSame($other_email, $untouched->user_email);
        $this->assertSame('subscriber', $untouched->roles[0]);
    }

    public function test_editor_can_change_their_own_nicename_but_not_another_users(): void
    {
        $editor = self::factory()->user->create(
            [
                'role'       => 'editor',
                'user_email' => 'editor.own.nicename@example.com',
            ]
        );
        $subject = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_email' => 'editor.subject.nicename@example.com',
            ]
        );
        $this->pinNicename($editor, 'editor-own-nicename');
        $this->pinNicename($subject, 'editor-subject-nicename');
        wp_set_current_user($editor);

        $this->assertFalse(current_user_can('edit_users'));
        $this->assertTrue($this->canChangeNicename($editor));
        $this->assertFalse($this->canChangeNicename($subject));

        $_POST['user_nicename'] = 'editor-self-chosen';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($editor));
        $this->assertEmpty($errors->get_error_codes());
        $this->plugin->save_nicename_field($editor);
        $this->assertSame('editor-self-chosen', get_userdata($editor)->user_nicename);

        $_POST['user_nicename'] = 'editor-subject-hijack';
        $this->plugin->save_nicename_field($subject);
        $this->assertSame('editor-subject-nicename', get_userdata($subject)->user_nicename);
        $this->assertSame('editor', get_userdata($editor)->roles[0]);
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

    private function pinNicename(int $user_id, string $nicename): void
    {
        global $wpdb;

        $wpdb->update(
            $wpdb->users,
            ['user_nicename' => $nicename],
            ['ID' => $user_id],
            ['%s'],
            ['%d']
        );
        clean_user_cache($user_id);
        $this->assertSame($nicename, get_userdata($user_id)->user_nicename);
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
