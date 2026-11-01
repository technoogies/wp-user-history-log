<?php

final class NewUserNicenameTest extends WP_UnitTestCase
{
    private User_History $plugin;
    private User_History_New_User_Nicename $generator;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->generator = User_History_New_User_Nicename::get_instance($this->plugin);
    }

    protected function tearDown(): void
    {
        $_POST = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_new_user_nicename_comes_from_display_name_and_is_not_the_login(): void
    {
        $user_id = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'jane.doe',
                'user_email'   => 'jane.doe@example.com',
                'display_name' => 'Jane Doe',
            ]
        );

        $user = get_userdata($user_id);

        $this->assertSame('jane-doe', $user->user_nicename);
        $this->assertNotSame($user->user_login, $user->user_nicename);
    }

    public function test_new_user_nicename_falls_back_to_first_and_last_name(): void
    {
        $user_id = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'jdoe',
                'user_email'   => 'jdoe@example.com',
                'display_name' => 'jdoe',
                'first_name'   => 'Jane',
                'last_name'    => 'Doe',
            ]
        );

        $this->assertSame('jane-doe', get_userdata($user_id)->user_nicename);
        $this->assertNotSame('jdoe', get_userdata($user_id)->user_nicename);
    }

    public function test_duplicate_name_seeds_get_a_unique_suffix(): void
    {
        $first = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'jane.one',
                'user_email'   => 'jane.one@example.com',
                'display_name' => 'Jane Doe',
            ]
        );
        $second = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'jane.two',
                'user_email'   => 'jane.two@example.com',
                'display_name' => 'Jane Doe',
            ]
        );

        $this->assertSame('jane-doe', get_userdata($first)->user_nicename);
        $this->assertSame('jane-doe-2', get_userdata($second)->user_nicename);
        $this->assertTrue($this->plugin->is_nicename_unique('jane-doe', $first));
        $this->assertTrue($this->plugin->is_nicename_unique('jane-doe-2', $second));
        $this->assertFalse($this->plugin->is_nicename_unique('jane-doe', $second));
    }

    public function test_existing_user_nicename_is_left_unchanged_on_profile_update(): void
    {
        $user_id = self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_login'    => 'existing.login',
                'user_email'    => 'existing.login@example.com',
                'user_nicename' => 'keep-existing-nicename',
            ]
        );

        $this->assertSame('keep-existing-nicename', get_userdata($user_id)->user_nicename);

        $updated = wp_update_user(
            [
                'ID'           => $user_id,
                'first_name'   => 'Existing',
                'last_name'    => 'Person',
                'display_name' => 'Existing Person',
            ]
        );

        $this->assertSame($user_id, $updated);
        $this->assertSame('keep-existing-nicename', get_userdata($user_id)->user_nicename);
    }

    public function test_profile_nicename_remains_editable_after_creation(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'editable.login',
                'user_email'   => 'editable.login@example.com',
                'display_name' => 'Editable Name',
            ]
        );

        $this->assertSame('editable-name', get_userdata($subject)->user_nicename);

        wp_set_current_user($administrator);
        $_POST['user_nicename'] = 'custom-after-create';
        $errors = new WP_Error();
        $this->plugin->validate_nicename_submission($errors, true, get_userdata($subject));
        $this->assertEmpty($errors->get_error_codes());
        $this->plugin->save_nicename_field($subject);

        $this->assertSame('custom-after-create', get_userdata($subject)->user_nicename);
    }

    public function test_wp_admin_add_user_uses_first_and_last_name(): void
    {
        require_once ABSPATH . 'wp-admin/includes/user.php';

        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);

        $_POST = [
            'user_login' => 'adduser.jane',
            'email'      => 'adduser.jane@example.com',
            'first_name' => 'Ada',
            'last_name'  => 'Lovelace',
            'pass1'      => 'password',
            'pass2'      => 'password',
            'role'       => 'subscriber',
        ];

        $user_id = edit_user();

        if (is_wp_error($user_id)) {
            $this->fail($user_id->get_error_message());
        }

        $this->assertIsInt($user_id);
        $user = get_userdata($user_id);
        $this->assertSame('ada-lovelace', $user->user_nicename);
        $this->assertSame('adduser.jane', $user->user_login);
        $this->assertNotSame($user->user_login, $user->user_nicename);
    }

    public function test_front_end_registration_nicename_is_not_the_login(): void
    {
        update_option('users_can_register', '1');
        add_filter('wp_send_new_user_notification_to_admin', '__return_false');
        add_filter('wp_send_new_user_notification_to_user', '__return_false');

        $user_id = register_new_user('frontjane', 'frontjane@example.com');

        if (is_wp_error($user_id)) {
            $this->fail($user_id->get_error_message());
        }

        $this->assertIsInt($user_id);
        $user = get_userdata($user_id);
        $this->assertSame('frontjane', $user->user_login);
        $this->assertNotSame('frontjane', $user->user_nicename);
        $this->assertSame('frontjane-2', $user->user_nicename);
    }

    public function test_generator_reuses_plugin_sanitize_and_uniqueness(): void
    {
        $this->assertSame(
            $this->plugin->sanitize_nicename_value('Jane Doe'),
            $this->generator->generate_unique_nicename(
                ['user_login' => 'other.login'],
                ['display_name' => 'Jane Doe', 'user_login' => 'other.login']
            )
        );

        self::factory()->user->create(
            [
                'role'          => 'subscriber',
                'user_login'    => 'taken.login',
                'user_email'    => 'taken.login@example.com',
                'user_nicename' => 'already-taken',
            ]
        );

        $this->assertFalse($this->plugin->is_nicename_unique('already-taken', 0));
        $this->assertSame(
            'already-taken-2',
            $this->generator->generate_unique_nicename(
                ['user_login' => 'fresh.login'],
                ['display_name' => 'Already Taken', 'user_login' => 'fresh.login']
            )
        );
    }
}
