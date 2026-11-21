<?php

final class StaffAvatarsTest extends WP_UnitTestCase
{
    private User_History_Staff_Avatars $avatars;

    protected function setUp(): void
    {
        parent::setUp();

        $this->avatars = User_History_Staff_Avatars::get_instance();
        update_option('show_avatars', '1');
        delete_option(User_History_Staff_Avatars::OPTION_KEY);
        remove_all_filters('user_history_disable_staff_gravatar');
    }

    protected function tearDown(): void
    {
        delete_option(User_History_Staff_Avatars::OPTION_KEY);
        remove_all_filters('user_history_disable_staff_gravatar');
        parent::tearDown();
    }

    public function test_staff_photos_stay_on_gravatar_until_the_setting_is_enabled(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');

        $this->assertFalse($this->avatars->is_enabled());
        $this->assertTrue($this->avatars->is_staff($admin));
        $this->assertFalse($this->avatars->is_staff($subscriber));
        $this->assertFalse($this->avatars->should_disable($admin));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));

        update_option(User_History_Staff_Avatars::OPTION_KEY, '0');

        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));
    }

    public function test_enabled_setting_blanks_staff_photos_and_leaves_subscribers(): void
    {
        update_option(User_History_Staff_Avatars::OPTION_KEY, '1');

        $admin = $this->createUser('administrator');
        $editor = $this->createUser('editor');
        $author = $this->createUser('author');
        $contributor = $this->createUser('contributor');
        $subscriber = $this->createUser('subscriber');

        foreach ([$admin, $editor, $author, $contributor] as $staff_id) {
            $this->assertTrue($this->avatars->is_staff($staff_id), 'User ' . $staff_id . ' should be staff');
            $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url($staff_id));
            $this->assertStringContainsString('blank.gif', (string) get_avatar_url($staff_id));
        }

        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));
        $this->assertStringNotContainsString('blank.gif', (string) get_avatar_url($subscriber));

        $html = get_avatar($admin, 48, '', 'Staff photo');
        $this->assertIsString($html);
        $this->assertStringNotContainsString('gravatar.com', $html);
        $this->assertStringContainsString('blank.gif', $html);
        $this->assertStringContainsString('Staff photo', $html);
    }

    public function test_a_content_capability_counts_as_staff_without_a_built_in_role(): void
    {
        update_option(User_History_Staff_Avatars::OPTION_KEY, '1');

        $subscriber = $this->createUser('subscriber');
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));

        $user = get_userdata($subscriber);
        $this->assertInstanceOf(WP_User::class, $user);
        $user->add_cap('manage_woocommerce');
        clean_user_cache($subscriber);

        $this->assertTrue($this->avatars->is_staff($subscriber));
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($subscriber));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url($subscriber));
    }

    public function test_staff_email_post_and_comment_avatars_are_blanked_when_enabled(): void
    {
        update_option(User_History_Staff_Avatars::OPTION_KEY, '1');

        $email = 'editor-photo-' . wp_generate_password(6, false) . '@example.com';
        $editor = $this->createUser('editor', $email);
        $post_id = self::factory()->post->create(['post_author' => $editor]);
        $comment_id = self::factory()->comment->create(
            [
                'comment_post_ID'      => $post_id,
                'user_id'              => $editor,
                'comment_author_email' => $email,
            ]
        );

        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($email));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url(get_userdata($editor)));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url(get_post($post_id)));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url(get_comment($comment_id)));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url('guest-' . $email));
    }

    public function test_profile_photo_markup_is_replaced_for_staff_only(): void
    {
        update_option(User_History_Staff_Avatars::OPTION_KEY, '1');

        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        $callback = static function () {
            return '<img src="https://secure.gravatar.com/avatar/plugin-photo" alt="" />';
        };

        add_filter('get_avatar', $callback, 10);

        try {
            $staff_html = get_avatar($admin);
            $subscriber_html = get_avatar($subscriber);
        } finally {
            remove_filter('get_avatar', $callback, 10);
        }

        $this->assertIsString($staff_html);
        $this->assertStringNotContainsString('gravatar.com', $staff_html);
        $this->assertStringContainsString('blank.gif', $staff_html);
        $this->assertIsString($subscriber_html);
        $this->assertStringContainsString('gravatar.com', $subscriber_html);
    }

    public function test_filter_can_override_the_setting_for_one_user(): void
    {
        $admin = $this->createUser('administrator');
        $editor = $this->createUser('editor');
        $subscriber = $this->createUser('subscriber');

        add_filter(
            'user_history_disable_staff_gravatar',
            static function ($disable, $user_id) use ($subscriber) {
                if ((int) $user_id === (int) $subscriber) {
                    return true;
                }

                return $disable;
            },
            10,
            2
        );

        $this->assertFalse($this->avatars->is_enabled());
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($subscriber));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));

        remove_all_filters('user_history_disable_staff_gravatar');
        update_option(User_History_Staff_Avatars::OPTION_KEY, '1');

        add_filter(
            'user_history_disable_staff_gravatar',
            static function ($disable, $user_id) use ($admin) {
                if ((int) $user_id === (int) $admin) {
                    return false;
                }

                return $disable;
            },
            10,
            2
        );

        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($editor));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));
        $this->assertFalse($this->avatars->should_disable(0));
    }

    /**
     * @return int
     */
    private function createUser(string $role, string $email = ''): int
    {
        $args = ['role' => $role];
        if ($email !== '') {
            $args['user_email'] = $email;
        }

        return (int) self::factory()->user->create($args);
    }
}
