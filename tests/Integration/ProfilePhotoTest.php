<?php

final class ProfilePhotoTest extends WP_UnitTestCase
{
    private User_History_Profile_Photo $photos;

    protected function setUp(): void
    {
        parent::setUp();

        $this->photos = User_History_Profile_Photo::get_instance();
        update_option('show_avatars', '1');
        $_POST = [];
        wp_set_current_user(0);
        remove_all_filters('user_history_disable_gravatar');
    }

    protected function tearDown(): void
    {
        $_POST = [];
        wp_set_current_user(0);
        remove_all_filters('user_history_disable_gravatar');
        parent::tearDown();
    }

    public function test_photos_stay_on_for_every_role_until_that_user_is_checked(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');

        $this->assertFalse($this->photos->user_has_photo_disabled($admin));
        $this->assertFalse($this->photos->user_has_photo_disabled($subscriber));
        $this->assertFalse($this->photos->should_disable($admin));
        $this->assertFalse($this->photos->should_disable($subscriber));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));
        $this->assertNull(get_role('staff'));
    }

    public function test_checking_one_user_blanks_only_that_user(): void
    {
        $admin = $this->createUser('administrator');
        $editor = $this->createUser('editor');
        $subscriber = $this->createUser('subscriber');

        update_user_meta($subscriber, User_History_Profile_Photo::META_KEY, '1');

        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($subscriber));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url($subscriber));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($editor));

        delete_user_meta($subscriber, User_History_Profile_Photo::META_KEY);
        update_user_meta($admin, User_History_Profile_Photo::META_KEY, '1');

        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($admin));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url($admin));

        $html = get_avatar($admin, 48, '', 'Hidden photo');
        $this->assertIsString($html);
        $this->assertStringNotContainsString('gravatar.com', $html);
        $this->assertStringContainsString('blank.gif', $html);
        $this->assertStringContainsString('Hidden photo', $html);
    }

    public function test_checked_user_is_blank_from_email_post_and_comment(): void
    {
        $email = 'person-photo-' . wp_generate_password(6, false) . '@example.com';
        $subscriber = $this->createUser('subscriber', $email);
        update_user_meta($subscriber, User_History_Profile_Photo::META_KEY, '1');

        $post_id = self::factory()->post->create(['post_author' => $subscriber]);
        $comment_id = self::factory()->comment->create(
            [
                'comment_post_ID'      => $post_id,
                'user_id'              => $subscriber,
                'comment_author_email' => $email,
            ]
        );

        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($email));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url(get_userdata($subscriber)));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url(get_post($post_id)));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url(get_comment($comment_id)));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url('guest-' . $email));
    }

    public function test_profile_photo_markup_is_replaced_only_for_the_checked_user(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        update_user_meta($admin, User_History_Profile_Photo::META_KEY, '1');

        $callback = static function () {
            return '<img src="https://secure.gravatar.com/avatar/plugin-photo" alt="" />';
        };
        add_filter('get_avatar', $callback, 10);

        try {
            $checked_html = get_avatar($admin);
            $other_html = get_avatar($subscriber);
        } finally {
            remove_filter('get_avatar', $callback, 10);
        }

        $this->assertIsString($checked_html);
        $this->assertStringNotContainsString('gravatar.com', $checked_html);
        $this->assertStringContainsString('blank.gif', $checked_html);
        $this->assertIsString($other_html);
        $this->assertStringContainsString('gravatar.com', $other_html);
    }

    public function test_filter_can_override_the_checkbox_for_one_user(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        update_user_meta($admin, User_History_Profile_Photo::META_KEY, '1');

        add_filter(
            'user_history_disable_gravatar',
            static function ($disable, $user_id) use ($admin, $subscriber) {
                if ((int) $user_id === (int) $admin) {
                    return false;
                }
                if ((int) $user_id === (int) $subscriber) {
                    return true;
                }

                return $disable;
            },
            10,
            2
        );

        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($subscriber));
        $this->assertFalse($this->photos->should_disable(0));
    }

    public function test_profile_checkbox_shows_for_the_user_and_for_an_editor_of_that_user(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');

        wp_set_current_user($subscriber);
        $own = $this->renderField($subscriber);
        $this->assertStringContainsString('Turn off Gravatar and profile photo for this user', $own);
        $this->assertStringContainsString('name="user_history_disable_gravatar"', $own);
        $this->assertDoesNotMatchRegularExpression('/id="user_history_disable_gravatar"[^>]*checked/', $own);
        $this->assertSame('', $this->renderField($admin));

        wp_set_current_user($admin);
        $editing = $this->renderField($subscriber);
        $this->assertStringContainsString('user_history_disable_gravatar', $editing);

        update_user_meta($subscriber, User_History_Profile_Photo::META_KEY, '1');
        $checked = $this->renderField($subscriber);
        $this->assertMatchesRegularExpression('/id="user_history_disable_gravatar"[^>]*checked=/', $checked);
    }

    public function test_save_checks_only_the_user_the_operator_can_edit(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');

        wp_set_current_user($subscriber);
        $_POST[User_History_Profile_Photo::META_KEY] = '1';
        $this->photos->save_profile_field($subscriber);
        $this->photos->save_profile_field($admin);

        $this->assertSame('1', get_user_meta($subscriber, User_History_Profile_Photo::META_KEY, true));
        $this->assertSame('', get_user_meta($admin, User_History_Profile_Photo::META_KEY, true));
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($subscriber));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($admin));

        $_POST[User_History_Profile_Photo::META_KEY] = '0';
        $this->photos->save_profile_field($subscriber);

        $this->assertSame('', get_user_meta($subscriber, User_History_Profile_Photo::META_KEY, true));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($subscriber));

        wp_set_current_user($admin);
        $_POST[User_History_Profile_Photo::META_KEY] = '1';
        $this->photos->save_profile_field($subscriber);
        $this->assertSame('1', get_user_meta($subscriber, User_History_Profile_Photo::META_KEY, true));
        $this->assertStringContainsString('blank.gif', (string) get_avatar_url($subscriber));
    }

    private function renderField(int $user_id): string
    {
        $user = get_userdata($user_id);
        $this->assertInstanceOf(WP_User::class, $user);

        ob_start();
        $this->photos->render_profile_field($user);

        return (string) ob_get_clean();
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
