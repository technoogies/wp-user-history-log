<?php

final class StaffNotesTest extends WP_UnitTestCase
{
    private User_History_Staff_Notes $notes;

    /** @var string|null */
    private $original_pagenow;

    protected function setUp(): void
    {
        parent::setUp();

        $this->notes = User_History_Staff_Notes::get_instance();
        $this->original_pagenow = isset($GLOBALS['pagenow']) ? $GLOBALS['pagenow'] : null;
        $GLOBALS['pagenow'] = 'users.php';
        $_GET = [];
        $_POST = [];
        wp_set_current_user(0);
        User_History::get_instance()->activate();
    }

    protected function tearDown(): void
    {
        $_GET = [];
        $_POST = [];
        wp_set_current_user(0);
        if (function_exists('set_current_screen')) {
            set_current_screen('front');
        }
        if (null === $this->original_pagenow) {
            unset($GLOBALS['pagenow']);
        } else {
            $GLOBALS['pagenow'] = $this->original_pagenow;
        }
        parent::tearDown();
    }

    public function test_account_holder_cannot_see_or_save_staff_notes(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');

        wp_set_current_user($subscriber);
        $this->assertFalse($this->notes->current_operator_can_manage($subscriber));
        $this->assertFalse($this->notes->current_operator_can_manage($admin));
        $this->assertSame('', $this->renderProfile($subscriber));

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Subscriber secret';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($subscriber);
        $this->notes->save_profile_fields($admin);

        $this->assertSame('', $this->notes->get_note($subscriber));
        $this->assertSame([], $this->notes->get_tags($subscriber));
        $this->assertSame('', $this->notes->get_note($admin));
    }

    public function test_editor_without_edit_users_cannot_see_or_save_staff_notes(): void
    {
        $editor = $this->createUser('editor');
        $subscriber = $this->createUser('subscriber');

        wp_set_current_user($editor);
        $this->assertFalse(current_user_can('edit_users'));
        $this->assertSame('', $this->renderProfile($subscriber));
        $this->assertStringNotContainsString('user_history_tag', $this->renderTagViews());

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Editor secret';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($subscriber);

        $this->assertSame('', $this->notes->get_note($subscriber));
        $this->assertSame([], $this->notes->get_tags($subscriber));
        $this->assertSame([], $this->notes->filter_list_table_args([]));
    }

    public function test_administrator_can_save_a_note_and_tags_for_another_user(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::META_NOTE] = "Call before shipping.\nVIP client.";
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'VIP, Needs Follow Up, vip';
        $this->notes->save_profile_fields($subscriber);

        $this->assertSame("Call before shipping.\nVIP client.", $this->notes->get_note($subscriber));
        $this->assertSame(['vip', 'needs-follow-up'], $this->notes->get_tags($subscriber));

        $html = $this->renderProfile($subscriber);
        $this->assertStringContainsString('Staff notes', $html);
        $this->assertStringContainsString('Call before shipping.', $html);
        $this->assertStringContainsString('value="vip, needs-follow-up"', $html);
        $this->assertStringContainsString('name="user_history_staff_note"', $html);
        $this->assertStringContainsString('name="user_history_staff_tags"', $html);
    }

    public function test_profile_keeps_the_gravatar_checkbox_and_nicename_rewrite_button(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        wp_set_current_user($admin);
        $this->notes->save_profile_fields($subscriber);
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($subscriber);

        $profile = $this->renderProfile($subscriber);
        ob_start();
        User_History_Profile_Photo::get_instance()->render_profile_field(get_userdata($subscriber));
        $profile .= (string) ob_get_clean();
        ob_start();
        User_History_Nicename_Rewrite::get_instance()->render_users_button('top');
        $users = (string) ob_get_clean();

        $this->assertStringContainsString('Turn off Gravatar and profile photo for this user', $profile);
        $this->assertStringContainsString('name="user_history_disable_gravatar"', $profile);
        $this->assertStringContainsString('Staff notes', $profile);
        $this->assertStringContainsString('Rewrite matching nicenames', $users);
        $this->assertStringContainsString('user_history_nicename_rewrite_preview', $users);
    }

    public function test_empty_submission_clears_the_note_and_tags_and_a_missing_field_does_not(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Keep me until cleared';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($subscriber);

        $_POST = [];
        $this->notes->save_profile_fields($subscriber);
        $this->assertSame('Keep me until cleared', $this->notes->get_note($subscriber));
        $this->assertSame(['vip'], $this->notes->get_tags($subscriber));

        $_POST[User_History_Staff_Notes::META_NOTE] = '   ';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = ' , ';
        $this->notes->save_profile_fields($subscriber);

        $this->assertSame('', $this->notes->get_note($subscriber));
        $this->assertSame([], $this->notes->get_tags($subscriber));
        $this->assertSame('', get_user_meta($subscriber, User_History_Staff_Notes::META_NOTE, true));
        $this->assertSame([], get_user_meta($subscriber, User_History_Staff_Notes::META_TAG, false));
    }

    public function test_note_html_is_stripped_on_save_and_escaped_if_already_stored(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::META_NOTE] = '<script>alert(1)</script>Hello';
        $this->notes->save_profile_fields($subscriber);
        $this->assertStringNotContainsString('<script>', $this->notes->get_note($subscriber));
        $this->assertStringContainsString('Hello', $this->notes->get_note($subscriber));

        update_user_meta($subscriber, User_History_Staff_Notes::META_NOTE, '<img src=x onerror=alert(1)>');
        $html = $this->renderProfile($subscriber);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringContainsString('&lt;img', $html);
    }

    public function test_long_notes_and_extra_tags_are_limited(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::META_NOTE] = str_repeat('a', User_History_Staff_Notes::MAX_NOTE_LENGTH + 25);
        $tags = [];
        for ($i = 1; $i <= User_History_Staff_Notes::MAX_TAGS + 3; $i++) {
            $tags[] = 'tag-' . $i;
        }
        $tags[] = str_repeat('b', User_History_Staff_Notes::MAX_TAG_LENGTH + 5);
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = implode(', ', $tags);
        $this->notes->save_profile_fields($subscriber);

        $this->assertSame(User_History_Staff_Notes::MAX_NOTE_LENGTH, strlen($this->notes->get_note($subscriber)));
        $this->assertCount(User_History_Staff_Notes::MAX_TAGS, $this->notes->get_tags($subscriber));
        $this->assertNotContains(str_repeat('b', User_History_Staff_Notes::MAX_TAG_LENGTH + 5), $this->notes->get_tags($subscriber));
    }

    public function test_saving_a_note_does_not_write_account_history(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        wp_set_current_user($admin);
        $before = $this->historyCount($subscriber);

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Not an audit row';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($subscriber);

        $this->assertSame($before, $this->historyCount($subscriber));
        $this->assertSame('Not an audit row', $this->notes->get_note($subscriber));
    }

    public function test_users_screen_filters_by_one_tag_and_hides_the_links_from_editors(): void
    {
        $admin = $this->createUser('administrator');
        $vip = $this->createUser('subscriber');
        $other = $this->createUser('subscriber');
        $gold = $this->createUser('subscriber');
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($vip);
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip-extra';
        $this->notes->save_profile_fields($gold);

        $views = $this->renderTagViews();
        $this->assertStringContainsString('Tag: vip', $views);
        $this->assertStringContainsString('user_history_tag=vip', $views);
        $this->assertStringContainsString('Tag: vip-extra', $views);

        $_GET[User_History_Staff_Notes::QUERY_ARG] = 'vip';
        $ids = $this->filteredUserIds();
        $this->assertContains($vip, $ids);
        $this->assertNotContains($other, $ids);
        $this->assertNotContains($gold, $ids);

        $hidden = $this->capture(function () {
            $this->notes->preserve_tag_query_arg('top');
        });
        $this->assertStringContainsString('name="user_history_tag"', $hidden);
        $this->assertStringContainsString('value="vip"', $hidden);
        $this->assertSame('', $this->capture(function () {
            $this->notes->preserve_tag_query_arg('bottom');
        }));

        wp_set_current_user($this->createUser('editor'));
        $_GET[User_History_Staff_Notes::QUERY_ARG] = 'vip';
        $this->assertStringNotContainsString('Tag: vip', $this->renderTagViews());
        $this->assertArrayNotHasKey('meta_query', $this->notes->filter_list_table_args(['fields' => 'ID']));
    }

    public function test_tag_query_arg_is_reduced_to_a_slug_before_it_is_used(): void
    {
        $admin = $this->createUser('administrator');
        wp_set_current_user($admin);

        $_GET[User_History_Staff_Notes::QUERY_ARG] = "vip' OR 1=1";
        $args = $this->notes->filter_list_table_args([]);
        $this->assertSame('vip-or-1-1', $args['meta_query'][0]['value']);
        $this->assertSame('=', $args['meta_query'][0]['compare']);

        $_GET[User_History_Staff_Notes::QUERY_ARG] = '!!!';
        $this->assertSame('', $this->notes->requested_tag());
        $this->assertArrayNotHasKey('meta_query', $this->notes->filter_list_table_args([]));

        $GLOBALS['pagenow'] = 'index.php';
        $_GET[User_History_Staff_Notes::QUERY_ARG] = 'vip';
        $this->assertArrayNotHasKey('meta_query', $this->notes->filter_list_table_args([]));
    }

    public function test_tag_filter_can_combine_with_the_locked_users_query(): void
    {
        $admin = $this->createUser('administrator');
        $locked_vip = $this->createUser('subscriber');
        $vip = $this->createUser('subscriber');
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip';
        $this->notes->save_profile_fields($locked_vip);
        $this->notes->save_profile_fields($vip);
        update_user_meta($locked_vip, User_History_Lock::META_KEY, '1');

        set_current_screen('users');
        $_GET['user_history_filter'] = 'locked';
        $_GET[User_History_Staff_Notes::QUERY_ARG] = 'vip';
        $ids = $this->filteredUserIds();

        $this->assertContains($locked_vip, $ids);
        $this->assertNotContains($vip, $ids);
    }

    public function test_personal_data_export_includes_notes_and_erasure_removes_them_only(): void
    {
        $admin = $this->createUser('administrator');
        $subscriber = $this->createUser('subscriber');
        $email = (string) get_userdata($subscriber)->user_email;
        wp_set_current_user($admin);

        $_POST[User_History_Staff_Notes::META_NOTE] = 'Export this note';
        $_POST[User_History_Staff_Notes::TAGS_INPUT] = 'vip, billing';
        $this->notes->save_profile_fields($subscriber);
        $history_before = $this->historyCount($subscriber);

        $exported = $this->notes->export_personal_data($email);
        $encoded = (string) wp_json_encode($exported);
        $this->assertTrue($exported['done']);
        $this->assertStringContainsString('Export this note', $encoded);
        $this->assertStringContainsString('vip, billing', $encoded);

        $erased = $this->notes->erase_personal_data($email);
        $this->assertTrue($erased['items_removed']);
        $this->assertFalse($erased['items_retained']);
        $this->assertSame('', $this->notes->get_note($subscriber));
        $this->assertSame([], $this->notes->get_tags($subscriber));
        $this->assertSame($history_before, $this->historyCount($subscriber));

        $history = User_History::get_instance()->erase_personal_data($email);
        $this->assertFalse($history['items_removed']);
        $this->assertTrue($history['items_retained']);

        $empty = $this->notes->export_personal_data($email);
        $this->assertSame([], $empty['data']);
        $this->assertTrue($empty['done']);
    }

    private function renderProfile(int $user_id): string
    {
        $user = get_userdata($user_id);
        $this->assertInstanceOf(WP_User::class, $user);

        ob_start();
        $this->notes->render_profile_fields($user);

        return (string) ob_get_clean();
    }

    private function renderTagViews(): string
    {
        $views = $this->notes->add_tag_views(
            [
                'all' => '<a href="users.php" class="current">All</a>',
            ]
        );

        return implode("\n", $views);
    }

    /**
     * @return array<int,int>
     */
    private function filteredUserIds(): array
    {
        $args = $this->notes->filter_list_table_args(
            [
                'fields' => 'ID',
                'number' => 100,
            ]
        );
        $ids = get_users($args);

        return array_map('intval', (array) $ids);
    }

    private function historyCount(int $user_id): int
    {
        global $wpdb;

        return (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}user_history WHERE user_id = %d",
                $user_id
            )
        );
    }

    /**
     * @param callable $callback Output callback.
     */
    private function capture($callback): string
    {
        ob_start();
        $callback();

        return (string) ob_get_clean();
    }

    private function createUser(string $role): int
    {
        return (int) self::factory()->user->create(['role' => $role]);
    }
}
