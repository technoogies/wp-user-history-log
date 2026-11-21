<?php

final class NicenameRewriteTest extends WP_UnitTestCase
{
    private User_History $plugin;

    private User_History_Nicename_Rewrite $rewrite;

    private int $operator_id = 0;

    /** @var string|null */
    private $redirect = null;

    /** @var mixed */
    private $original_pagenow = null;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->rewrite = User_History_Nicename_Rewrite::get_instance($this->plugin);
        $this->original_pagenow = isset($GLOBALS['pagenow']) ? $GLOBALS['pagenow'] : null;
        $GLOBALS['pagenow'] = 'users.php';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_POST = [];
        $_GET = [];
    }

    protected function tearDown(): void
    {
        if ($this->operator_id) {
            delete_transient('uh_nicename_preview_' . $this->operator_id);
            delete_transient('uh_nicename_result_' . $this->operator_id);
        }

        remove_filter('wp_redirect', [$this, 'recordRedirect'], 1);
        remove_all_filters('wp_die_handler');
        remove_role('account_manager');
        $_POST = [];
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        wp_set_current_user(0);

        if (null === $this->original_pagenow) {
            unset($GLOBALS['pagenow']);
        } else {
            $GLOBALS['pagenow'] = $this->original_pagenow;
        }

        parent::tearDown();
    }

    public function test_display_name_rewrites_only_when_nicename_equals_login(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'jane.doe',
                'user_email'   => 'jane.doe@example.com',
                'display_name' => 'Jane Doe',
            ],
            'jane.doe'
        );

        $result = $this->rewrite->rewrite_matching_nicenames();

        $this->assertSame('jane-doe', get_userdata($user_id)->user_nicename);
        $this->assertNotSame('jane.doe', get_userdata($user_id)->user_nicename);
        $this->assertGreaterThanOrEqual(1, $result['changed']);
    }

    public function test_hyphenated_login_that_still_matches_its_nicename_is_rewritten_from_first_and_last(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'a-addavies',
                'user_email'   => 'a-addavies@example.com',
                'display_name' => 'a-addavies',
                'first_name'   => 'A',
                'last_name'    => 'D Davies',
                'nickname'     => 'a-addavies',
            ],
            'a-addavies'
        );
        $skipped = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'a-kept',
                'user_email'   => 'a-kept@example.com',
                'display_name' => 'Kept Person',
            ]
        );
        $skipped_nicename = get_userdata($skipped)->user_nicename;
        $this->assertNotSame(get_userdata($skipped)->user_login, $skipped_nicename);
        $this->assertSame('a-addavies', get_user_meta($user_id, 'nickname', true));

        ob_start();
        $this->rewrite->render_users_button('top');
        $button = ob_get_clean();
        $this->assertStringContainsString('formmethod="post"', $button);
        $this->assertStringContainsString('formaction="' . esc_url(admin_url('users.php')) . '"', $button);

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET[User_History_Nicename_Rewrite::PREVIEW_ACTION] = '1';
        $this->rewrite->handle_request();
        $this->assertSame('a-addavies', get_userdata($user_id)->user_nicename);

        $this->rewrite->rewrite_matching_nicenames();

        $user = get_userdata($user_id);
        $this->assertSame('a-d-davies', $user->user_nicename);
        $this->assertSame('a-addavies', $user->user_login);
        $this->assertNotSame($user->user_login, $user->user_nicename);
        $this->assertSame('a-addavies', get_user_meta($user_id, 'nickname', true));
        $this->assertSame('A', get_user_meta($user_id, 'first_name', true));
        $this->assertSame('D Davies', get_user_meta($user_id, 'last_name', true));
        $this->assertSame($skipped_nicename, get_userdata($skipped)->user_nicename);
    }

    public function test_first_and_last_name_are_used_when_display_name_is_the_login(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'jdoe',
                'user_email'   => 'jdoe@example.com',
                'display_name' => 'jdoe',
                'first_name'   => 'Jane',
                'last_name'    => 'Doe',
            ],
            'jdoe'
        );

        $this->rewrite->rewrite_matching_nicenames();

        $this->assertSame('jane-doe', get_userdata($user_id)->user_nicename);
    }

    public function test_login_without_a_separate_name_gets_a_numeric_suffix(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'plainuser',
                'user_email'   => 'plainuser@example.com',
                'display_name' => 'plainuser',
            ],
            'plainuser'
        );

        $this->rewrite->rewrite_matching_nicenames();

        $user = get_userdata($user_id);
        $this->assertSame('plainuser-2', $user->user_nicename);
        $this->assertNotSame($user->user_login, $user->user_nicename);
    }

    public function test_duplicate_display_names_receive_unique_suffixes_in_id_order(): void
    {
        $this->actAsAdmin();
        $first = $this->createLegacyUser(
            [
                'user_login'   => 'jane.one',
                'user_email'   => 'jane.one@example.com',
                'display_name' => 'Jane Doe',
            ],
            'jane.one'
        );
        $second = $this->createLegacyUser(
            [
                'user_login'   => 'jane.two',
                'user_email'   => 'jane.two@example.com',
                'display_name' => 'Jane Doe',
            ],
            'jane.two'
        );

        $this->rewrite->rewrite_matching_nicenames();

        $this->assertSame('jane-doe', get_userdata($first)->user_nicename);
        $this->assertSame('jane-doe-2', get_userdata($second)->user_nicename);
        $this->assertTrue($this->plugin->is_nicename_unique('jane-doe', $first));
        $this->assertTrue($this->plugin->is_nicename_unique('jane-doe-2', $second));
    }

    public function test_existing_slug_is_kept_when_it_already_differs_from_the_login(): void
    {
        $this->actAsAdmin();
        $user_id = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'jane.doe',
                'user_email'   => 'slug.jane@example.com',
                'display_name' => 'Jane Doe',
            ]
        );
        $before = get_userdata($user_id)->user_nicename;
        $this->assertSame('jane-doe', $before);
        $this->assertNotSame('jane.doe', $before);

        $summary = $this->rewrite->summarize();
        $result = $this->rewrite->rewrite_matching_nicenames();

        $this->assertSame('jane-doe', get_userdata($user_id)->user_nicename);
        $this->assertSame($summary['skipped'], $result['skipped']);
        $this->assertGreaterThanOrEqual(1, $result['skipped']);
    }

    public function test_custom_nicename_is_not_rewritten_and_a_second_run_skips_updated_accounts(): void
    {
        $this->actAsAdmin();
        $custom = $this->createLegacyUser(
            [
                'user_login'   => 'kept.login',
                'user_email'   => 'kept.login@example.com',
                'display_name' => 'Kept Person',
            ],
            'already-custom'
        );
        $legacy = $this->createLegacyUser(
            [
                'user_login'   => 'legacy.login',
                'user_email'   => 'legacy.login@example.com',
                'display_name' => 'Legacy Person',
            ],
            'legacy.login'
        );

        $first = $this->rewrite->rewrite_matching_nicenames();
        $this->assertSame('already-custom', get_userdata($custom)->user_nicename);
        $this->assertSame('legacy-person', get_userdata($legacy)->user_nicename);
        $this->assertGreaterThanOrEqual(1, $first['changed']);
        $this->assertGreaterThanOrEqual(1, $first['skipped']);

        $second = $this->rewrite->rewrite_matching_nicenames();
        $this->assertSame('legacy-person', get_userdata($legacy)->user_nicename);
        $this->assertSame('already-custom', get_userdata($custom)->user_nicename);
        $this->assertSame(0, $second['changed']);
        $this->assertGreaterThanOrEqual($first['skipped'], $second['skipped']);
    }

    public function test_case_difference_still_counts_as_the_same_login(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'CaseUser',
                'user_email'   => 'case.user@example.com',
                'display_name' => 'CaseUser',
            ],
            'caseuser'
        );

        $this->assertTrue(
            User_History_New_User_Nicename::get_instance($this->plugin)->nicename_matches_login('caseuser', 'CaseUser')
        );

        $this->rewrite->rewrite_matching_nicenames();

        $user = get_userdata($user_id);
        $this->assertSame('caseuser-2', $user->user_nicename);
        $this->assertFalse(
            User_History_New_User_Nicename::get_instance($this->plugin)->nicename_matches_login(
                $user->user_nicename,
                $user->user_login
            )
        );
    }

    public function test_gravatar_checkbox_is_left_alone(): void
    {
        $this->actAsAdmin();
        update_option('show_avatars', '1');

        $matching = $this->createLegacyUser(
            [
                'user_login'   => 'photo.match',
                'user_email'   => 'photo.match@example.com',
                'display_name' => 'Photo Match',
            ],
            'photo.match'
        );
        $skipped = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'photo.skip',
                'user_email'   => 'photo.skip@example.com',
                'display_name' => 'Photo Skip',
            ]
        );
        $skipped_nicename = get_userdata($skipped)->user_nicename;
        $this->assertNotSame('photo.skip', $skipped_nicename);
        update_user_meta($matching, User_History_Profile_Photo::META_KEY, '1');

        $this->rewrite->rewrite_matching_nicenames();

        $this->assertSame('photo-match', get_userdata($matching)->user_nicename);
        $this->assertSame($skipped_nicename, get_userdata($skipped)->user_nicename);
        $this->assertSame('1', get_user_meta($matching, User_History_Profile_Photo::META_KEY, true));
        $this->assertSame('', get_user_meta($skipped, User_History_Profile_Photo::META_KEY, true));
        $this->assertStringNotContainsString('gravatar.com', (string) get_avatar_url($matching));
        $this->assertStringContainsString('gravatar.com', (string) get_avatar_url($skipped));
    }

    public function test_rewrite_records_nicename_history_without_a_password_event(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'audit.login',
                'user_email'   => 'audit.login@example.com',
                'display_name' => 'Audit Person',
            ],
            'audit.login'
        );

        $this->rewrite->rewrite_matching_nicenames();

        $fields = [];
        foreach ($this->plugin->get_user_history($user_id, 20) as $entry) {
            $fields[] = $entry->field_name;
        }

        $this->assertContains('user_nicename', $fields);
        $this->assertNotContains('user_pass', $fields);
    }

    public function test_users_screen_get_does_not_rewrite(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'page.load',
                'user_email'   => 'page.load@example.com',
                'display_name' => 'Page Load',
            ],
            'page.load'
        );
        $_GET[User_History_Nicename_Rewrite::CONFIRM_ACTION] = '1';
        $_GET[User_History_Nicename_Rewrite::PREVIEW_FLAG] = '1';

        $this->rewrite->handle_request();
        ob_start();
        $this->rewrite->render_admin_notice();
        $html = ob_get_clean();

        $this->assertSame('page.load', get_userdata($user_id)->user_nicename);
        $this->assertSame('', $html);
    }

    public function test_preview_post_counts_without_writing(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'preview.user',
                'user_email'   => 'preview.user@example.com',
                'display_name' => 'Preview User',
            ],
            'preview.user'
        );
        $this->captureRedirect();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST[User_History_Nicename_Rewrite::PREVIEW_ACTION] = '1';
        $_POST[User_History_Nicename_Rewrite::NONCE_FIELD] = wp_create_nonce(
            User_History_Nicename_Rewrite::NONCE_ACTION
        );

        $this->rewrite->handle_request();

        $this->assertSame('preview.user', get_userdata($user_id)->user_nicename);
        $this->assertSame('1', get_transient('uh_nicename_preview_' . $this->operator_id));
        $this->assertNotNull($this->redirect);
        $this->assertStringContainsString('user_history_nicename_preview=1', (string) $this->redirect);
        $this->assertStringNotContainsString('user_history_nicename_rewritten=1', (string) $this->redirect);
    }

    public function test_confirm_post_rewrites_and_reports_changed_and_skipped(): void
    {
        $this->actAsAdmin();
        $matching = $this->createLegacyUser(
            [
                'user_login'   => 'confirm.user',
                'user_email'   => 'confirm.user@example.com',
                'display_name' => 'Confirm User',
            ],
            'confirm.user'
        );
        $skipped = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'confirm.skip',
                'user_email'   => 'confirm.skip@example.com',
                'display_name' => 'Confirm Skip',
            ]
        );
        $skipped_nicename = get_userdata($skipped)->user_nicename;
        $summary = $this->rewrite->summarize();
        $this->captureRedirect();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST[User_History_Nicename_Rewrite::CONFIRM_ACTION] = '1';
        $_POST[User_History_Nicename_Rewrite::NONCE_FIELD] = wp_create_nonce(
            User_History_Nicename_Rewrite::NONCE_ACTION
        );

        $this->rewrite->handle_request();

        $this->assertSame('confirm-user', get_userdata($matching)->user_nicename);
        $this->assertSame($skipped_nicename, get_userdata($skipped)->user_nicename);
        $stored = get_transient('uh_nicename_result_' . $this->operator_id);
        $this->assertIsArray($stored);
        $this->assertSame($summary['matches'], $stored['changed']);
        $this->assertSame($summary['skipped'], $stored['skipped']);
        $this->assertGreaterThanOrEqual(1, $stored['changed']);
        $this->assertGreaterThanOrEqual(1, $stored['skipped']);
        $this->assertStringContainsString('user_history_nicename_rewritten=1', (string) $this->redirect);

        $_GET[User_History_Nicename_Rewrite::RESULT_FLAG] = '1';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        ob_start();
        $this->rewrite->render_admin_notice();
        $html = ob_get_clean();

        $this->assertStringContainsString($this->rewrite->result_message($stored['changed'], $stored['skipped']), $html);
        $this->assertStringContainsString('Updated', $html);
        $this->assertStringContainsString('Skipped', $html);
    }

    public function test_preview_notice_asks_for_confirmation_and_does_not_write(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'notice.user',
                'user_email'   => 'notice.user@example.com',
                'display_name' => 'Notice User',
            ],
            'notice.user'
        );
        set_transient('uh_nicename_preview_' . $this->operator_id, '1', MINUTE_IN_SECONDS);
        $_GET[User_History_Nicename_Rewrite::PREVIEW_FLAG] = '1';
        $summary = $this->rewrite->summarize();

        ob_start();
        $this->rewrite->render_admin_notice();
        $html = ob_get_clean();

        $this->assertSame('notice.user', get_userdata($user_id)->user_nicename);
        $this->assertStringContainsString($this->rewrite->preview_message($summary['matches'], $summary['skipped']), $html);
        $this->assertStringContainsString('user_history_nicename_rewrite_confirm', $html);
        $this->assertStringContainsString('data-confirm=', $html);
        $this->assertStringContainsString('Update matching nicenames', $html);
        $this->assertStringNotContainsString('innerHTML', $html);
    }

    public function test_invalid_nonce_does_not_rewrite(): void
    {
        $this->actAsAdmin();
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'nonce.user',
                'user_email'   => 'nonce.user@example.com',
                'display_name' => 'Nonce User',
            ],
            'nonce.user'
        );
        $this->throwOnWpDie();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST[User_History_Nicename_Rewrite::CONFIRM_ACTION] = '1';
        $_POST[User_History_Nicename_Rewrite::NONCE_FIELD] = 'not-a-nonce';

        try {
            $this->rewrite->handle_request();
            $this->fail('Expected the bad nonce to stop the request.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('could not be verified', $exception->getMessage());
        }

        $this->assertSame('nonce.user', get_userdata($user_id)->user_nicename);
    }

    public function test_editor_without_edit_users_cannot_rewrite_or_see_the_button(): void
    {
        $editor = self::factory()->user->create(['role' => 'editor']);
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'editor.target',
                'user_email'   => 'editor.target@example.com',
                'display_name' => 'Editor Target',
            ],
            'editor.target'
        );
        wp_set_current_user($editor);
        $this->operator_id = (int) $editor;

        $this->assertFalse(current_user_can('edit_users'));
        $this->assertFalse($this->rewrite->current_operator_can_rewrite());

        $result = $this->rewrite->rewrite_matching_nicenames();
        $this->assertSame(0, $result['changed']);
        $this->assertSame('editor.target', get_userdata($user_id)->user_nicename);

        ob_start();
        $this->rewrite->render_users_button('top');
        $button = ob_get_clean();
        $this->assertSame('', $button);

        $this->throwOnWpDie();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST[User_History_Nicename_Rewrite::CONFIRM_ACTION] = '1';
        $_POST[User_History_Nicename_Rewrite::NONCE_FIELD] = wp_create_nonce(
            User_History_Nicename_Rewrite::NONCE_ACTION
        );

        try {
            $this->rewrite->handle_request();
            $this->fail('Expected the editor to be refused.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('not allowed', $exception->getMessage());
        }

        $this->assertSame('editor.target', get_userdata($user_id)->user_nicename);
    }

    public function test_role_with_edit_users_can_rewrite_without_the_administrator_slug(): void
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
        $manager = self::factory()->user->create(['role' => 'account_manager']);
        $user_id = $this->createLegacyUser(
            [
                'user_login'   => 'managed.user',
                'user_email'   => 'managed.user@example.com',
                'display_name' => 'Managed User',
            ],
            'managed.user'
        );
        wp_set_current_user($manager);
        $this->operator_id = (int) $manager;

        $this->assertFalse(in_array('administrator', (array) wp_get_current_user()->roles, true));
        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('edit_user', $user_id));

        $this->rewrite->rewrite_matching_nicenames();

        $this->assertSame('managed-user', get_userdata($user_id)->user_nicename);
    }

    public function test_button_is_on_the_users_screen_for_people_who_can_edit_users(): void
    {
        $this->actAsAdmin();

        ob_start();
        $this->rewrite->render_users_button('top');
        $html = ob_get_clean();

        $this->assertStringContainsString('Rewrite matching nicenames', $html);
        $this->assertStringContainsString('formmethod="post"', $html);
        $this->assertStringContainsString('user_history_nicename_rewrite_preview', $html);
        $this->assertStringContainsString('user_history_nicename_rewrite_nonce', $html);
        $this->assertStringNotContainsString('user_history_nicename_rewrite_confirm', $html);

        ob_start();
        $this->rewrite->render_users_button('bottom');
        $bottom = ob_get_clean();
        $this->assertSame('', $bottom);
    }

    /**
     * @param array<string,mixed> $args User data.
     * @param string              $nicename Value to store after creation.
     */
    private function createLegacyUser(array $args, string $nicename): int
    {
        $args['role'] = isset($args['role']) ? $args['role'] : 'subscriber';
        $user_id = self::factory()->user->create($args);
        $this->pinNicename($user_id, $nicename);

        return (int) $user_id;
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

    private function actAsAdmin(): void
    {
        $admin = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($admin);
        $this->operator_id = (int) $admin;
    }

    private function captureRedirect(): void
    {
        $this->redirect = null;
        add_filter('wp_redirect', [$this, 'recordRedirect'], 1);
    }

    /**
     * @param string $location Redirect target.
     * @return false
     */
    public function recordRedirect($location)
    {
        $this->redirect = (string) $location;

        return false;
    }

    private function throwOnWpDie(): void
    {
        add_filter(
            'wp_die_handler',
            static function () {
                return static function ($message) {
                    throw new RuntimeException(is_string($message) ? wp_strip_all_tags($message) : 'denied');
                };
            }
        );
    }

}
