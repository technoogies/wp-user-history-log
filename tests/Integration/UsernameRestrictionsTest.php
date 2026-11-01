<?php

final class UsernameRestrictionsTest extends WP_Ajax_UnitTestCase
{
    private User_History $plugin;
    private User_History_Username_Restrictions $restrictions;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->restrictions = User_History_Username_Restrictions::get_instance($this->plugin);
        $this->resetUsernameOptions();
    }

    protected function tearDown(): void
    {
        $this->resetUsernameOptions();
        remove_all_filters('user_history_validate_username');
        $_POST = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_username_rules_are_off_by_default(): void
    {
        wp_set_current_user(0);

        $this->assertFalse($this->restrictions->is_enabled());
        $this->assertSame('0', (string) get_option(User_History_Username_Restrictions::OPTION_ENABLED, '0'));
        $this->assertTrue(validate_username('admin'));
        $this->assertNull($this->restrictions->get_restriction_reason('admin'));
        $this->assertFalse($this->restrictions->is_restricted('admin'));
    }

    public function test_blocklist_and_partial_rules_match_acceptance_names(): void
    {
        $this->enableRules(
            [
                User_History_Username_Restrictions::OPTION_BLOCKLIST => 'admin',
                User_History_Username_Restrictions::OPTION_PARTIAL_BLOCKLIST => 'support',
            ]
        );
        wp_set_current_user(0);

        $this->assertNotNull($this->restrictions->get_restriction_reason('admin'));
        $this->assertNotNull($this->restrictions->get_restriction_reason('mysupport'));
        $this->assertNull($this->restrictions->get_restriction_reason('jane.doe'));
        $this->assertFalse(validate_username('admin'));
        $this->assertFalse(validate_username('mysupport'));
        $this->assertTrue(validate_username('jane.doe'));
    }

    public function test_disallow_spaces_and_test_usernames_share_the_same_reasons(): void
    {
        $this->enableRules(
            [
                User_History_Username_Restrictions::OPTION_DISALLOW_SPACES => '1',
                User_History_Username_Restrictions::OPTION_BLOCKLIST => 'admin',
                User_History_Username_Restrictions::OPTION_PARTIAL_BLOCKLIST => 'support',
            ]
        );

        $this->assertSame('contains spaces', $this->restrictions->get_restriction_reason('jane doe'));
        $this->assertNull($this->restrictions->get_restriction_reason('jane.doe'));

        $evaluated = $this->restrictions->evaluate_usernames('admin, mysupport, jane.doe, jane doe');
        $this->assertFalse($evaluated['results'][0]['valid']);
        $this->assertSame('is on the blocked usernames list', $evaluated['results'][0]['reason']);
        $this->assertFalse($evaluated['results'][1]['valid']);
        $this->assertStringContainsString('support', $evaluated['results'][1]['reason']);
        $this->assertTrue($evaluated['results'][2]['valid']);
        $this->assertFalse($evaluated['results'][3]['valid']);
        $this->assertSame('contains spaces', $evaluated['results'][3]['reason']);
    }

    public function test_admin_bypass_is_off_until_apply_to_admins_is_enabled(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $this->enableRules(
            [
                User_History_Username_Restrictions::OPTION_BLOCKLIST => 'admin',
            ]
        );

        wp_set_current_user($administrator);
        $this->assertTrue(current_user_can('create_users'));
        $this->assertTrue($this->restrictions->should_skip());
        $this->assertTrue(validate_username('admin'));
        $this->assertNull($this->restrictions->get_admin_username_error('admin'));

        update_option(User_History_Username_Restrictions::OPTION_APPLY_TO_ADMINS, '1');
        $this->assertFalse($this->restrictions->should_skip());
        $this->assertFalse(validate_username('admin'));
        $this->assertNotNull($this->restrictions->get_admin_username_error('admin'));
    }

    public function test_change_username_honors_apply_to_admins(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $allowed = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'rules-allowed',
            ]
        );
        $blocked = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'rules-blocked',
            ]
        );

        $this->enableRules(
            [
                User_History_Username_Restrictions::OPTION_BLOCKLIST => "blockedname\nsupportname",
            ]
        );
        wp_set_current_user($administrator);

        $allowed_response = $this->changeUsername('rules-allowed', 'blockedname');
        $this->assertTrue($allowed_response['success']);
        $this->assertSame('blockedname', get_userdata($allowed)->user_login);

        update_option(User_History_Username_Restrictions::OPTION_APPLY_TO_ADMINS, '1');

        $blocked_response = $this->changeUsername('rules-blocked', 'supportname');
        $this->assertFalse($blocked_response['success']);
        $this->assertSame('This username is not allowed. Please choose another.', $blocked_response['message']);
        $this->assertSame('rules-blocked', get_userdata($blocked)->user_login);
    }

    public function test_existing_blocked_username_can_still_log_in(): void
    {
        $user_id = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'adminhold',
                'user_pass'  => 'existing-pass',
            ]
        );

        $this->enableRules(
            [
                User_History_Username_Restrictions::OPTION_BLOCKLIST => 'adminhold',
            ]
        );

        $authenticated = wp_authenticate('adminhold', 'existing-pass');
        $this->assertInstanceOf(WP_User::class, $authenticated);
        $this->assertSame($user_id, (int) $authenticated->ID);
    }

    public function test_restrict_usernames_import_copies_settings_but_leaves_the_switch_off(): void
    {
        delete_option(User_History_Username_Restrictions::MIGRATED_OPTION);
        update_option(
            'c2c_restrict_usernames',
            [
                'disallow_spaces'   => true,
                'min_length'        => 4,
                'max_length'        => 20,
                'usernames'         => "Admin\nSupport",
                'partial_usernames' => ['Help'],
                'required_partials' => ['^member_'],
            ]
        );

        $this->restrictions->maybe_import_restrict_usernames_settings();

        $this->assertSame('1', get_option(User_History_Username_Restrictions::MIGRATED_OPTION));
        $this->assertSame('0', (string) get_option(User_History_Username_Restrictions::OPTION_ENABLED, '0'));
        $this->assertFalse($this->restrictions->is_enabled());
        $this->assertSame('1', get_option(User_History_Username_Restrictions::OPTION_DISALLOW_SPACES));
        $this->assertSame(4, (int) get_option(User_History_Username_Restrictions::OPTION_MIN_LENGTH));
        $this->assertSame(20, (int) get_option(User_History_Username_Restrictions::OPTION_MAX_LENGTH));
        $this->assertSame("admin\nsupport", get_option(User_History_Username_Restrictions::OPTION_BLOCKLIST));
        $this->assertSame('help', get_option(User_History_Username_Restrictions::OPTION_PARTIAL_BLOCKLIST));
        $this->assertSame('^member_', get_option(User_History_Username_Restrictions::OPTION_REQUIRED_PARTIALS));

        update_option('c2c_restrict_usernames', ['disallow_spaces' => false]);
        $this->restrictions->maybe_import_restrict_usernames_settings();
        $this->assertSame('1', get_option(User_History_Username_Restrictions::OPTION_DISALLOW_SPACES));
        $this->assertSame('0', (string) get_option(User_History_Username_Restrictions::OPTION_ENABLED, '0'));
    }

    public function test_custom_filter_can_reject_an_otherwise_valid_username(): void
    {
        $this->enableRules([]);
        add_filter(
            'user_history_validate_username',
            static function ($valid, $username) {
                return $username === 'custom.ok' ? $valid : false;
            },
            10,
            2
        );

        $this->assertNull($this->restrictions->get_restriction_reason('custom.ok'));
        $this->assertSame('was rejected by a custom rule', $this->restrictions->get_restriction_reason('anyone.else'));
    }

    public function test_test_usernames_ajax_requires_manage_user_history(): void
    {
        $this->enableRules(
            [
                User_History_Username_Restrictions::OPTION_BLOCKLIST => 'admin',
            ]
        );

        $editor = self::factory()->user->create(['role' => 'editor']);
        wp_set_current_user($editor);
        $denied = $this->testUsernames('admin, jane.doe');
        $this->assertFalse($denied['success']);

        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);
        $allowed = $this->testUsernames('admin, jane.doe');
        $this->assertTrue($allowed['success']);
        $this->assertFalse($allowed['data']['results'][0]['valid']);
        $this->assertTrue($allowed['data']['results'][1]['valid']);
    }

    /**
     * @param array<string,mixed> $options Option values to store.
     */
    private function enableRules(array $options): void
    {
        update_option(User_History_Username_Restrictions::OPTION_ENABLED, '1');
        foreach ($options as $key => $value) {
            update_option($key, $value);
        }
    }

    /**
     * @return array<string,mixed>
     */
    private function changeUsername($current, $new): array
    {
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => wp_create_nonce('user_history_change_username'),
            'current_username' => $current,
            'new_username'     => $new,
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);
        $this->_last_response = '';

        return $response;
    }

    /**
     * @return array<string,mixed>
     */
    private function testUsernames($raw): array
    {
        $_POST = [
            'action'    => User_History_Username_Restrictions::TEST_ACTION,
            'nonce'     => wp_create_nonce(User_History_Username_Restrictions::TEST_NONCE),
            'usernames' => $raw,
        ];

        try {
            $this->_handleAjax(User_History_Username_Restrictions::TEST_ACTION);
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);
        $this->_last_response = '';

        return $response;
    }

    private function resetUsernameOptions(): void
    {
        delete_option(User_History_Username_Restrictions::OPTION_ENABLED);
        delete_option(User_History_Username_Restrictions::OPTION_DISALLOW_SPACES);
        delete_option(User_History_Username_Restrictions::OPTION_MIN_LENGTH);
        delete_option(User_History_Username_Restrictions::OPTION_MAX_LENGTH);
        delete_option(User_History_Username_Restrictions::OPTION_BLOCKLIST);
        delete_option(User_History_Username_Restrictions::OPTION_PARTIAL_BLOCKLIST);
        delete_option(User_History_Username_Restrictions::OPTION_REQUIRED_PARTIALS);
        delete_option(User_History_Username_Restrictions::OPTION_ERROR_MESSAGE);
        delete_option(User_History_Username_Restrictions::OPTION_APPLY_TO_ADMINS);
        delete_option(User_History_Username_Restrictions::MIGRATED_OPTION);
        delete_option('c2c_restrict_usernames');
    }
}
