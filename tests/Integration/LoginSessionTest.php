<?php

final class LoginSessionTest extends WP_Ajax_UnitTestCase
{
    private User_History $plugin;
    private User_History_Login_Tracker $tracker;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->tracker = User_History_Login_Tracker::get_instance($this->plugin);
        delete_option(User_History_Login_Tracker::OPTION_KEY);
        $_SERVER['REMOTE_ADDR'] = '203.0.113.80';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_GET = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
        delete_option(User_History_Login_Tracker::OPTION_KEY);
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_login_recording_is_off_by_default(): void
    {
        $this->assertFalse($this->tracker->is_enabled());
        $this->assertSame('0', User_History_Settings::get_instance()->sanitize_login_tracking(''));

        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $this->tracker->log_login(get_userdata($subject)->user_login, get_userdata($subject));
        $this->tracker->log_logout($subject);
        $this->tracker->log_failed_login(get_userdata($subject)->user_login);

        wp_set_current_user($administrator);
        $this->assertSame([], $this->loginHistorySnapshot($subject));
        $this->assertSame(0, $this->plugin->get_user_history_count($subject, 'logins'));
    }

    public function test_enabled_tracking_records_login_logout_and_existing_failed_login(): void
    {
        update_option(User_History_Login_Tracker::OPTION_KEY, '1');
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $user = get_userdata($subject);

        $this->tracker->log_login($user->user_login, $user);
        $this->tracker->log_logout($subject);
        $this->tracker->log_failed_login($user->user_login);
        $this->tracker->log_failed_login('definitely-not-a-user-' . wp_generate_password(8, false, false));

        wp_set_current_user($administrator);
        $rows = $this->loginHistorySnapshot($subject);
        $this->assertCount(3, $rows);
        $this->assertSame(['login', 'logout', 'login_failed'], array_column($rows, 'change_type'));
        $this->assertSame(['user_session', 'user_session', 'user_session'], array_column($rows, 'field_name'));

        foreach ($rows as $row) {
            $this->assertStringNotContainsString('password', strtolower((string) $row['old_value']));
            $this->assertStringNotContainsString('password', strtolower((string) $row['new_value']));
            $this->assertSame('', $row['search_tokens']);
        }

        $this->assertSame(3, $this->plugin->get_user_history_count($subject, 'logins'));
        $change_types = array_column((array) $this->plugin->get_user_history($subject, 50, 0, 'changes'), 'change_type');
        $this->assertNotContains('login', $change_types);
        $this->assertNotContains('logout', $change_types);
        $this->assertNotContains('login_failed', $change_types);
    }

    public function test_user_agent_is_encrypted_and_not_historically_searchable(): void
    {
        update_option(User_History_Login_Tracker::OPTION_KEY, '1');
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $marker = 'UniqueChromeAgentStringXYZ';
        $_SERVER['HTTP_USER_AGENT'] = $marker;
        $this->tracker->log_login(get_userdata($subject)->user_login, get_userdata($subject));

        $rows = $this->loginHistorySnapshot($subject);
        $this->assertNotSame('', $rows[0]['new_value']);
        $this->assertStringNotContainsString($marker, (string) $rows[0]['new_value']);
        $this->assertSame('', $rows[0]['search_tokens']);

        $entry = (object) $rows[0];
        $this->assertSame($marker, $this->plugin->get_history_row_display_value($entry, 'new'));

        wp_set_current_user($administrator);
        $this->openUsersScreen();
        $ids = $this->searchUserIds($marker);
        $this->assertNotContains($subject, $ids);
    }

    public function test_login_ip_follows_collect_ip_setting(): void
    {
        update_option(User_History_Login_Tracker::OPTION_KEY, '1');
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        unset($administrator);

        $this->tracker->log_failed_login(get_userdata($subject)->user_email);
        $with_ip = $this->loginHistorySnapshot($subject);
        $this->assertSame('203.0.113.80', $this->plugin->get_history_row_ip((object) $with_ip[0]));

        update_option('user_history_collect_ip', '0');
        $this->tracker->log_failed_login(get_userdata($subject)->user_email);
        $rows = $this->loginHistorySnapshot($subject);
        $without_ip = $rows[count($rows) - 1];
        $this->assertSame('', $this->plugin->get_history_row_ip((object) $without_ip));
        delete_option('user_history_collect_ip');
    }

    public function test_browser_parser_is_local(): void
    {
        $this->assertSame(
            'Chrome on macOS',
            $this->tracker->parse_user_agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')
        );
        $this->assertSame(
            'Firefox on Windows',
            $this->tracker->parse_user_agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0')
        );
    }

    public function test_log_out_everywhere_requires_edit_users_and_edit_user(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $manager = WP_Session_Tokens::get_instance($subject);
        $manager->create(time() + HOUR_IN_SECONDS);
        $this->assertNotEmpty($manager->get_all());

        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        $deny = static function ($caps, $cap, $user_id, $args) use ($subject) {
            if ($cap === 'edit_user' && isset($args[0]) && (int) $args[0] === $subject) {
                return ['do_not_allow'];
            }

            return $caps;
        };
        add_filter('map_meta_cap', $deny, 10, 4);
        wp_set_current_user($editor);

        $denied = $this->destroySessions($subject);
        remove_filter('map_meta_cap', $deny, 10);

        $this->assertFalse($denied['success']);
        $this->assertNotEmpty(WP_Session_Tokens::get_instance($subject)->get_all());

        wp_set_current_user($administrator);
        $allowed = $this->destroySessions($subject);
        $this->assertTrue($allowed['success']);
        $this->assertEmpty(WP_Session_Tokens::get_instance($subject)->get_all());
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createAdministratorAndSubject(): array
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);

        return [$administrator, $subject];
    }

    private function destroySessions($user_id): array
    {
        $this->_last_response = '';
        $_POST = [
            'action'  => 'user_history_destroy_sessions',
            'nonce'   => wp_create_nonce('user_history_destroy_sessions'),
            'user_id' => (int) $user_id,
        ];

        try {
            $this->_handleAjax('user_history_destroy_sessions');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    private function loginHistorySnapshot($user_id): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT field_name, old_value, new_value, change_type, search_tokens, changed_by_details FROM ' . $wpdb->prefix . User_History::TABLE_NAME . " WHERE user_id = %d AND change_type IN ('login','logout','login_failed') ORDER BY id ASC",
                (int) $user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    private function searchUserIds($term): array
    {
        $this->openUsersScreen();
        $query = new WP_User_Query(
            [
                'search'         => '*' . $term . '*',
                'search_columns' => ['user_email'],
                'fields'         => 'ID',
                'number'         => 100,
                'count_total'    => false,
            ]
        );

        return array_map('intval', (array) $query->get_results());
    }

    private function openUsersScreen(): void
    {
        require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
        require_once ABSPATH . 'wp-admin/includes/screen.php';

        set_current_screen('users');
        $GLOBALS['pagenow'] = 'users.php';
    }
}
