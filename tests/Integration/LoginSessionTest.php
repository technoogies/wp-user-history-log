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
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'],
            $_SERVER['HTTP_CF_CONNECTING_IP'],
            $_SERVER['HTTP_X_REAL_IP'],
            $_SERVER['HTTP_X_FORWARDED_FOR']
        );
        unset($_COOKIE[LOGGED_IN_COOKIE]);
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

    public function test_forwarded_headers_use_the_first_public_client_address_only(): void
    {
        $this->assertSame('', $this->tracker->public_client_ip_from_forwarded_value(''));
        $this->assertSame('', $this->tracker->public_client_ip_from_forwarded_value('   '));
        $this->assertSame('', $this->tracker->public_client_ip_from_forwarded_value('not-an-ip'));
        $this->assertSame('', $this->tracker->public_client_ip_from_forwarded_value('10.1.2.3'));
        $this->assertSame('', $this->tracker->public_client_ip_from_forwarded_value('192.168.1.20, 203.0.113.50'));
        $this->assertSame('', $this->tracker->public_client_ip_from_forwarded_value('127.0.0.1'));
        $this->assertSame('203.0.113.50', $this->tracker->public_client_ip_from_forwarded_value(' 203.0.113.50 '));
        $this->assertSame('203.0.113.50', $this->tracker->public_client_ip_from_forwarded_value('203.0.113.50, 10.1.2.3'));
        $this->assertSame('198.51.100.20', $this->tracker->public_client_ip_from_forwarded_value('"198.51.100.20"'));

        $_SERVER['REMOTE_ADDR'] = '10.1.2.3';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.50';
        $_SERVER['HTTP_X_REAL_IP'] = '198.51.100.20';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '8.8.8.8';
        $this->assertSame('203.0.113.50', $this->tracker->forwarded_public_client_ip());

        $_SERVER['HTTP_CF_CONNECTING_IP'] = '10.9.8.7';
        $this->assertSame('198.51.100.20', $this->tracker->forwarded_public_client_ip());

        $_SERVER['HTTP_X_REAL_IP'] = '';
        $this->assertSame('8.8.8.8', $this->tracker->forwarded_public_client_ip());

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '172.16.0.4, 192.168.0.9';
        $this->assertSame('', $this->tracker->forwarded_public_client_ip());

        unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_FORWARDED_FOR']);
        $this->assertSame('', $this->tracker->forwarded_public_client_ip());
    }

    public function test_new_sessions_store_the_forwarded_public_ip_without_rewriting_old_rows(): void
    {
        $this->assertNotFalse(has_filter('attach_session_information', [$this->tracker, 'remember_client_ip_for_new_session']));
        $this->assertNotFalse(has_action('set_logged_in_cookie', [$this->tracker, 'store_client_ip_on_new_session']));

        $user_id = self::factory()->user->create(['role' => 'subscriber']);
        unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['REMOTE_ADDR'] = '10.1.2.3';

        $manager = WP_Session_Tokens::get_instance($user_id);
        $old_token = $manager->create(time() + DAY_IN_SECONDS);
        $manager->update(
            $old_token,
            [
                'expiration' => time() + DAY_IN_SECONDS,
                'login'      => time() - DAY_IN_SECONDS,
                'ip'         => '10.9.8.7',
                'ua'         => 'old-session',
            ]
        );
        $old_before = $manager->get($old_token);

        $_SERVER['HTTP_CF_CONNECTING_IP'] = '192.168.1.20';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '172.16.4.4, 203.0.113.50';
        $private_token = $manager->create(time() + DAY_IN_SECONDS);
        $this->assertSame('10.1.2.3', $this->sessionField($user_id, $private_token, 'ip'));
        $this->fireLoggedInCookie($user_id, $private_token);
        $this->assertSame('10.1.2.3', $this->sessionField($user_id, $private_token, 'ip'));
        $this->assertSame($old_before, WP_Session_Tokens::get_instance($user_id)->get($old_token));

        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.50';
        $new_token = $manager->create(time() + DAY_IN_SECONDS);
        $this->assertSame(
            '10.1.2.3',
            $this->sessionField($user_id, $new_token, 'ip'),
            'Core overwrites attach_session_information and keeps REMOTE_ADDR until set_logged_in_cookie.'
        );

        $this->fireLoggedInCookie($user_id, $old_token);
        $this->assertSame($old_before, WP_Session_Tokens::get_instance($user_id)->get($old_token));
        $this->assertSame('10.1.2.3', $this->sessionField($user_id, $new_token, 'ip'));

        $this->fireLoggedInCookie($user_id, $new_token);
        $this->assertSame('203.0.113.50', $this->sessionField($user_id, $new_token, 'ip'));
        $this->assertSame('old-session', $this->sessionField($user_id, $old_token, 'ua'));
        $this->assertSame('10.9.8.7', $this->sessionField($user_id, $old_token, 'ip'));
        $this->assertSame($old_before, WP_Session_Tokens::get_instance($user_id)->get($old_token));
        $this->assertArrayNotHasKey('user_history_client_ip', (array) $manager->get($new_token));
    }

    public function test_history_rows_ignore_forwarded_ips_and_still_honor_collect_ip(): void
    {
        update_option(User_History_Login_Tracker::OPTION_KEY, '1');
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        unset($administrator);

        $_SERVER['REMOTE_ADDR'] = '203.0.113.80';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.20';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.50';
        $this->tracker->log_failed_login(get_userdata($subject)->user_email);

        $rows = $this->loginHistorySnapshot($subject);
        $this->assertSame('203.0.113.80', $this->plugin->get_history_row_ip((object) $rows[0]));

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

    public function test_sessions_tab_shows_the_newest_25_and_pages_the_older_remainder(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $tokens = $this->seedSessions($subject, 130);
        $stored = get_user_meta($subject, 'session_tokens', true);

        wp_set_current_user($administrator);
        $html = $this->renderHistorySection($subject);

        $this->assertSame(130, count(WP_Session_Tokens::get_instance($subject)->get_all()));
        $this->assertSame($stored, get_user_meta($subject, 'session_tokens', true));
        $this->assertStringContainsString('user-history-count">130', $html);
        $this->assertSame(25, substr_count($this->newestSessionMarkup($html), 'user-history-entry'));
        $this->assertStringContainsString('>Load Pages</button>', $html);
        $this->assertStringContainsString('>Log Out Everywhere</button>', $html);
        $this->assertStringNotContainsString('(current)', $html);
        $this->assertSame('ip-marker-129', $this->firstSessionIp($html));
        $this->assertLessThan(strpos($html, '>ip-marker-105</td>'), strpos($html, '>ip-marker-129</td>'));
        $this->assertStringContainsString('>ip-marker-105</td>', $html);
        $this->assertStringNotContainsString('>ip-marker-104</td>', $html);
        $this->assertStringNotContainsString('>ip-marker-0</td>', $html);
        $this->assertSessionSecretsStayOutOfHtml($html, $tokens);

        $page = $this->loadSessionPages($subject, 1);
        $this->assertTrue($page['success']);
        $this->assertSame(1, $page['data']['page']);
        $this->assertSame(2, $page['data']['pages']);
        $this->assertSame(105, $page['data']['olderCount']);
        $this->assertSame(100, substr_count($page['data']['html'], 'user-history-entry'));
        $this->assertSame('ip-marker-104', $this->firstSessionIp($page['data']['html']));
        $this->assertStringContainsString('>ip-marker-5</td>', $page['data']['html']);
        $this->assertStringNotContainsString('>ip-marker-129</td>', $page['data']['html']);
        $this->assertStringNotContainsString('>ip-marker-105</td>', $page['data']['html']);
        $this->assertStringNotContainsString('>ip-marker-4</td>', $page['data']['html']);
        $this->assertSessionSecretsStayOutOfHtml($page['data']['html'], $tokens);

        $last = $this->loadSessionPages($subject, 99);
        $this->assertTrue($last['success']);
        $this->assertSame(2, $last['data']['page']);
        $this->assertSame(2, $last['data']['pages']);
        $this->assertSame(5, substr_count($last['data']['html'], 'user-history-entry'));
        $this->assertSame('ip-marker-4', $this->firstSessionIp($last['data']['html']));
        $this->assertStringContainsString('>ip-marker-0</td>', $last['data']['html']);
        $this->assertStringNotContainsString('>ip-marker-5</td>', $last['data']['html']);
        $this->assertStringNotContainsString('>ip-marker-129</td>', $last['data']['html']);
        $this->assertSame($stored, get_user_meta($subject, 'session_tokens', true));
    }

    public function test_current_marker_follows_the_matching_session_onto_its_page(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $tokens = $this->seedSessions($administrator, 26);
        $expiration = time() + DAY_IN_SECONDS;

        wp_set_current_user($administrator);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($administrator, $expiration, 'logged_in', $tokens[0]);
        $html = $this->tracker->render_sessions_tab(get_userdata($administrator), WP_Session_Tokens::get_instance($administrator)->get_all());

        $this->assertStringContainsString('>Load Pages</button>', $html);
        $this->assertStringContainsString('>Log Out Everywhere</button>', $html);
        $this->assertSame(25, substr_count($html, 'user-history-entry'));
        $this->assertSame('ip-marker-25', $this->firstSessionIp($html));
        $this->assertStringNotContainsString('(current)', $html);
        $this->assertStringNotContainsString('>ip-marker-0</td>', $html);

        $page = $this->loadSessionPages($administrator, 1);
        $this->assertTrue($page['success']);
        $this->assertSame(1, substr_count($page['data']['html'], 'user-history-entry'));
        $this->assertStringContainsString('>ip-marker-0</td>', $page['data']['html']);
        $this->assertStringContainsString('(current)', $page['data']['html']);
        $this->assertStringNotContainsString('>ip-marker-25</td>', $page['data']['html']);
        $this->assertSame(26, count(WP_Session_Tokens::get_instance($administrator)->get_all()));

        unset($_COOKIE[LOGGED_IN_COOKIE]);
        WP_Session_Tokens::get_instance($administrator)->destroy_all();

        $short = $this->seedSessions($administrator, 3);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($administrator, $expiration, 'logged_in', $short[2]);
        $preview = $this->tracker->render_sessions_tab(get_userdata($administrator), WP_Session_Tokens::get_instance($administrator)->get_all());

        $this->assertSame(3, substr_count($preview, 'user-history-entry'));
        $this->assertStringNotContainsString('id="user-history-load-session-pages"', $preview);
        $this->assertStringContainsString('>Log Out Everywhere</button>', $preview);
        $this->assertSame('ip-marker-2', $this->firstSessionIp($preview));
        $this->assertStringContainsString('(current)', $preview);
        $this->assertLessThan(strpos($preview, '>ip-marker-2</td>'), strpos($preview, '(current)'));
    }

    public function test_session_lists_at_or_below_25_render_every_row_without_load_pages(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);

        $empty = $this->tracker->render_sessions_tab(get_userdata($subject), []);
        $this->assertStringContainsString('No active sessions.', $empty);
        $this->assertStringNotContainsString('id="user-history-load-session-pages"', $empty);
        $this->assertStringContainsString('>Log Out Everywhere</button>', $empty);

        $this->seedSessions($subject, 25);
        $html = $this->tracker->render_sessions_tab(get_userdata($subject), WP_Session_Tokens::get_instance($subject)->get_all());
        $this->assertSame(25, substr_count($html, 'user-history-entry'));
        $this->assertSame('ip-marker-24', $this->firstSessionIp($html));
        $this->assertStringContainsString('>ip-marker-0</td>', $html);
        $this->assertStringNotContainsString('id="user-history-load-session-pages"', $html);
        $this->assertStringContainsString('>Log Out Everywhere</button>', $html);
        $this->assertSame(25, count(WP_Session_Tokens::get_instance($subject)->get_all()));
    }

    public function test_sessions_with_the_same_login_time_keep_the_later_session_first(): void
    {
        $sorted = $this->tracker->sort_sessions_newest_first([
            'older-tie' => ['login' => 100, 'ip' => 'first'],
            'newest'    => ['login' => 300, 'ip' => 'newest'],
            'later-tie' => ['login' => 100, 'ip' => 'later-tie'],
            'middle'    => ['login' => 200, 'ip' => 'middle'],
            'missing'   => ['ip' => 'no-login'],
        ]);

        $this->assertSame(
            ['newest', 'middle', 'later-tie', 'first', 'no-login'],
            array_values(array_column($sorted, 'ip'))
        );
    }

    public function test_session_pages_require_edit_user_and_do_not_delete_tokens(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $this->seedSessions($subject, 30);
        $stored = get_user_meta($subject, 'session_tokens', true);

        $stranger = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($stranger);
        $denied = $this->loadSessionPages($subject, 1);
        $this->assertFalse($denied['success']);
        $this->assertStringNotContainsString('ip-marker-', wp_json_encode($denied));
        $this->assertSame($stored, get_user_meta($subject, 'session_tokens', true));

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
        $blocked = $this->loadSessionPages($subject, 1);
        remove_filter('map_meta_cap', $deny, 10);
        $this->assertFalse($blocked['success']);
        $this->assertSame($stored, get_user_meta($subject, 'session_tokens', true));

        wp_set_current_user($subject);
        $own = $this->loadSessionPages($subject, 1);
        $this->assertTrue($own['success']);
        $this->assertSame(5, substr_count($own['data']['html'], 'user-history-entry'));
        $this->assertSame('ip-marker-4', $this->firstSessionIp($own['data']['html']));

        wp_set_current_user($administrator);
        $allowed = $this->loadSessionPages($subject, 1);
        $this->assertTrue($allowed['success']);
        $this->assertSame($stored, get_user_meta($subject, 'session_tokens', true));
        $this->assertSame(30, count(WP_Session_Tokens::get_instance($subject)->get_all()));
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

    /**
     * @param int $user_id Account that owns the sessions.
     * @param int $count   How many sessions to store, oldest first.
     * @return string[] Raw tokens, index 0 is the oldest login.
     */
    private function seedSessions($user_id, $count): array
    {
        $manager = WP_Session_Tokens::get_instance((int) $user_id);
        $expiration = time() + DAY_IN_SECONDS;
        $tokens = [];
        $base = time() - (int) $count;

        for ($index = 0; $index < (int) $count; $index++) {
            $token = $manager->create($expiration);
            $manager->update(
                $token,
                [
                    'expiration' => $expiration,
                    'login'      => $base + $index,
                    'ip'         => 'ip-marker-' . $index,
                    'ua'         => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                ]
            );
            $tokens[] = $token;
        }

        return $tokens;
    }

    private function renderHistorySection($user_id): string
    {
        ob_start();
        $this->plugin->display_history_section(get_userdata((int) $user_id));

        return (string) ob_get_clean();
    }

    private function newestSessionMarkup($html): string
    {
        $html = (string) $html;
        $start = strpos($html, 'id="user-history-sessions-newest"');
        $this->assertNotFalse($start);
        $end = strpos($html, 'id="user-history-sessions-older"', $start);
        $this->assertNotFalse($end);

        return substr($html, $start, $end - $start);
    }

    private function firstSessionIp($html): string
    {
        $html = (string) $html;
        $start = strpos($html, 'id="user-history-sessions-table"');
        if ($start !== false) {
            $html = substr($html, $start);
        }

        $this->assertSame(1, preg_match('/<td class="column-ip">([^<]*)<\/td>/', $html, $match));

        return html_entity_decode($match[1], ENT_QUOTES, 'UTF-8');
    }

    /**
     * @param string[] $tokens
     */
    private function assertSessionSecretsStayOutOfHtml($html, array $tokens): void
    {
        foreach ($tokens as $token) {
            $this->assertStringNotContainsString($token, $html);
            $this->assertStringNotContainsString(hash('sha256', $token), $html);
        }
    }

    private function loadSessionPages($user_id, $page): array
    {
        $this->_last_response = '';
        $_POST = [
            'action'  => 'user_history_load_session_pages',
            'nonce'   => wp_create_nonce('user_history_load_session_pages'),
            'user_id' => (int) $user_id,
            'page'    => (int) $page,
        ];

        try {
            $this->_handleAjax('user_history_load_session_pages');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    private function sessionField($user_id, $token, $field): string
    {
        $session = WP_Session_Tokens::get_instance((int) $user_id)->get($token);
        if (!is_array($session) || !isset($session[$field])) {
            return '';
        }

        return (string) $session[$field];
    }

    private function fireLoggedInCookie($user_id, $token): void
    {
        do_action(
            'set_logged_in_cookie',
            'cookie',
            0,
            time() + HOUR_IN_SECONDS,
            (int) $user_id,
            'logged_in',
            $token
        );
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
