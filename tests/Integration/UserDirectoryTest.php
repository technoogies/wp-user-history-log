<?php

final class UserDirectoryTest extends WP_UnitTestCase
{
    private User_History_User_Directory $directory;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->directory = User_History_User_Directory::get_instance();
        User_History::get_instance()->activate();
        delete_option(User_History_Login_Tracker::OPTION_KEY);
        $_GET = [];
        $_POST = [];
        $_REQUEST = [];
        wp_set_current_user(0);
    }

    protected function tearDown(): void
    {
        $_GET = [];
        $_POST = [];
        $_REQUEST = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_login_stamp_is_saved_when_login_recording_is_off_and_does_not_write_history(): void
    {
        $user_id = $this->createUser('subscriber');
        $user = get_userdata($user_id);
        $this->assertInstanceOf(WP_User::class, $user);
        $this->assertFalse(User_History_Login_Tracker::get_instance()->is_enabled());
        $this->assertSame(0, $this->directory->last_login_timestamp($user_id));
        $this->assertSame('Never', $this->directory->render_last_login_column('', User_History_User_Directory::COLUMN_LAST_LOGIN, $user_id));

        $history_before = $this->historyCount($user_id);
        $before = time();
        do_action('wp_login', $user->user_login, $user);
        $stamp = $this->directory->last_login_timestamp($user_id);

        $this->assertGreaterThanOrEqual($before, $stamp);
        $this->assertLessThanOrEqual(time(), $stamp);
        $this->assertFalse(User_History_Login_Tracker::get_instance()->is_enabled());
        $this->assertSame($history_before, $this->historyCount($user_id));
        $this->assertStringContainsString(
            $this->directory->format_last_login_for_display($stamp),
            $this->directory->render_last_login_column('', User_History_User_Directory::COLUMN_LAST_LOGIN, $user_id)
        );

        do_action('wp_login_failed', $user->user_login);
        do_action('wp_logout', $user_id);
        $this->assertSame($stamp, $this->directory->last_login_timestamp($user_id));
    }

    public function test_last_login_column_follows_role_or_status(): void
    {
        $with_status = $this->directory->add_last_login_column(
            [
                'username'             => 'Username',
                'email'                => 'Email',
                'role'                 => 'Role',
                'user_history_locked'  => 'Status',
                'posts'                => 'Posts',
            ]
        );
        $this->assertSame(
            ['username', 'email', 'role', 'user_history_locked', 'user_history_last_login', 'posts'],
            array_keys($with_status)
        );
        $this->assertSame('Last login', $with_status['user_history_last_login']);

        $without_status = $this->directory->add_last_login_column(
            [
                'username' => 'Username',
                'role'     => 'Role',
                'posts'    => 'Posts',
            ]
        );
        $this->assertSame(
            ['username', 'role', 'user_history_last_login', 'posts'],
            array_keys($without_status)
        );
    }

    public function test_duplicate_finder_groups_shared_email_and_username_only(): void
    {
        $shared_email_a = $this->createUser('subscriber');
        $shared_email_b = $this->createUser('subscriber');
        $shared_login_a = $this->createUser('subscriber');
        $shared_login_b = $this->createUser('subscriber');
        $unique = $this->createUser('subscriber');

        $this->forceUserFields($shared_email_a, ['user_email' => 'Shared@Example.com']);
        $this->forceUserFields($shared_email_b, ['user_email' => 'shared@example.com']);
        $this->forceUserFields($shared_login_a, ['user_login' => 'TwinUser']);
        $this->forceUserFields($shared_login_b, ['user_login' => 'twinuser']);
        $this->stamp($shared_email_a, 1700000000);

        $blank_groups = $this->directory->duplicate_groups(
            [
                ['id' => 1, 'username' => '', 'email' => ''],
                ['id' => 2, 'username' => '   ', 'email' => '   '],
                ['id' => 3, 'username' => 'only-one', 'email' => 'only@example.com'],
            ]
        );
        $this->assertSame([], $blank_groups['email']);
        $this->assertSame([], $blank_groups['login']);

        $report = $this->directory->directory_report();
        $email_ids = $this->groupMemberIds($report['groups']['email'], 'shared@example.com');
        $login_ids = $this->groupMemberIds($report['groups']['login'], 'twinuser');

        $expected_email = [$shared_email_a, $shared_email_b];
        $expected_login = [$shared_login_a, $shared_login_b];
        sort($expected_email);
        sort($expected_login);
        $this->assertSame($expected_email, $email_ids);
        $this->assertSame($expected_login, $login_ids);
        $this->assertNotContains($unique, $this->allGroupedIds($report['groups']['email']));

        $queried_ids = array_map('intval', array_column($report['rows'], 'id'));
        $this->assertContains($shared_email_a, $queried_ids);
        $this->assertContains($unique, $queried_ids);

        $match = $this->rowById($report['rows'], $shared_email_a);
        $this->assertSame(1700000000, $match['last_login']);
    }

    public function test_csv_uses_the_same_user_query_and_includes_last_login(): void
    {
        $admin = $this->createUser('administrator');
        $subject = $this->createUser('subscriber');
        $this->forceUserFields($subject, ['display_name' => '=1+1']);
        $this->stamp($subject, 1700000000);
        wp_set_current_user($admin);
        $_REQUEST['_wpnonce'] = wp_create_nonce(User_History_User_Directory::EXPORT_NONCE);

        $exported = $this->directory->export_rows();
        $queried = $this->directory->query_site_users();

        $this->assertSame(
            array_map('intval', array_column($queried, 'id')),
            array_map('intval', array_column($exported, 'id'))
        );

        $csv = $this->directory->build_csv($exported);
        $parsed = $this->parseCsv($csv);
        $this->assertSame(User_History_User_Directory::CSV_HEADERS, $parsed[0]);
        $this->assertCount(count($exported) + 1, $parsed);
        $this->assertStringNotContainsString('user_pass', $csv);
        $this->assertStringNotContainsString('staff_note', $csv);

        $line = $this->csvRowById($parsed, $subject);
        $this->assertSame((string) $subject, $line[0]);
        $this->assertSame("'=1+1", $line[3]);
        $this->assertSame($this->directory->format_last_login_for_csv(1700000000), $line[6]);
        $this->assertNotSame('', $line[6]);
    }

    public function test_duplicate_page_is_read_only_for_an_administrator(): void
    {
        $admin = $this->createUser('administrator');
        $first = $this->createUser('subscriber');
        $second = $this->createUser('subscriber');
        $this->forceUserFields($first, ['user_email' => 'pair@example.com']);
        $this->forceUserFields($second, ['user_email' => 'pair@example.com']);
        wp_set_current_user($admin);

        $html = $this->renderPage();

        $this->assertStringContainsString('Duplicate users', $html);
        $this->assertStringContainsString('This page only looks. It does not change, lock, or disable any account.', $html);
        $this->assertStringContainsString('Download users CSV', $html);
        $this->assertStringContainsString('pair@example.com', $html);
        $this->assertStringContainsString('admin-post.php', $html);
        $this->assertStringContainsString('user_history_export_users', $html);
        $this->assertStringNotContainsString('<form', $html);
        $this->assertStringNotContainsString('user_history_lock', $html);
        $this->assertStringNotContainsString('user_pass', $html);
    }

    public function test_account_editor_without_manage_user_history_cannot_export_or_open_the_page(): void
    {
        $editor = $this->createAccountEditor();
        wp_set_current_user($editor);

        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('list_users'));
        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertFalse($this->directory->current_operator_can_export());

        try {
            $this->directory->render_page();
            $this->fail('The duplicate page should stop for an account editor.');
        } catch (WPDieException $exception) {
            $this->assertStringContainsString('not allowed', strtolower($exception->getMessage()));
        }

        try {
            $this->directory->export_rows();
            $this->fail('The CSV export should stop for an account editor.');
        } catch (WPDieException $exception) {
            $this->assertStringContainsString('not allowed', strtolower($exception->getMessage()));
        }
    }

    public function test_export_requires_a_valid_nonce(): void
    {
        $admin = $this->createUser('administrator');
        wp_set_current_user($admin);
        $_REQUEST['_wpnonce'] = 'not-a-real-nonce';

        try {
            $this->directory->export_rows();
            $this->fail('The CSV export should stop when the nonce is wrong.');
        } catch (WPDieException $exception) {
            $this->assertStringContainsString('expired', strtolower($exception->getMessage()));
        }
    }

    public function test_list_users_alone_cannot_export(): void
    {
        $user_id = $this->createUser('subscriber');
        $user = get_userdata($user_id);
        $this->assertInstanceOf(WP_User::class, $user);
        $user->add_cap('list_users');
        wp_set_current_user($user_id);

        $this->assertTrue(current_user_can('list_users'));
        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertFalse($this->directory->current_operator_can_export());
    }

    public function test_personal_data_export_includes_last_login_and_erasure_keeps_history(): void
    {
        $user_id = $this->createUser('subscriber');
        $user = get_userdata($user_id);
        $this->assertInstanceOf(WP_User::class, $user);
        $this->stamp($user_id, 1700000000);
        $this->seedHistory($user_id, 'keep-history');
        $history_before = $this->historyCount($user_id);
        $email = $user->user_email;

        $exported = $this->directory->export_personal_data($email);
        $this->assertTrue($exported['done']);
        $this->assertSame('Last login', $exported['data'][0]['data'][0]['name']);
        $this->assertSame(
            $this->directory->format_last_login_for_display(1700000000),
            $exported['data'][0]['data'][0]['value']
        );

        $erased = $this->directory->erase_personal_data($email);
        $this->assertTrue($erased['items_removed']);
        $this->assertFalse($erased['items_retained']);
        $this->assertSame(0, $this->directory->last_login_timestamp($user_id));
        $this->assertSame($history_before, $this->historyCount($user_id));

        $history = User_History::get_instance()->erase_personal_data($email);
        $this->assertFalse($history['items_removed']);
        $this->assertTrue($history['items_retained']);
        $this->assertSame([], $this->directory->export_personal_data($email)['data']);
    }

    private function renderPage(): string
    {
        ob_start();
        $this->directory->render_page();

        return (string) ob_get_clean();
    }

    private function stamp(int $user_id, int $timestamp): void
    {
        update_user_meta($user_id, User_History_User_Directory::META_LAST_LOGIN, (string) $timestamp);
    }

    /**
     * @param array<string,string> $fields Users table columns.
     */
    private function forceUserFields(int $user_id, array $fields): void
    {
        global $wpdb;

        $wpdb->update($wpdb->users, $fields, ['ID' => $user_id]);
        clean_user_cache($user_id);
    }

    /**
     * @param array<int,array<string,mixed>> $groups Duplicate groups.
     * @return array<int,int>
     */
    private function groupMemberIds(array $groups, string $needle): array
    {
        $needle = strtolower($needle);
        foreach ($groups as $group) {
            if (strtolower((string) $group['value']) !== $needle) {
                continue;
            }

            $ids = array_map(
                static function ($row) {
                    return (int) $row['id'];
                },
                $group['users']
            );
            sort($ids);

            return $ids;
        }

        $this->fail('Missing duplicate group for ' . $needle);

        return [];
    }

    /**
     * @param array<int,array<string,mixed>> $groups Duplicate groups.
     * @return array<int,int>
     */
    private function allGroupedIds(array $groups): array
    {
        $ids = [];
        foreach ($groups as $group) {
            foreach ($group['users'] as $row) {
                $ids[] = (int) $row['id'];
            }
        }

        return $ids;
    }

    /**
     * @param array<int,array<string,mixed>> $rows User rows.
     * @return array<string,mixed>
     */
    private function rowById(array $rows, int $user_id): array
    {
        foreach ($rows as $row) {
            if ((int) $row['id'] === $user_id) {
                return $row;
            }
        }

        $this->fail('Missing user row ' . $user_id);

        return [];
    }

    /**
     * @param array<int,array<int,string>> $parsed Parsed CSV rows.
     * @return array<int,string>
     */
    private function csvRowById(array $parsed, int $user_id): array
    {
        foreach ($parsed as $index => $row) {
            if ($index === 0) {
                continue;
            }
            if (isset($row[0]) && (int) $row[0] === $user_id) {
                return $row;
            }
        }

        $this->fail('Missing CSV row ' . $user_id);

        return [];
    }

    /**
     * @return array<int,array<int,string>>
     */
    private function parseCsv(string $csv): array
    {
        $handle = fopen('php://temp', 'r+');
        $this->assertNotFalse($handle);
        fwrite($handle, $csv);
        rewind($handle);

        $rows = [];
        while (($row = fgetcsv($handle)) !== false) {
            $rows[] = $row;
        }
        fclose($handle);

        return $rows;
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

    private function seedHistory(int $user_id, string $marker): void
    {
        global $wpdb;

        $wpdb->insert(
            $wpdb->prefix . 'user_history',
            [
                'user_id'            => $user_id,
                'changed_by'         => $user_id,
                'field_name'         => 'first_name',
                'field_label'        => 'First Name',
                'old_value'          => $marker . '-old',
                'new_value'          => $marker . '-new',
                'search_tokens'      => '',
                'changed_by_details' => '',
                'change_type'        => 'update',
                'created_at'         => current_time('mysql'),
            ]
        );
    }

    private function createUser(string $role): int
    {
        return (int) self::factory()->user->create(['role' => $role]);
    }

    private function createAccountEditor(): int
    {
        $editor = $this->createUser('editor');
        $user = get_userdata($editor);
        $this->assertInstanceOf(WP_User::class, $user);
        $user->add_cap('edit_users');
        $user->add_cap('list_users');

        return $editor;
    }
}
