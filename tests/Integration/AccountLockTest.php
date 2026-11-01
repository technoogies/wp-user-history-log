<?php

final class AccountLockTest extends WP_Ajax_UnitTestCase
{
    private User_History $plugin;
    private User_History_Lock $lock;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->lock = User_History_Lock::get_instance($this->plugin);
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_administrator_can_lock_and_unlock_a_subscriber(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);

        $this->assertFalse($this->lock->is_user_locked($subject));

        $result = $this->lock->lock_user($subject);

        $this->assertTrue($result);
        $this->assertTrue($this->lock->is_user_locked($subject));
        $this->assertSame('1', get_user_meta($subject, User_History_Lock::META_KEY, true));

        $rows = $this->historySnapshot($subject);
        $this->assertSame('lock', $rows[count($rows) - 1]['change_type']);
        $this->assertSame('account_locked', $rows[count($rows) - 1]['field_name']);

        $unlocked = $this->lock->unlock_user($subject);
        $this->assertTrue($unlocked);
        $this->assertFalse($this->lock->is_user_locked($subject));

        $rows = $this->historySnapshot($subject);
        $this->assertSame('unlock', $rows[count($rows) - 1]['change_type']);
    }

    public function test_locked_user_cannot_authenticate_and_app_passwords_fail(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);
        $this->lock->lock_user($subject);

        $user = get_userdata($subject);
        $blocked = $this->lock->block_locked_user_auth($user, $user->user_login, 'password');

        $this->assertInstanceOf(WP_Error::class, $blocked);
        $this->assertSame('user_locked', $blocked->get_error_code());
        $this->assertStringContainsString('contact the administrator', $blocked->get_error_message());

        $error = new WP_Error();
        $this->lock->block_locked_user_app_password($error, $user);
        $this->assertSame('user_locked', $error->get_error_code());

        $this->assertFalse($this->lock->block_locked_user_session($subject));
    }

    public function test_operator_cannot_lock_themselves(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);

        $result = $this->lock->lock_user($administrator);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('self_lock', $result->get_error_code());
        $this->assertFalse($this->lock->is_user_locked($administrator));
    }

    public function test_editor_without_edit_user_cannot_lock_via_ajax(): void
    {
        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        $deny = static function ($caps, $cap, $user_id, $args) use ($subject) {
            if ($cap === 'edit_user' && isset($args[0]) && (int) $args[0] === $subject) {
                return ['do_not_allow'];
            }

            return $caps;
        };
        add_filter('map_meta_cap', $deny, 10, 4);

        wp_set_current_user($editor);
        $this->assertFalse($this->lock->current_operator_can_lock_user($subject));

        $response = $this->toggleLock($subject, 'lock');
        remove_filter('map_meta_cap', $deny, 10);

        $this->assertFalse($response['success']);
        $this->assertFalse($this->lock->is_user_locked($subject));
    }

    public function test_administrator_can_lock_via_ajax(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);

        $response = $this->toggleLock($subject, 'lock');

        $this->assertTrue($response['success']);
        $this->assertTrue($this->lock->is_user_locked($subject));
    }

    public function test_custom_lock_message_is_used_when_set(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);
        update_option(User_History_Lock::MESSAGE_OPTION, 'Call the office.');
        $this->lock->lock_user($subject);

        $blocked = $this->lock->block_locked_user_auth(get_userdata($subject));
        $this->assertSame('Call the office.', $blocked->get_error_message());
    }

    public function test_migration_copies_legacy_lock_flags_once(): void
    {
        $legacy = self::factory()->user->create(['role' => 'subscriber']);
        $plain = self::factory()->user->create(['role' => 'subscriber']);
        update_user_meta($legacy, 'baba_user_locked', 'yes');
        update_option('baba_locked_message', 'Old lock message.');
        delete_option(User_History_Lock::MIGRATED_OPTION);
        delete_option(User_History_Lock::MESSAGE_OPTION);

        $this->lock->maybe_migrate_lock_user_account();

        $this->assertTrue($this->lock->is_user_locked($legacy));
        $this->assertFalse($this->lock->is_user_locked($plain));
        $this->assertSame('Old lock message.', get_option(User_History_Lock::MESSAGE_OPTION));
        $this->assertSame('1', get_option(User_History_Lock::MIGRATED_OPTION));

        update_user_meta($plain, 'baba_user_locked', 'yes');
        $this->lock->maybe_migrate_lock_user_account();
        $this->assertFalse($this->lock->is_user_locked($plain));
    }

    public function test_bulk_lock_skips_users_the_operator_cannot_edit(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        $blocked = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($administrator);

        $deny = static function ($caps, $cap, $user_id, $args) use ($blocked) {
            if ($cap === 'edit_user' && isset($args[0]) && (int) $args[0] === $blocked) {
                return ['do_not_allow'];
            }

            return $caps;
        };
        add_filter('map_meta_cap', $deny, 10, 4);

        $redirect = $this->lock->handle_lock_bulk_actions(admin_url('users.php'), 'user_history_lock_users', [$subject, $blocked]);
        remove_filter('map_meta_cap', $deny, 10);

        $this->assertTrue($this->lock->is_user_locked($subject));
        $this->assertFalse($this->lock->is_user_locked($blocked));
        $this->assertStringContainsString('user_history_lock_count=1', $redirect);
    }

    public function test_row_action_is_hidden_for_self_and_unauthorized_targets(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);

        $self_actions = $this->lock->add_lock_row_action([], get_userdata($administrator));
        $this->assertArrayNotHasKey('user_history_lock', $self_actions);

        $target_actions = $this->lock->add_lock_row_action([], get_userdata($subject));
        $this->assertArrayHasKey('user_history_lock', $target_actions);
    }

    public function test_users_table_shows_status_column_and_locked_view(): void
    {
        [$administrator, $subject] = $this->createAdministratorAndSubject();
        wp_set_current_user($administrator);
        $this->lock->lock_user($subject);

        $columns = $this->lock->add_locked_column(['role' => 'Role']);
        $this->assertSame('Status', $columns['user_history_locked']);
        $this->assertSame(
            'Locked',
            wp_strip_all_tags($this->lock->render_locked_column('', 'user_history_locked', $subject))
        );
        $this->assertSame('&mdash;', $this->lock->render_locked_column('', 'user_history_locked', $administrator));

        $views = $this->lock->add_locked_users_view([]);
        $this->assertArrayHasKey('user_history_locked', $views);
        $this->assertStringContainsString('Locked', $views['user_history_locked']);
        $this->assertStringContainsString('(1)', $views['user_history_locked']);
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

    private function toggleLock($user_id, $action): array
    {
        $_POST = [
            'action'      => 'user_history_toggle_lock',
            'nonce'       => wp_create_nonce('user_history_lock'),
            'user_id'     => (int) $user_id,
            'lock_action' => $action,
        ];

        try {
            $this->_handleAjax('user_history_toggle_lock');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    private function historySnapshot($user_id): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT field_name, change_type FROM ' . $wpdb->prefix . User_History::TABLE_NAME . ' WHERE user_id = %d ORDER BY id ASC',
                (int) $user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }
}
