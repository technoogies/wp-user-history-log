<?php

final class DashboardAccessTest extends WP_UnitTestCase
{
    private User_History $plugin;
    private User_History_Dashboard_Access $dashboard;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->dashboard = User_History_Dashboard_Access::get_instance($this->plugin);
        $this->resetDashboardOptions();
    }

    protected function tearDown(): void
    {
        $this->resetDashboardOptions();
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_dashboard_restriction_is_off_by_default(): void
    {
        $subscriber = self::factory()->user->create(['role' => 'subscriber']);
        wp_set_current_user($subscriber);

        $this->assertFalse($this->dashboard->is_enabled());
        $this->assertSame('0', (string) get_option(User_History_Dashboard_Access::OPTION_ENABLED, '0'));
        $this->assertFalse($this->dashboard->should_restrict_current_user());
        $this->assertFalse($this->dashboard->should_redirect_current_request('index.php'));
        $this->assertFalse($this->dashboard->should_restrict_ajax_request());
    }

    public function test_administrators_only_redirects_subscribers_and_not_admins(): void
    {
        [$administrator, $subscriber] = $this->createAdministratorAndSubscriber();
        update_option(User_History_Dashboard_Access::OPTION_ENABLED, '1');
        update_option(User_History_Dashboard_Access::OPTION_SWITCH, 'manage_options');

        wp_set_current_user($subscriber);
        $this->assertTrue($this->dashboard->should_restrict_current_user());
        $this->assertTrue($this->dashboard->should_redirect_current_request('index.php'));

        wp_set_current_user($administrator);
        $this->assertFalse($this->dashboard->should_restrict_current_user());
        $this->assertFalse($this->dashboard->should_redirect_current_request('index.php'));
    }

    public function test_profile_access_skips_redirect_for_restricted_users(): void
    {
        [, $subscriber] = $this->createAdministratorAndSubscriber();
        update_option(User_History_Dashboard_Access::OPTION_ENABLED, '1');
        update_option(User_History_Dashboard_Access::OPTION_SWITCH, 'manage_options');
        update_option(User_History_Dashboard_Access::OPTION_PROFILE, '1');
        wp_set_current_user($subscriber);

        $this->assertFalse($this->dashboard->should_redirect_current_request('profile.php'));
        $this->assertTrue($this->dashboard->should_redirect_current_request('index.php'));

        update_option(User_History_Dashboard_Access::OPTION_PROFILE, '0');
        $this->assertTrue($this->dashboard->should_redirect_current_request('profile.php'));
    }

    public function test_allowlist_wildcard_matches_only_those_pages(): void
    {
        update_option(User_History_Dashboard_Access::OPTION_ALLOWLIST, 'admin.php?page=example-*');

        $this->assertTrue($this->dashboard->request_matches_allowlist('admin.php', ['page' => 'example-tools']));
        $this->assertTrue($this->dashboard->request_matches_allowlist('admin.php', ['page' => 'example-settings', 'tab' => 'general']));
        $this->assertFalse($this->dashboard->request_matches_allowlist('admin.php', ['page' => 'other-page']));
        $this->assertFalse($this->dashboard->request_matches_allowlist('users.php', ['page' => 'example-tools']));
    }

    public function test_ajax_stays_unlocked_by_default(): void
    {
        [, $subscriber] = $this->createAdministratorAndSubscriber();
        update_option(User_History_Dashboard_Access::OPTION_ENABLED, '1');
        update_option(User_History_Dashboard_Access::OPTION_SWITCH, 'manage_options');
        wp_set_current_user($subscriber);

        $this->assertSame('0', (string) get_option(User_History_Dashboard_Access::OPTION_LOCK_AJAX, '0'));
        $this->assertFalse($this->dashboard->should_restrict_ajax_request());

        update_option(User_History_Dashboard_Access::OPTION_LOCK_AJAX, '1');
        $this->assertTrue($this->dashboard->should_restrict_ajax_request());
    }

    public function test_turning_the_feature_off_restores_access(): void
    {
        [, $subscriber] = $this->createAdministratorAndSubscriber();
        update_option(User_History_Dashboard_Access::OPTION_ENABLED, '1');
        update_option(User_History_Dashboard_Access::OPTION_SWITCH, 'manage_options');
        wp_set_current_user($subscriber);

        $this->assertTrue($this->dashboard->should_restrict_current_user());

        update_option(User_History_Dashboard_Access::OPTION_ENABLED, '0');

        $this->assertFalse($this->dashboard->is_enabled());
        $this->assertFalse($this->dashboard->should_restrict_current_user());
        $this->assertFalse($this->dashboard->should_redirect_current_request('index.php'));
        $this->assertFalse($this->dashboard->should_restrict_ajax_request());
    }

    public function test_rda_import_copies_settings_but_leaves_the_switch_off(): void
    {
        delete_option(User_History_Dashboard_Access::MIGRATED_OPTION);
        update_option('rda_access_switch', 'edit_others_posts');
        update_option('rda_access_cap', 'edit_posts');
        update_option('rda_redirect_url', home_url('/welcome/'));
        update_option('rda_login_message', 'Staff only.');
        update_option('rda_url_allowlist', 'admin.php?page=example-*');
        update_option('rda_enable_profile', '0');
        update_option('rda_lock_ajax', '1');

        $this->dashboard->maybe_import_rda_settings();

        $this->assertSame('1', get_option(User_History_Dashboard_Access::MIGRATED_OPTION));
        $this->assertSame('0', (string) get_option(User_History_Dashboard_Access::OPTION_ENABLED, '0'));
        $this->assertFalse($this->dashboard->is_enabled());
        $this->assertSame('edit_others_posts', get_option(User_History_Dashboard_Access::OPTION_SWITCH));
        $this->assertSame('edit_posts', get_option(User_History_Dashboard_Access::OPTION_CAP));
        $this->assertSame(home_url('/welcome/'), get_option(User_History_Dashboard_Access::OPTION_REDIRECT));
        $this->assertSame('Staff only.', get_option(User_History_Dashboard_Access::OPTION_LOGIN_MESSAGE));
        $this->assertSame('/admin.php?page=example-*', get_option(User_History_Dashboard_Access::OPTION_ALLOWLIST));
        $this->assertSame('0', get_option(User_History_Dashboard_Access::OPTION_PROFILE));
        $this->assertSame('1', get_option(User_History_Dashboard_Access::OPTION_LOCK_AJAX));

        update_option('rda_access_switch', 'publish_posts');
        $this->dashboard->maybe_import_rda_settings();
        $this->assertSame('edit_others_posts', get_option(User_History_Dashboard_Access::OPTION_SWITCH));
        $this->assertSame('0', (string) get_option(User_History_Dashboard_Access::OPTION_ENABLED, '0'));
    }

    public function test_enabling_requires_manage_user_history_and_manage_options(): void
    {
        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap(User_History::CLEAR_HISTORY_CAPABILITY);
        wp_set_current_user($editor);

        $this->assertTrue(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));
        $this->assertFalse(current_user_can('manage_options'));
        $this->assertFalse($this->dashboard->current_operator_can_enable());
        $this->assertSame('0', $this->dashboard->sanitize_enabled('1'));

        $administrator = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($administrator);

        $this->assertTrue($this->dashboard->current_operator_can_enable());
        $this->assertSame('1', $this->dashboard->sanitize_enabled('1'));
        $this->assertSame('0', $this->dashboard->sanitize_enabled('0'));
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createAdministratorAndSubscriber(): array
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subscriber = self::factory()->user->create(['role' => 'subscriber']);

        return [$administrator, $subscriber];
    }

    private function resetDashboardOptions(): void
    {
        delete_option(User_History_Dashboard_Access::OPTION_ENABLED);
        delete_option(User_History_Dashboard_Access::OPTION_SWITCH);
        delete_option(User_History_Dashboard_Access::OPTION_CAP);
        delete_option(User_History_Dashboard_Access::OPTION_REDIRECT);
        delete_option(User_History_Dashboard_Access::OPTION_PROFILE);
        delete_option(User_History_Dashboard_Access::OPTION_LOGIN_MESSAGE);
        delete_option(User_History_Dashboard_Access::OPTION_LOCK_AJAX);
        delete_option(User_History_Dashboard_Access::OPTION_ALLOWLIST);
        delete_option(User_History_Dashboard_Access::MIGRATED_OPTION);
        delete_option('rda_access_switch');
        delete_option('rda_access_cap');
        delete_option('rda_redirect_url');
        delete_option('rda_login_message');
        delete_option('rda_url_allowlist');
        delete_option('rda_enable_profile');
        delete_option('rda_lock_ajax');
    }
}
