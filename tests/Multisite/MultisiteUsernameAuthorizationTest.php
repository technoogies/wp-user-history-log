<?php

final class MultisiteUsernameAuthorizationTest extends WP_Ajax_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        User_History::get_instance()->activate();
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subsite_administrator_cannot_change_network_global_username(): void
    {
        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();
        $administrator = self::factory()->user->create(
            [
                'role'       => 'administrator',
                'user_login' => 'subsite-administrator',
            ]
        );

        wp_set_current_user($administrator);

        $this->assertFalse(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('edit_user', $administrator));
        $this->assertFalse(current_user_can('manage_network_users'));
        $this->assertFalse(is_super_admin($administrator));

        $history_count = User_History::get_instance()->get_user_history_count($administrator);
        $response = $this->changeUsername('subsite-administrator', 'subsite-admin-renamed');

        $this->assertFalse($response['success']);
        $this->assertSame('subsite-administrator', get_userdata($administrator)->user_login);
        $this->assertFalse(username_exists('subsite-admin-renamed'));
        $this->assertSame(
            $history_count,
            User_History::get_instance()->get_user_history_count($administrator)
        );
    }

    public function test_non_super_admin_is_denied_even_with_delegated_network_capabilities(): void
    {
        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();
        $administrator = self::factory()->user->create(
            [
                'role'       => 'administrator',
                'user_login' => 'delegated-administrator',
            ]
        );
        $administrator_user = get_userdata($administrator);
        $administrator_user->add_cap('edit_users');
        $administrator_user->add_cap('manage_network_users');

        wp_set_current_user($administrator);

        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('edit_user', $administrator));
        $this->assertTrue(current_user_can('manage_network_users'));
        $this->assertFalse(is_super_admin($administrator));

        $response = $this->changeUsername('delegated-administrator', 'delegated-renamed');

        $this->assertFalse($response['success']);
        $this->assertSame('delegated-administrator', get_userdata($administrator)->user_login);
        $this->assertFalse(username_exists('delegated-renamed'));
    }

    public function test_network_super_administrator_can_change_eligible_username(): void
    {
        $site_id = self::factory()->blog->create();
        $network_administrator = self::factory()->user->create(
            [
                'user_login' => 'network-administrator',
            ]
        );
        $target = self::factory()->user->create(
            [
                'user_login' => 'super-admin-target',
            ]
        );
        grant_super_admin($network_administrator);
        add_user_to_blog($site_id, $target, 'subscriber');

        switch_to_blog($site_id);
        wp_set_current_user($network_administrator);
        User_History::get_instance()->activate();

        $this->assertTrue(is_super_admin($network_administrator));
        $this->assertTrue(current_user_can('manage_network_users'));
        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('edit_user', $target));

        $response = $this->changeUsername('super-admin-target', 'super-admin-renamed');

        $this->assertTrue($response['success']);
        $this->assertSame('super-admin-renamed', get_userdata($target)->user_login);
        $this->assertFalse(username_exists('super-admin-target'));
    }

    private function changeUsername($current_username, $new_username): array
    {
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => wp_create_nonce('user_history_change_username'),
            'current_username' => $current_username,
            'new_username'     => $new_username,
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }
}
