<?php

final class AjaxAuthorizationTest extends WP_Ajax_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        User_History::get_instance()->activate();
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subscriber_cannot_change_a_username_even_with_a_valid_nonce(): void
    {
        $subscriber = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'baseline-subscriber',
            ]
        );
        $target = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'baseline-target',
            ]
        );

        wp_set_current_user($subscriber);
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => wp_create_nonce('user_history_change_username'),
            'current_username' => 'baseline-target',
            'new_username'     => 'renamed-target',
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);

        $this->assertIsArray($response);
        $this->assertFalse($response['success']);
        $this->assertSame(
            'baseline-target',
            get_userdata($target)->user_login
        );
    }

    public function test_administrator_cannot_change_a_username_with_an_invalid_nonce(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $target = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'nonce-target',
            ]
        );

        wp_set_current_user($administrator);
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => 'invalid',
            'current_username' => 'nonce-target',
            'new_username'     => 'nonce-bypass',
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);

        $this->assertIsArray($response);
        $this->assertFalse($response['success']);
        $this->assertSame('nonce-target', get_userdata($target)->user_login);
    }

    public function test_single_site_administrator_can_change_an_eligible_username(): void
    {
        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $target = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'single-site-target',
            ]
        );

        wp_set_current_user($administrator);
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => wp_create_nonce('user_history_change_username'),
            'current_username' => 'single-site-target',
            'new_username'     => 'single-site-renamed',
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);

        $this->assertIsArray($response);
        $this->assertTrue($response['success']);
        $this->assertSame('single-site-renamed', get_userdata($target)->user_login);
    }

    public function test_target_level_denial_prevents_username_mutation(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $target = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'protected-target',
            ]
        );
        $deny_target = static function ($required_caps, $capability, $user_id, $args) use ($target) {
            if ('edit_user' === $capability && isset($args[0]) && (int) $args[0] === $target) {
                return ['do_not_allow'];
            }

            return $required_caps;
        };
        add_filter('map_meta_cap', $deny_target, 10, 4);

        wp_set_current_user($administrator);
        $_POST = [
            'action'           => 'user_history_change_username',
            '_ajax_nonce'      => wp_create_nonce('user_history_change_username'),
            'current_username' => 'protected-target',
            'new_username'     => 'protected-renamed',
        ];

        try {
            $this->_handleAjax('user_history_change_username');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json() ends the AJAX request.
        } finally {
            remove_filter('map_meta_cap', $deny_target, 10);
        }

        $response = json_decode($this->_last_response, true);

        $this->assertIsArray($response);
        $this->assertFalse($response['success']);
        $this->assertSame('protected-target', get_userdata($target)->user_login);
        $this->assertFalse(username_exists('protected-renamed'));
    }
}
