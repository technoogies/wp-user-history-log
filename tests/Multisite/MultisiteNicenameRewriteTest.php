<?php

final class MultisiteNicenameRewriteTest extends WP_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        User_History::get_instance()->activate();
        $GLOBALS['pagenow'] = 'users.php';
        $_POST = [];
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        $_POST = [];
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subsite_editor_of_users_rewrites_only_matching_nicenames_on_that_site(): void
    {
        $main_user = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_login' => 'main.legacy',
                'user_email' => 'main.legacy@example.com',
            ]
        );
        $this->pinNicename($main_user, 'main.legacy');

        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $manager = self::factory()->user->create(['role' => 'administrator']);
        $matching = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'site.legacy',
                'user_email'   => 'site.legacy@example.com',
                'display_name' => 'Site Legacy',
            ]
        );
        $skipped = self::factory()->user->create(
            [
                'role'         => 'subscriber',
                'user_login'   => 'site.custom',
                'user_email'   => 'site.custom@example.com',
                'display_name' => 'Site Custom',
            ]
        );
        add_user_to_blog($site_id, $manager, 'administrator');
        add_user_to_blog($site_id, $matching, 'subscriber');
        add_user_to_blog($site_id, $skipped, 'subscriber');
        $this->pinNicename($matching, 'site.legacy');
        $this->pinNicename($skipped, 'site-custom-nicename');
        update_user_meta($matching, User_History_Profile_Photo::META_KEY, '1');
        wp_set_current_user($manager);

        $rewrite = User_History_Nicename_Rewrite::get_instance(User_History::get_instance());
        $this->assertFalse(current_user_can('edit_users'));
        $this->assertFalse(current_user_can('manage_network_users'));
        $this->assertFalse($rewrite->current_operator_can_rewrite());
        $denied = $rewrite->rewrite_matching_nicenames();
        $this->assertSame(0, $denied['changed']);
        $this->assertSame('site.legacy', get_userdata($matching)->user_nicename);

        grant_super_admin($manager);
        wp_set_current_user($manager);

        $this->assertTrue(is_super_admin($manager));
        $this->assertTrue(current_user_can('edit_users'));
        $this->assertTrue(current_user_can('manage_network_users'));
        $this->assertTrue($rewrite->current_operator_can_rewrite());
        $result = $rewrite->rewrite_matching_nicenames();

        $this->assertSame('site-legacy', get_userdata($matching)->user_nicename);
        $this->assertSame('site-custom-nicename', get_userdata($skipped)->user_nicename);
        $this->assertSame('main.legacy', get_userdata($main_user)->user_nicename);
        $this->assertSame('1', get_user_meta($matching, User_History_Profile_Photo::META_KEY, true));
        $this->assertGreaterThanOrEqual(1, $result['changed']);
        $this->assertGreaterThanOrEqual(1, $result['skipped']);
    }

    /**
     * @param int    $user_id User ID.
     * @param string $nicename Stored nicename.
     */
    private function pinNicename($user_id, $nicename): void
    {
        global $wpdb;

        $wpdb->update(
            $wpdb->users,
            ['user_nicename' => $nicename],
            ['ID' => (int) $user_id],
            ['%s'],
            ['%d']
        );
        clean_user_cache((int) $user_id);
    }
}
