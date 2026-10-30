<?php

final class MultisiteHistoricalSearchScopeTest extends WP_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->openUsersScreen();
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        $GLOBALS['pagenow'] = '';
        unset($GLOBALS['current_screen']);
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_historical_match_is_found_for_a_site_member(): void
    {
        $site_id = self::factory()->blog->create();
        $operator = $this->createNetworkOperator();
        $old_email = 'former-member-' . wp_generate_password(8, false, false) . '@example.com';

        switch_to_blog($site_id);
        $this->plugin->activate();
        $this->openUsersScreen();
        wp_set_current_user($operator);

        $member = self::factory()->user->create(
            [
                'user_email' => $old_email,
            ]
        );
        add_user_to_blog($site_id, $member, 'subscriber');
        $this->changeEmail($member, 'current-member-' . wp_generate_password(8, false, false) . '@example.com');

        $ids = $this->searchUserIds($old_email, ['blog_id' => $site_id]);

        $this->assertContains($member, $ids);
    }

    public function test_historical_match_remains_excluded_when_the_user_is_not_a_site_member(): void
    {
        $site_id = self::factory()->blog->create();
        $operator = $this->createNetworkOperator();
        $suffix = wp_generate_password(8, false, false);
        $old_email = 'former-site-' . $suffix . '@example.com';

        switch_to_blog($site_id);
        $this->plugin->activate();
        $this->openUsersScreen();
        wp_set_current_user($operator);

        $former_member = self::factory()->user->create(
            [
                'user_email' => $old_email,
            ]
        );
        add_user_to_blog($site_id, $former_member, 'subscriber');
        $this->changeEmail($former_member, 'current-site-' . $suffix . '@example.com');
        remove_user_from_blog($former_member, $site_id);

        $ids = $this->searchUserIds($old_email, ['blog_id' => $site_id]);

        $this->assertNotContains($former_member, $ids);
        $this->assertFalse(is_user_member_of_blog($former_member, $site_id));
    }

    public function test_historical_match_remains_excluded_when_exclude_contains_a_site_member(): void
    {
        $site_id = self::factory()->blog->create();
        $operator = $this->createNetworkOperator();
        $old_email = 'former-exclude-' . wp_generate_password(8, false, false) . '@example.com';

        switch_to_blog($site_id);
        $this->plugin->activate();
        $this->openUsersScreen();
        wp_set_current_user($operator);

        $member = self::factory()->user->create(
            [
                'user_email' => $old_email,
            ]
        );
        add_user_to_blog($site_id, $member, 'subscriber');
        $this->changeEmail($member, 'current-exclude-' . wp_generate_password(8, false, false) . '@example.com');

        $ids = $this->searchUserIds(
            $old_email,
            [
                'blog_id' => $site_id,
                'exclude' => [$member],
            ]
        );

        $this->assertNotContains($member, $ids);
    }

    private function createNetworkOperator(): int
    {
        $operator = self::factory()->user->create(
            [
                'user_login' => 'hist-search-operator-' . wp_generate_password(6, false, false),
            ]
        );
        grant_super_admin($operator);

        return $operator;
    }

    private function changeEmail($user_id, $new_email): void
    {
        $updated = wp_update_user(
            [
                'ID'         => $user_id,
                'user_email' => $new_email,
            ]
        );
        $this->assertSame($user_id, $updated);
    }

    private function searchUserIds($term, array $args = []): array
    {
        $query = new WP_User_Query(
            array_merge(
                [
                    'search'         => '*' . $term . '*',
                    'search_columns' => ['user_email'],
                    'fields'         => 'ID',
                    'number'         => 100,
                    'count_total'    => false,
                ],
                $args
            )
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
