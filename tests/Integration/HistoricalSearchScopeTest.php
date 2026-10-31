<?php

final class HistoricalSearchScopeTest extends WP_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->openUsersScreen();
    }

    protected function tearDown(): void
    {
        $GLOBALS['pagenow'] = '';
        unset($GLOBALS['current_screen']);
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_historical_match_is_found_when_no_query_restriction_excludes_the_user(): void
    {
        [$administrator, $subject, $old_email] = $this->createHistoricallyMatchingUser();
        wp_set_current_user($administrator);

        $ids = $this->searchUserIds($old_email);

        $this->assertContains($subject, $ids);
    }

    public function test_historical_match_remains_excluded_when_exclude_contains_the_user(): void
    {
        [$administrator, $subject, $old_email] = $this->createHistoricallyMatchingUser();
        wp_set_current_user($administrator);

        $ids = $this->searchUserIds($old_email, ['exclude' => [$subject]]);

        $this->assertNotContains($subject, $ids);
    }

    public function test_historical_match_remains_excluded_when_login_not_in_contains_the_user(): void
    {
        [$administrator, $subject, $old_email] = $this->createHistoricallyMatchingUser();
        wp_set_current_user($administrator);

        $user = get_userdata($subject);
        $ids = $this->searchUserIds(
            $old_email,
            ['login__not_in' => [$user->user_login]]
        );

        $this->assertNotContains($subject, $ids);
    }

    public function test_historical_match_remains_excluded_when_a_plugin_adds_an_and_restriction(): void
    {
        global $wpdb;

        [$administrator, $subject, $old_email] = $this->createHistoricallyMatchingUser();
        wp_set_current_user($administrator);

        $restrict = static function ($query) use ($wpdb, $subject) {
            $query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.ID != %d", $subject);
        };
        add_action('pre_user_query', $restrict, 20);

        try {
            $ids = $this->searchUserIds($old_email);
        } finally {
            remove_action('pre_user_query', $restrict, 20);
        }

        $this->assertNotContains($subject, $ids);
    }

    /**
     * @return array{0:int,1:int,2:string}
     */
    private function createHistoricallyMatchingUser(): array
    {
        $suffix = wp_generate_password(8, false, false);
        $old_email = 'former-scope-' . $suffix . '@example.com';
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(
            [
                'role'       => 'subscriber',
                'user_email' => $old_email,
            ]
        );

        wp_set_current_user($administrator);
        $updated = wp_update_user(
            [
                'ID'         => $subject,
                'user_email' => 'current-scope-' . $suffix . '@example.com',
            ]
        );
        $this->assertSame($subject, $updated);

        return [$administrator, $subject, $old_email];
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
