<?php

final class HistoricalSearchGroupingTest extends WP_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->plugin = User_History::get_instance();
    }

    public function test_historical_ids_are_inserted_inside_the_search_group(): void
    {
        global $wpdb;

        $where = "WHERE 1=1 AND (user_login LIKE '%former%' OR user_email LIKE '%former%') AND {$wpdb->users}.ID NOT IN (9)";
        $updated = $this->insertGroup($where, "{$wpdb->users}.ID IN (42)");

        $this->assertSame(
            "WHERE 1=1 AND (user_login LIKE '%former%' OR user_email LIKE '%former%' OR {$wpdb->users}.ID IN (42)) AND {$wpdb->users}.ID NOT IN (9)",
            $updated
        );
    }

    public function test_earlier_subquery_parentheses_do_not_capture_the_search_group(): void
    {
        global $wpdb;

        $where = "WHERE 1=1 AND {$wpdb->users}.ID IN ( SELECT DISTINCT post_author FROM {$wpdb->posts} WHERE post_status = 'publish' AND post_type IN ( 'post', 'page' ) ) AND (user_login LIKE '%former%') AND {$wpdb->users}.ID NOT IN (9)";
        $updated = $this->insertGroup($where, "{$wpdb->users}.ID IN (42)");

        $this->assertStringContainsString(
            "AND (user_login LIKE '%former%' OR {$wpdb->users}.ID IN (42))",
            $updated
        );
        $this->assertStringContainsString("AND {$wpdb->users}.ID NOT IN (9)", $updated);
        $this->assertStringEndsWith("AND {$wpdb->users}.ID NOT IN (9)", $updated);
    }

    public function test_parentheses_inside_quoted_search_text_do_not_break_grouping(): void
    {
        global $wpdb;

        $where = "WHERE 1=1 AND (user_login LIKE '%foo (bar)%' OR display_name LIKE '%foo (bar)%') AND {$wpdb->users}.ID NOT IN (9)";
        $updated = $this->insertGroup($where, "{$wpdb->users}.ID IN (42)");

        $this->assertSame(
            "WHERE 1=1 AND (user_login LIKE '%foo (bar)%' OR display_name LIKE '%foo (bar)%' OR {$wpdb->users}.ID IN (42)) AND {$wpdb->users}.ID NOT IN (9)",
            $updated
        );
    }

    public function test_missing_search_group_does_not_append_an_outer_or(): void
    {
        global $wpdb;

        $where = "WHERE 1=1 AND {$wpdb->users}.ID NOT IN (9)";
        $updated = $this->insertGroup($where, "{$wpdb->users}.ID IN (42)");

        $this->assertSame($where, $updated);
        $this->assertStringNotContainsString(' OR ', $updated);
    }

    private function insertGroup($where, $historical_sql): string
    {
        $method = new ReflectionMethod(User_History::class, 'insert_historical_ids_into_search_group');
        $method->setAccessible(true);

        return $method->invoke($this->plugin, $where, $historical_sql);
    }
}
