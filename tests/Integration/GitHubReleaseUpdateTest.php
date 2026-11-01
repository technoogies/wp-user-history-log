<?php

final class GitHubReleaseUpdateIntegrationTest extends WP_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }
    }

    public function test_update_checker_boots_for_the_public_repo_without_authentication(): void
    {
        $updater = User_History_Update_Checker::get_instance();
        $checker = $updater->get_checker();

        $this->assertSame(
            'https://github.com/technoogies/wp-user-history-log',
            User_History_Update_Checker::REPO_URL
        );
        $this->assertNotNull($checker);
        $this->assertSame(
            '1.9.0',
            User_History_Update_Checker::normalize_release_tag(USER_HISTORY_VERSION)
        );
        $this->assertSame(
            USER_HISTORY_VERSION,
            User_History_Update_Checker::normalize_release_tag('v' . USER_HISTORY_VERSION)
        );
    }
}
