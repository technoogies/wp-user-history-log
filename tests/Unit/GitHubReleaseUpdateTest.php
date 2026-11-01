<?php

use PHPUnit\Framework\TestCase;

final class GitHubReleaseUpdateTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__, 2);

        if (!defined('ABSPATH')) {
            define('ABSPATH', $this->root . '/');
        }

        require_once $this->root . '/includes/class-update-checker.php';
    }

    public function test_release_tags_with_or_without_v_prefix_normalize_equally(): void
    {
        $this->assertSame('1.8.0', User_History_Update_Checker::normalize_release_tag('1.8.0'));
        $this->assertSame('1.8.0', User_History_Update_Checker::normalize_release_tag('v1.8.0'));
        $this->assertSame('1.8.0', User_History_Update_Checker::normalize_release_tag('V1.8.0'));
        $this->assertSame('1.9.0', User_History_Update_Checker::normalize_release_tag(' v1.9.0 '));
    }

    public function test_updater_uses_public_repo_and_vendored_library_without_a_token(): void
    {
        $source = $this->updaterSource();

        $this->assertStringContainsString("if (!defined('ABSPATH'))", $source);
        $this->assertStringContainsString('https://github.com/technoogies/wp-user-history-log', $source);
        $this->assertStringContainsString("SLUG = 'wp-user-history-log'", $source);
        $this->assertStringContainsString('lib/plugin-update-checker/plugin-update-checker.php', $source);
        $this->assertStringContainsString("setBranch('main')", $source);
        $this->assertStringNotContainsString('->setAuthentication(', $source);
        $this->assertStringNotContainsString('wp_ajax_nopriv_', $source);
        $this->assertStringNotContainsString('TRUNCATE', $source);
        $this->assertStringNotContainsString('ipinfo.io', $source);
        $this->assertDoesNotMatchRegularExpression('/\b(?:ghp_|github_pat_)/', $source);
        $this->assertFileExists($this->root . '/lib/plugin-update-checker/plugin-update-checker.php');
        $this->assertFileExists($this->root . '/lib/plugin-update-checker/license.txt');
    }

    public function test_release_action_publishes_a_tag_matching_plugin_version(): void
    {
        $workflow = file_get_contents($this->root . '/.github/workflows/release.yml');
        $script = file_get_contents($this->root . '/bin/create-github-release.sh');
        $plugin = file_get_contents($this->root . '/wp-user-history-logging.php');

        $this->assertNotFalse($workflow);
        $this->assertNotFalse($script);
        $this->assertNotFalse($plugin);

        $this->assertStringContainsString("branches:\n      - main", $workflow);
        $this->assertStringContainsString('contents: write', $workflow);
        $this->assertStringContainsString('bin/create-github-release.sh', $workflow);
        $this->assertStringContainsString('Version:', $script);
        $this->assertStringContainsString('gh release create', $script);
        $this->assertStringContainsString('v${current_version}', $script);
        $this->assertStringNotContainsString('ghp_', $script);
        $this->assertStringNotContainsString('github_pat_', $script);

        $this->assertSame(1, preg_match('/^\s*\*\s*Version:\s*(.+)$/m', $plugin, $plugin_version));
        $this->assertSame('1.9.0', trim($plugin_version[1]));
        $this->assertSame(
            User_History_Update_Checker::normalize_release_tag('v1.9.0'),
            User_History_Update_Checker::normalize_release_tag(trim($plugin_version[1]))
        );
    }

    private function updaterSource(): string
    {
        $source = file_get_contents($this->root . '/includes/class-update-checker.php');
        $this->assertNotFalse($source);

        return $source;
    }
}
