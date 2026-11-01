<?php

/**
 * GitHub Release updater for WP User History Log.
 *
 * Compares the plugin header Version with the latest public GitHub Release
 * tag (1.8.0 or v1.8.0). The Plugin Update Checker library is vendored so
 * sites do not need Composer or a GitHub token.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Update_Checker {

    const REPO_URL = 'https://github.com/technoogies/wp-user-history-log';
    const SLUG = 'wp-user-history-log';
    const LIBRARY_FILE = 'lib/plugin-update-checker/plugin-update-checker.php';

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * @var \YahnisElsts\PluginUpdateChecker\v5p7\Plugin\UpdateChecker|null
     */
    private $checker = null;

    /**
     * @return self
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct() {
        $this->boot();
    }

    /**
     * Strip a leading v so 1.8.0 and v1.8.0 compare equal.
     *
     * @param mixed $tag GitHub Release tag or plugin Version header.
     * @return string
     */
    public static function normalize_release_tag($tag) {
        return ltrim(trim((string) $tag), 'vV');
    }

    /**
     * @return \YahnisElsts\PluginUpdateChecker\v5p7\Plugin\UpdateChecker|null
     */
    public function get_checker() {
        return $this->checker;
    }

    private function boot() {
        $library = USER_HISTORY_PLUGIN_DIR . self::LIBRARY_FILE;
        if (!is_readable($library)) {
            return;
        }

        require_once $library;

        if (!class_exists('\YahnisElsts\PluginUpdateChecker\v5\PucFactory')) {
            return;
        }

        $this->checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            self::REPO_URL,
            USER_HISTORY_PLUGIN_FILE,
            self::SLUG
        );

        // Prefer GitHub Releases, then version tags. main is this repo's default
        // branch; PUC still looks at Releases first when the branch is main.
        $this->checker->setBranch('main');

        // Public repository. Do not pass a GitHub token.
    }
}
