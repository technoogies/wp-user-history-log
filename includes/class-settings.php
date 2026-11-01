<?php

/**
 * User History admin menu and Settings screen.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Settings {

    const MENU_SLUG = 'user-history';
    const OPTION_GROUP = 'user_history_settings';
    const CLEAR_ALL_NONCE = 'user_history_clear_all_logs';

    /**
     * Singleton instance
     *
     * @var self|null
     */
    private static $instance = null;

    /**
     * Get singleton instance
     *
     * @return self
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        add_action('admin_menu', [$this, 'register_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('option_page_capability_' . self::OPTION_GROUP, [$this, 'settings_capability']);
        add_filter('plugin_action_links_' . plugin_basename(USER_HISTORY_PLUGIN_FILE), [$this, 'plugin_action_links']);
        add_action('wp_ajax_user_history_clear_all_logs', [$this, 'ajax_clear_all_logs']);
    }

    /**
     * Capability for the User History menu and Settings saves.
     *
     * @return string
     */
    public function settings_capability() {
        return User_History::CLEAR_HISTORY_CAPABILITY;
    }

    /**
     * Register the User History top-level menu. Settings stays last.
     */
    public function register_menu() {
        $capability = $this->settings_capability();
        if (!current_user_can($capability)) {
            return;
        }

        add_menu_page(
            __('User History Settings', 'user-history'),
            __('User History', 'user-history'),
            $capability,
            self::MENU_SLUG,
            [$this, 'render_settings_page'],
            'dashicons-backup',
            71
        );

        // Same slug as the parent so WordPress does not copy a duplicate first item.
        add_submenu_page(
            self::MENU_SLUG,
            __('User History Settings', 'user-history'),
            __('Settings', 'user-history'),
            $capability,
            self::MENU_SLUG,
            [$this, 'render_settings_page']
        );

        add_submenu_page(
            self::MENU_SLUG,
            __('Lock Accounts', 'user-history'),
            __('Lock Accounts', 'user-history'),
            $capability,
            User_History_Lock::MENU_SLUG,
            [User_History_Lock::get_instance(), 'render_settings_page'],
            0
        );
    }

    /**
     * Register Settings API fields. Retention stays 0; IP stays on.
     */
    public function register_settings() {
        register_setting(
            self::OPTION_GROUP,
            'user_history_retention_days',
            [
                'type'              => 'integer',
                'sanitize_callback' => [$this, 'sanitize_retention_days'],
                'default'           => 0,
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            'user_history_collect_ip',
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_collect_ip'],
                'default'           => '1',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            User_History_Login_Tracker::OPTION_KEY,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_login_tracking'],
                'default'           => '0',
                'show_in_rest'      => false,
            ]
        );

        add_settings_section(
            'user_history_privacy',
            __('Privacy', 'user-history'),
            [$this, 'render_privacy_section'],
            self::MENU_SLUG
        );

        add_settings_field(
            'user_history_collect_ip',
            __('Record IP addresses', 'user-history'),
            [$this, 'render_collect_ip_field'],
            self::MENU_SLUG,
            'user_history_privacy'
        );

        add_settings_field(
            User_History_Login_Tracker::OPTION_KEY,
            __('Record logins', 'user-history'),
            [$this, 'render_login_tracking_field'],
            self::MENU_SLUG,
            'user_history_privacy'
        );

        add_settings_section(
            'user_history_retention',
            __('Data retention', 'user-history'),
            [$this, 'render_retention_section'],
            self::MENU_SLUG
        );

        add_settings_field(
            'user_history_retention_days',
            __('Keep forever (0) or delete rows older than this many days.', 'user-history'),
            [$this, 'render_retention_days_field'],
            self::MENU_SLUG,
            'user_history_retention'
        );
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return int Zero or a positive day count. Never a 30-day default.
     */
    public function sanitize_retention_days($value) {
        return max(0, (int) $value);
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string '1' or '0'
     */
    public function sanitize_collect_ip($value) {
        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string '1' or '0'. Default stays off.
     */
    public function sanitize_login_tracking($value) {
        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * Settings intro for the privacy section.
     */
    public function render_privacy_section() {
        echo '<p>' . esc_html__('Choose whether new history rows store the operator IP address. Existing rows are not rewritten.', 'user-history') . '</p>';
    }

    /**
     * Settings intro for the retention section.
     */
    public function render_retention_section() {
        echo '<p>' . esc_html__('Automatic cleanup uses the existing daily hook. This screen does not add a second schedule.', 'user-history') . '</p>';
    }

    /**
     * IP collection checkbox. USER_HISTORY_COLLECT_IP still wins when defined.
     */
    public function render_collect_ip_field() {
        $constant_defined = defined('USER_HISTORY_COLLECT_IP');
        $option_on = $this->option_flag_is_enabled(get_option('user_history_collect_ip', '1'));
        $effective_on = $constant_defined ? (bool) USER_HISTORY_COLLECT_IP : $option_on;

        if ($constant_defined) {
            ?>
            <label>
                <input type="checkbox" value="1" <?php checked($effective_on); ?> disabled="disabled" />
                <?php esc_html_e('Record IP addresses in new history rows', 'user-history'); ?>
            </label>
            <p class="description">
                <?php esc_html_e('USER_HISTORY_COLLECT_IP is defined, so that value is used instead of this checkbox.', 'user-history'); ?>
            </p>
            <?php
            return;
        }

        ?>
        <label>
            <input type="hidden" name="user_history_collect_ip" value="0" />
            <input type="checkbox" name="user_history_collect_ip" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Record IP addresses in new history rows', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('On by default. Uncheck to stop storing operator IPs in the encrypted snapshot. You can still override this with USER_HISTORY_COLLECT_IP or the user_history_collect_ip filter.', 'user-history'); ?>
            </p>
        <?php
    }

    /**
     * Login recording checkbox. Default off so an update does not fill the history table.
     */
    public function render_login_tracking_field() {
        $option_on = $this->option_flag_is_enabled(get_option(User_History_Login_Tracker::OPTION_KEY, '0'));

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(User_History_Login_Tracker::OPTION_KEY); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(User_History_Login_Tracker::OPTION_KEY); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Record login, logout, and failed-login events for existing accounts', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Off by default. Failed logins are stored only when the typed username or email matches a real account. Passwords are never stored.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Retention number field. Default 0 keeps history forever.
     */
    public function render_retention_days_field() {
        $days = max(0, (int) get_option('user_history_retention_days', 0));

        ?>
        <input
            type="number"
            min="0"
            step="1"
            class="small-text"
            id="user_history_retention_days"
            name="user_history_retention_days"
            value="<?php echo esc_attr((string) $days); ?>"
        />
        <p class="description">
            <?php esc_html_e('0 means keep history forever. Type 1 or more days to turn on daily cleanup. This plugin will not delete old rows unless you opt in.', 'user-history'); ?>
        </p>
        <?php if ($days > 0) : ?>
            <p class="description">
                <?php esc_html_e('Daily cleanup is on. Rows older than this many days are removed once a day.', 'user-history'); ?>
            </p>
        <?php endif; ?>
        <?php
    }

    /**
     * Render the Settings screen.
     */
    public function render_settings_page() {
        if (!current_user_can($this->settings_capability())) {
            wp_die(esc_html__('You are not allowed to access User History settings.', 'user-history'));
        }

        ?>
        <div class="wrap user-history-settings">
            <h1><?php esc_html_e('User History Settings', 'user-history'); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields(self::OPTION_GROUP);
                do_settings_sections(self::MENU_SLUG);
                submit_button();
                ?>
            </form>

            <div class="user-history-settings-clear-all">
                <h2><?php esc_html_e('Clear All Logs', 'user-history'); ?></h2>
                <p>
                    <?php esc_html_e('Delete every account-history row on this site. This cannot be undone. A maintenance note is written after a successful clear.', 'user-history'); ?>
                </p>
                <p>
                    <button type="button" id="user-history-clear-all-logs" class="button user-history-clear-log">
                        <?php esc_html_e('Clear All Logs', 'user-history'); ?>
                    </button>
                    <span id="user-history-clear-all-logs-message" class="user-history-clear-all-message" role="status"></span>
                </p>
            </div>
        </div>
        <?php
    }

    /**
     * Add a Settings link on the Plugins screen.
     *
     * @param array<string,string> $links Existing action links.
     * @return array<string,string>
     */
    public function plugin_action_links($links) {
        if (!current_user_can($this->settings_capability())) {
            return $links;
        }

        $url = admin_url('admin.php?page=' . self::MENU_SLUG);
        $links['settings'] = '<a href="' . esc_url($url) . '">' . esc_html__('Settings', 'user-history') . '</a>';

        return $links;
    }

    /**
     * AJAX: clear every history row behind manage_user_history.
     */
    public function ajax_clear_all_logs() {
        check_ajax_referer(self::CLEAR_ALL_NONCE, 'nonce');

        $plugin = User_History::get_instance();
        if (!$plugin->current_operator_can_clear_all_logs()) {
            wp_send_json_error(['message' => __('You are not allowed to clear all history logs.', 'user-history')]);
        }

        $result = $plugin->clear_all_history_logs();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }

        wp_send_json_success(
            [
                'message' => __('All history logs were cleared. A maintenance note was written.', 'user-history'),
                'deleted' => (int) $result,
            ]
        );
    }

    /**
     * @param mixed $value Stored or submitted flag.
     * @return bool
     */
    private function option_flag_is_enabled($value) {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (int) $value === 1;
        }

        $normalized = strtolower(trim((string) $value));

        return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
    }
}
