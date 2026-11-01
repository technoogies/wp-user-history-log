<?php

/**
 * Optional registration username rules for User History.
 *
 * Ported from upstream username-restrictions. The feature stays off until
 * enabled. Existing accounts are never renamed. Restrict Usernames settings
 * can be imported once; the switch stays off.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Username_Restrictions {

    const MENU_SLUG = 'user-history-username-restrictions';
    const OPTION_GROUP = 'user_history_username_settings';
    const OPTION_ENABLED = 'user_history_username_restrictions_enabled';
    const OPTION_DISALLOW_SPACES = 'user_history_username_disallow_spaces';
    const OPTION_MIN_LENGTH = 'user_history_username_min_length';
    const OPTION_MAX_LENGTH = 'user_history_username_max_length';
    const OPTION_BLOCKLIST = 'user_history_username_blocklist';
    const OPTION_PARTIAL_BLOCKLIST = 'user_history_username_partial_blocklist';
    const OPTION_REQUIRED_PARTIALS = 'user_history_username_required_partials';
    const OPTION_ERROR_MESSAGE = 'user_history_username_error_message';
    const OPTION_APPLY_TO_ADMINS = 'user_history_username_apply_to_admins';
    const MIGRATED_OPTION = 'user_history_migrated_restrict_usernames';
    const TEST_ACTION = 'user_history_test_usernames';
    const TEST_NONCE = 'user_history_test_usernames';

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * @var User_History
     */
    private $plugin;

    /**
     * Whether the last validate_username() call was rejected by these rules.
     *
     * @var bool
     */
    private $got_restricted = false;

    /**
     * @param User_History $plugin Main plugin instance.
     * @return self
     */
    public static function get_instance($plugin = null) {
        if (null === self::$instance) {
            if (!$plugin instanceof User_History) {
                $plugin = User_History::get_instance();
            }
            self::$instance = new self($plugin);
        }

        return self::$instance;
    }

    /**
     * @param User_History $plugin Main plugin instance.
     */
    private function __construct($plugin) {
        $this->plugin = $plugin;

        add_filter('validate_username', [$this, 'filter_validate_username'], 10, 2);
        add_filter('illegal_user_logins', [$this, 'filter_illegal_user_logins']);
        add_filter('registration_errors', [$this, 'filter_registration_errors']);
        add_action('user_profile_update_errors', [$this, 'filter_profile_update_errors'], 10, 2);
        add_filter('wpmu_validate_user_signup', [$this, 'filter_signup_result']);
        add_filter('bp_core_validate_user_signup', [$this, 'filter_signup_result']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('option_page_capability_' . self::OPTION_GROUP, [$this, 'settings_capability']);
        add_action('wp_ajax_' . self::TEST_ACTION, [$this, 'ajax_test_usernames']);
    }

    /**
     * @return string
     */
    public function settings_capability() {
        return User_History::CLEAR_HISTORY_CAPABILITY;
    }

    /**
     * @return bool
     */
    public function is_enabled() {
        return $this->option_flag_is_enabled(get_option(self::OPTION_ENABLED, '0'));
    }

    /**
     * Current settings as an array.
     *
     * @return array<string,mixed>
     */
    public function get_settings() {
        return [
            'disallow_spaces'   => $this->option_flag_is_enabled(get_option(self::OPTION_DISALLOW_SPACES, '0')),
            'min_length'        => (int) get_option(self::OPTION_MIN_LENGTH, 0),
            'max_length'        => (int) get_option(self::OPTION_MAX_LENGTH, 0),
            'blocklist'         => self::parse_list(get_option(self::OPTION_BLOCKLIST, '')),
            'partial_blocklist' => self::parse_list(get_option(self::OPTION_PARTIAL_BLOCKLIST, '')),
            'required_partials' => self::parse_list(get_option(self::OPTION_REQUIRED_PARTIALS, '')),
            'apply_to_admins'   => $this->option_flag_is_enabled(get_option(self::OPTION_APPLY_TO_ADMINS, '0')),
        ];
    }

    /**
     * Split a newline-separated option value into a clean lowercase array.
     *
     * @param mixed $value Stored option value.
     * @return string[]
     */
    public static function parse_list($value) {
        if (!is_string($value) || $value === '') {
            return [];
        }

        $items = [];
        foreach (preg_split('/\R/', $value) as $line) {
            $line = trim($line);
            if ($line !== '') {
                $items[] = mb_strtolower($line);
            }
        }

        return array_values(array_unique($items));
    }

    /**
     * @return string
     */
    public function get_error_message() {
        $message = get_option(self::OPTION_ERROR_MESSAGE, '');
        if (!is_string($message) || $message === '') {
            $message = __('This username is not allowed. Please choose another.', 'user-history');
        }

        return apply_filters('user_history_username_restricted_message', $message);
    }

    /**
     * Evaluate a username against the configured rules.
     *
     * Ignores request context so the Test Usernames tool can call it directly.
     *
     * @param string $username Username to check.
     * @return string|null
     */
    public function get_restriction_reason($username) {
        $settings = $this->get_settings();
        $username = mb_strtolower(trim((string) $username));
        $reason = null;

        if ($settings['disallow_spaces'] && strpos($username, ' ') !== false) {
            $reason = __('contains spaces', 'user-history');
        } elseif ($settings['min_length'] > 0 && mb_strlen($username) < $settings['min_length']) {
            $reason = sprintf(
                _n('is shorter than %d character', 'is shorter than %d characters', $settings['min_length'], 'user-history'),
                $settings['min_length']
            );
        } elseif ($settings['max_length'] > 0 && mb_strlen($username) > $settings['max_length']) {
            $reason = sprintf(
                _n('is longer than %d character', 'is longer than %d characters', $settings['max_length'], 'user-history'),
                $settings['max_length']
            );
        } elseif (in_array($username, $settings['blocklist'], true)) {
            $reason = __('is on the blocked usernames list', 'user-history');
        } else {
            foreach ($settings['partial_blocklist'] as $partial) {
                if (strpos($username, $partial) !== false) {
                    $reason = sprintf(__('contains the blocked text "%s"', 'user-history'), $partial);
                    break;
                }
            }

            if ($reason === null && !empty($settings['required_partials']) && !$this->matches_required_partial($username, $settings['required_partials'])) {
                $reason = __('does not include any of the required text fragments', 'user-history');
            }
        }

        $valid = ($reason === null);

        $filtered = (bool) apply_filters('user_history_validate_username', $valid, $username, $settings);

        if ($filtered !== $valid) {
            $reason = $filtered ? null : __('was rejected by a custom rule', 'user-history');
        }

        return $reason;
    }

    /**
     * Whether a username is restricted in the current request context.
     *
     * @param string $username Username to check.
     * @return bool
     */
    public function is_restricted($username) {
        if ($this->should_skip()) {
            return false;
        }

        return $this->get_restriction_reason($username) !== null;
    }

    /**
     * Error for Change Username when apply-to-admins is on. Null otherwise.
     *
     * @param string $username Proposed username.
     * @return string|null
     */
    public function get_admin_username_error($username) {
        if (!$this->is_enabled()) {
            return null;
        }

        $settings = $this->get_settings();
        if (!$settings['apply_to_admins']) {
            return null;
        }

        if ($this->get_restriction_reason($username) === null) {
            return null;
        }

        return $this->get_error_message();
    }

    /**
     * Evaluate comma-separated sample usernames for the Test Usernames tool.
     *
     * @param string $raw Comma-separated usernames.
     * @return array{enabled:bool,results:array<int,array{username:string,valid:bool,reason:string}>}
     */
    public function evaluate_usernames($raw) {
        $usernames = array_filter(array_map('trim', explode(',', (string) $raw)), 'strlen');
        $usernames = array_slice(array_unique($usernames), 0, 50);

        $results = [];
        foreach ($usernames as $username) {
            $reason = $this->get_restriction_reason($username);
            $results[] = [
                'username' => $username,
                'valid'    => $reason === null,
                'reason'   => $reason === null ? '' : $reason,
            ];
        }

        return [
            'enabled' => $this->is_enabled(),
            'results' => $results,
        ];
    }

    /**
     * One-time copy of Restrict Usernames options. Never auto-enables.
     */
    public function maybe_import_restrict_usernames_settings() {
        if (get_option(self::MIGRATED_OPTION)) {
            return;
        }

        update_option(self::MIGRATED_OPTION, '1');

        $old = get_option('c2c_restrict_usernames');
        if (!is_array($old) || empty($old)) {
            return;
        }

        $to_lines = static function ($value) {
            if (is_string($value)) {
                $value = preg_split('/\R/', $value);
            }
            if (!is_array($value)) {
                return '';
            }
            $value = array_filter(array_map('trim', array_map('strval', $value)), 'strlen');

            return implode("\n", array_values(array_unique(array_map('mb_strtolower', $value))));
        };

        $map = [
            'disallow_spaces'    => [self::OPTION_DISALLOW_SPACES, static function ($value) {
                return $value ? '1' : '0';
            }],
            'min_length'         => [self::OPTION_MIN_LENGTH, static function ($value) {
                return min(60, max(0, (int) $value));
            }],
            'max_length'         => [self::OPTION_MAX_LENGTH, static function ($value) {
                return min(60, max(0, (int) $value));
            }],
            'usernames'          => [self::OPTION_BLOCKLIST, $to_lines],
            'partial_usernames'  => [self::OPTION_PARTIAL_BLOCKLIST, $to_lines],
            'required_partials'  => [self::OPTION_REQUIRED_PARTIALS, $to_lines],
        ];

        foreach ($map as $old_key => $config) {
            if (!isset($old[ $old_key ]) || get_option($config[0]) !== false) {
                continue;
            }

            update_option($config[0], $config[1]($old[ $old_key ]));
        }
    }

    /**
     * `validate_username` filter: reject restricted usernames.
     *
     * @param bool   $valid    WordPress's own assessment.
     * @param string $username Username being validated.
     * @return bool
     */
    public function filter_validate_username($valid, $username) {
        $this->got_restricted = false;

        if (!$valid) {
            return $valid;
        }

        if ($this->is_restricted($username)) {
            $this->got_restricted = true;
            return false;
        }

        return $valid;
    }

    /**
     * Add the exact blocklist. Names that already belong to an account stay out
     * so those users can still save their profile.
     *
     * @param array<int,string> $illegal_user_logins Existing list.
     * @return array<int,string>
     */
    public function filter_illegal_user_logins($illegal_user_logins) {
        if ($this->should_skip()) {
            return $illegal_user_logins;
        }

        $settings = $this->get_settings();
        if (empty($settings['blocklist'])) {
            return $illegal_user_logins;
        }

        foreach ($settings['blocklist'] as $login) {
            if (!username_exists($login)) {
                $illegal_user_logins[] = $login;
            }
        }

        return array_values(array_unique((array) $illegal_user_logins));
    }

    /**
     * @param WP_Error $errors Registration errors.
     * @return WP_Error
     */
    public function filter_registration_errors($errors) {
        if ($this->got_restricted && is_wp_error($errors)) {
            $errors->remove('invalid_username');
            $errors->add(
                'invalid_username',
                '<strong>' . __('Error:', 'user-history') . '</strong> ' . esc_html($this->get_error_message())
            );
        }

        return $errors;
    }

    /**
     * @param WP_Error $errors Errors object.
     * @param bool     $update Whether this is an existing user update.
     */
    public function filter_profile_update_errors($errors, $update) {
        if ($update || !$this->got_restricted || !is_wp_error($errors)) {
            return;
        }

        $errors->remove('user_login');
        $errors->add(
            'user_login',
            '<strong>' . __('Error:', 'user-history') . '</strong> ' . esc_html($this->get_error_message()),
            ['form-field' => 'user_login']
        );
    }

    /**
     * @param array<string,mixed> $result Signup result.
     * @return array<string,mixed>
     */
    public function filter_signup_result($result) {
        if (!is_array($result) || empty($result['user_name']) || !isset($result['errors']) || !is_wp_error($result['errors'])) {
            return $result;
        }

        if (!$this->is_restricted($result['user_name'])) {
            return $result;
        }

        $result['errors']->remove('user_name');
        $result['errors']->add('user_name', $this->get_error_message());

        return $result;
    }

    /**
     * Register Settings API fields. Restriction default stays off.
     */
    public function register_settings() {
        register_setting(
            self::OPTION_GROUP,
            self::OPTION_ENABLED,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_enabled'],
                'default'           => '0',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_DISALLOW_SPACES,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_checkbox'],
                'default'           => '0',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_MIN_LENGTH,
            [
                'type'              => 'integer',
                'sanitize_callback' => [$this, 'sanitize_username_length'],
                'default'           => 0,
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_MAX_LENGTH,
            [
                'type'              => 'integer',
                'sanitize_callback' => [$this, 'sanitize_username_length'],
                'default'           => 0,
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_BLOCKLIST,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_username_list'],
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_PARTIAL_BLOCKLIST,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_username_list'],
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_REQUIRED_PARTIALS,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_username_list'],
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_ERROR_MESSAGE,
            [
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_APPLY_TO_ADMINS,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_checkbox'],
                'default'           => '0',
                'show_in_rest'      => false,
            ]
        );

        add_settings_section(
            'user_history_username_section',
            __('Username Restrictions', 'user-history'),
            [$this, 'render_section_description'],
            self::MENU_SLUG
        );

        add_settings_field(self::OPTION_ENABLED, __('Restrict Usernames', 'user-history'), [$this, 'render_enabled_field'], self::MENU_SLUG, 'user_history_username_section');
        add_settings_field(self::OPTION_DISALLOW_SPACES, __('Spaces', 'user-history'), [$this, 'render_disallow_spaces_field'], self::MENU_SLUG, 'user_history_username_section');
        add_settings_field('user_history_username_length', __('Length', 'user-history'), [$this, 'render_length_field'], self::MENU_SLUG, 'user_history_username_section');
        add_settings_field(self::OPTION_BLOCKLIST, __('Blocked Usernames', 'user-history'), [$this, 'render_blocklist_field'], self::MENU_SLUG, 'user_history_username_section');
        add_settings_field(self::OPTION_PARTIAL_BLOCKLIST, __('Blocked Text', 'user-history'), [$this, 'render_partial_blocklist_field'], self::MENU_SLUG, 'user_history_username_section');
        add_settings_field(self::OPTION_REQUIRED_PARTIALS, __('Required Text', 'user-history'), [$this, 'render_required_partials_field'], self::MENU_SLUG, 'user_history_username_section');
        add_settings_field(self::OPTION_ERROR_MESSAGE, __('Error Message', 'user-history'), [$this, 'render_error_message_field'], self::MENU_SLUG, 'user_history_username_section');

        add_settings_section(
            'user_history_username_advanced_section',
            __('Advanced', 'user-history'),
            '__return_null',
            self::MENU_SLUG
        );

        add_settings_field(self::OPTION_APPLY_TO_ADMINS, __('Administrators', 'user-history'), [$this, 'render_apply_to_admins_field'], self::MENU_SLUG, 'user_history_username_advanced_section');
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string
     */
    public function sanitize_enabled($value) {
        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string
     */
    public function sanitize_checkbox($value) {
        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Input value.
     * @return int
     */
    public function sanitize_username_length($value) {
        return min(60, max(0, (int) $value));
    }

    /**
     * @param mixed $value Raw textarea value.
     * @return string
     */
    public function sanitize_username_list($value) {
        if (!is_string($value) || $value === '') {
            return '';
        }

        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
        $clean = [];
        foreach (preg_split('/\R/', $value) as $line) {
            $line = trim(wp_strip_all_tags($line));
            if ($line !== '') {
                $clean[] = mb_strtolower($line);
            }
        }

        return implode("\n", array_values(array_unique($clean)));
    }

    /**
     * Settings intro.
     */
    public function render_section_description() {
        echo '<p>' . esc_html__('Optional rules for new registrations only. Existing accounts are never renamed. Matching is case-insensitive.', 'user-history') . '</p>';
    }

    /**
     * Enable checkbox. Off by default.
     */
    public function render_enabled_field() {
        $option_on = $this->is_enabled();

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_ENABLED); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION_ENABLED); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Apply the rules below to usernames chosen during registration', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Off by default. Works with the standard WordPress registration form, Multisite signup, BuddyPress, WooCommerce, and most plugins that validate usernames through WordPress. An old Restrict Usernames install will not turn this on for you.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Disallow-spaces checkbox.
     */
    public function render_disallow_spaces_field() {
        $option_on = $this->option_flag_is_enabled(get_option(self::OPTION_DISALLOW_SPACES, '0'));

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_DISALLOW_SPACES); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION_DISALLOW_SPACES); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Do not allow spaces in usernames', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('WordPress (single-site) allows spaces in usernames by default.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Min/max length fields.
     */
    public function render_length_field() {
        $min = (int) get_option(self::OPTION_MIN_LENGTH, 0);
        $max = (int) get_option(self::OPTION_MAX_LENGTH, 0);

        ?>
        <label>
            <?php esc_html_e('Minimum', 'user-history'); ?>
            <input type="number" name="<?php echo esc_attr(self::OPTION_MIN_LENGTH); ?>" min="0" max="60" step="1" class="small-text" value="<?php echo esc_attr((string) $min); ?>" />
        </label>
        &nbsp;&nbsp;
        <label>
            <?php esc_html_e('Maximum', 'user-history'); ?>
            <input type="number" name="<?php echo esc_attr(self::OPTION_MAX_LENGTH); ?>" min="0" max="60" step="1" class="small-text" value="<?php echo esc_attr((string) $max); ?>" />
        </label>
        <?php esc_html_e('characters', 'user-history'); ?>
        <p class="description">
            <?php esc_html_e('Set to 0 for no limit. WordPress itself never allows more than 60 characters.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Exact blocklist.
     */
    public function render_blocklist_field() {
        $value = get_option(self::OPTION_BLOCKLIST, '');

        ?>
        <textarea name="<?php echo esc_attr(self::OPTION_BLOCKLIST); ?>" class="large-text code" rows="5" placeholder="<?php echo esc_attr("admin\nsupport\nwebmaster"); ?>"><?php echo esc_textarea(is_string($value) ? $value : ''); ?></textarea>
        <p class="description">
            <?php esc_html_e('One username per line. These exact usernames cannot be registered.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Partial blocklist.
     */
    public function render_partial_blocklist_field() {
        $value = get_option(self::OPTION_PARTIAL_BLOCKLIST, '');

        ?>
        <textarea name="<?php echo esc_attr(self::OPTION_PARTIAL_BLOCKLIST); ?>" class="large-text code" rows="5" placeholder="<?php echo esc_attr("support\nadmin_"); ?>"><?php echo esc_textarea(is_string($value) ? $value : ''); ?></textarea>
        <p class="description">
            <?php esc_html_e('One entry per line. Usernames containing any of these fragments anywhere are rejected.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Required partials.
     */
    public function render_required_partials_field() {
        $value = get_option(self::OPTION_REQUIRED_PARTIALS, '');

        ?>
        <textarea name="<?php echo esc_attr(self::OPTION_REQUIRED_PARTIALS); ?>" class="large-text code" rows="5" placeholder="<?php echo esc_attr("^member_\n_team^"); ?>"><?php echo esc_textarea(is_string($value) ? $value : ''); ?></textarea>
        <p class="description">
            <?php esc_html_e('One entry per line. When set, a username must contain at least one of these fragments.', 'user-history'); ?>
            <?php
            echo ' ';
            echo wp_kses(
                sprintf(
                    __('Prefix with %1$s to require it at the start (%2$s) or suffix with %1$s to require it at the end (%3$s). Leave empty to not require anything.', 'user-history'),
                    '<code>^</code>',
                    '<code>^member_</code>',
                    '<code>_team^</code>'
                ),
                ['code' => []]
            );
            ?>
        </p>
        <?php
    }

    /**
     * Custom error message.
     */
    public function render_error_message_field() {
        $value = get_option(self::OPTION_ERROR_MESSAGE, '');

        ?>
        <input type="text" name="<?php echo esc_attr(self::OPTION_ERROR_MESSAGE); ?>" class="regular-text" value="<?php echo esc_attr(is_string($value) ? $value : ''); ?>" placeholder="<?php echo esc_attr__('This username is not allowed. Please choose another.', 'user-history'); ?>" />
        <p class="description">
            <?php esc_html_e('Shown to visitors who pick a restricted username. Leave empty for the default message.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Apply-to-admins checkbox. Default off.
     */
    public function render_apply_to_admins_field() {
        $option_on = $this->option_flag_is_enabled(get_option(self::OPTION_APPLY_TO_ADMINS, '0'));

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_APPLY_TO_ADMINS); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION_APPLY_TO_ADMINS); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Also apply the rules to usernames chosen by administrators', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Off by default. Users who can create accounts bypass these rules on Users → Add New and Change Username. Enable this to enforce the rules there too. WP-CLI is always exempt. Existing accounts are never renamed.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Render the Username Restrictions screen.
     */
    public function render_settings_page() {
        if (!current_user_can($this->settings_capability())) {
            wp_die(esc_html__('You are not allowed to access User History settings.', 'user-history'));
        }

        ?>
        <div class="wrap user-history-settings">
            <h1><?php esc_html_e('Username Restrictions', 'user-history'); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields(self::OPTION_GROUP);
                do_settings_sections(self::MENU_SLUG);
                submit_button();
                ?>
            </form>
            <?php $this->render_username_test_tool(); ?>
        </div>
        <?php
    }

    /**
     * AJAX: Test Usernames tool. Authenticated only.
     */
    public function ajax_test_usernames() {
        check_ajax_referer(self::TEST_NONCE, 'nonce');

        if (!current_user_can($this->settings_capability())) {
            wp_send_json_error(['message' => __('You are not allowed to test username rules.', 'user-history')]);
        }

        $raw = isset($_POST['usernames']) ? sanitize_text_field(wp_unslash($_POST['usernames'])) : '';

        wp_send_json_success($this->evaluate_usernames($raw));
    }

    /**
     * Whether checks should be skipped in the current request.
     *
     * @return bool
     */
    public function should_skip() {
        if (!$this->is_enabled()) {
            return true;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        $settings = $this->get_settings();
        if (!$settings['apply_to_admins'] && is_user_logged_in() && current_user_can('create_users')) {
            return true;
        }

        return false;
    }

    /**
     * @param string   $username Lowercased username.
     * @param string[] $partials Required partials.
     * @return bool
     */
    private function matches_required_partial($username, $partials) {
        foreach ($partials as $partial) {
            if ($partial === '' || $partial === '^') {
                continue;
            }

            if ($partial[0] === '^') {
                $needle = substr($partial, 1);
                if ($needle !== '' && strpos($username, $needle) === 0) {
                    return true;
                }
            } elseif (substr($partial, -1) === '^') {
                $needle = substr($partial, 0, -1);
                if ($needle !== '' && substr($username, -strlen($needle)) === $needle) {
                    return true;
                }
            } elseif (strpos($username, $partial) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Test Usernames tool. Uses text nodes, not innerHTML.
     */
    private function render_username_test_tool() {
        ?>
        <hr />
        <h2><?php esc_html_e('Test Usernames', 'user-history'); ?></h2>
        <p class="description">
            <?php esc_html_e('Check how the saved rules above evaluate sample usernames. Separate multiple usernames with commas. Save your changes first — the test uses the stored settings.', 'user-history'); ?>
        </p>
        <p>
            <input type="text" id="user-history-test-usernames" class="regular-text" placeholder="admin, john_doe, member_jane" />
            <button type="button" class="button" id="user-history-test-usernames-btn">
                <?php esc_html_e('Test', 'user-history'); ?>
            </button>
        </p>
        <ul id="user-history-test-usernames-results" hidden></ul>
        <script>
        (function () {
            var input = document.getElementById('user-history-test-usernames');
            var btn = document.getElementById('user-history-test-usernames-btn');
            var list = document.getElementById('user-history-test-usernames-results');
            if (!input || !btn || !list) {
                return;
            }

            function clearList() {
                while (list.firstChild) {
                    list.removeChild(list.firstChild);
                }
            }

            function run() {
                var value = input.value.trim();
                if (!value) {
                    return;
                }

                btn.disabled = true;

                var xhr = new XMLHttpRequest();
                xhr.open('POST', <?php echo wp_json_encode(admin_url('admin-ajax.php')); ?>);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.onload = function () {
                    btn.disabled = false;
                    clearList();
                    var res;
                    try {
                        res = JSON.parse(xhr.responseText);
                    } catch (e) {
                        res = null;
                    }

                    if (!res || !res.success) {
                        var errorItem = document.createElement('li');
                        errorItem.appendChild(document.createTextNode(
                            (res && res.data && res.data.message) || <?php echo wp_json_encode(__('Something went wrong.', 'user-history')); ?>
                        ));
                        list.appendChild(errorItem);
                    } else {
                        res.data.results.forEach(function (row) {
                            var item = document.createElement('li');
                            var name = document.createElement('code');
                            name.appendChild(document.createTextNode(row.username));
                            var status = document.createElement('strong');
                            status.appendChild(document.createTextNode(
                                row.valid
                                    ? <?php echo wp_json_encode(__('allowed', 'user-history')); ?>
                                    : <?php echo wp_json_encode(__('restricted', 'user-history')); ?>
                            ));
                            item.appendChild(name);
                            item.appendChild(document.createTextNode(' — '));
                            item.appendChild(status);
                            if (!row.valid && row.reason) {
                                item.appendChild(document.createTextNode(' (' + row.reason + ')'));
                            }
                            list.appendChild(item);
                        });
                        if (!res.data.enabled) {
                            var note = document.createElement('li');
                            note.className = 'description';
                            note.appendChild(document.createTextNode(
                                <?php echo wp_json_encode(__('Note: username restrictions are currently disabled, so these rules are not being enforced.', 'user-history')); ?>
                            ));
                            list.appendChild(note);
                        }
                    }
                    list.hidden = false;
                };
                xhr.send(
                    'action=<?php echo esc_js(self::TEST_ACTION); ?>' +
                    '&nonce=<?php echo esc_js(wp_create_nonce(self::TEST_NONCE)); ?>' +
                    '&usernames=' + encodeURIComponent(value)
                );
            }

            btn.addEventListener('click', run);
            input.addEventListener('keydown', function (event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    run();
                }
            });
        })();
        </script>
        <?php
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
