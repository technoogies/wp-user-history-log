<?php

/**
 * Optional wp-admin restriction for User History.
 *
 * Ported from upstream dashboard-access enforcement. The feature stays off
 * until an operator with manage_user_history and manage_options enables it.
 * Remove Dashboard Access settings can be imported once; the switch stays off.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Dashboard_Access {

    const MENU_SLUG = 'user-history-dashboard-access';
    const OPTION_GROUP = 'user_history_dashboard_settings';
    const OPTION_ENABLED = 'user_history_dashboard_access_enabled';
    const OPTION_SWITCH = 'user_history_dashboard_access_switch';
    const OPTION_CAP = 'user_history_dashboard_access_cap';
    const OPTION_REDIRECT = 'user_history_dashboard_redirect_url';
    const OPTION_PROFILE = 'user_history_dashboard_enable_profile';
    const OPTION_LOGIN_MESSAGE = 'user_history_dashboard_login_message';
    const OPTION_LOCK_AJAX = 'user_history_dashboard_lock_ajax';
    const OPTION_ALLOWLIST = 'user_history_dashboard_url_allowlist';
    const MIGRATED_OPTION = 'user_history_migrated_rda';

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * @var User_History
     */
    private $plugin;

    /**
     * Temporarily allow sanitizers to write imported RDA values without a dual-cap operator.
     *
     * @var bool
     */
    private $importing_rda = false;

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

        add_action('init', [$this, 'maybe_restrict_access']);
        add_filter('login_message', [$this, 'output_login_message']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('option_page_capability_' . self::OPTION_GROUP, [$this, 'settings_capability']);
    }

    /**
     * Capability that can open the Dashboard Access screen.
     *
     * @return string
     */
    public function settings_capability() {
        return User_History::CLEAR_HISTORY_CAPABILITY;
    }

    /**
     * Enabling or changing dashboard restriction settings needs both caps.
     *
     * @return bool
     */
    public function current_operator_can_enable() {
        return current_user_can(User_History::CLEAR_HISTORY_CAPABILITY)
            && current_user_can('manage_options');
    }

    /**
     * Default capabilities for the role-based access presets.
     *
     * @return array<string,string>
     */
    public static function get_default_role_caps() {
        return apply_filters(
            'user_history_default_caps_for_role',
            [
                'admin'  => 'manage_options',
                'editor' => 'edit_others_posts',
                'author' => 'publish_posts',
            ]
        );
    }

    /**
     * Whether the dashboard access restriction is enabled.
     *
     * @return bool
     */
    public function is_enabled() {
        return $this->option_flag_is_enabled(get_option(self::OPTION_ENABLED, '0'));
    }

    /**
     * Resolve the capability required for dashboard access.
     *
     * @return string
     */
    public function get_capability() {
        $switch = get_option(self::OPTION_SWITCH, 'manage_options');

        if ($switch === 'capability') {
            $capability = get_option(self::OPTION_CAP, 'manage_options');
        } else {
            $capability = $switch;
        }

        if (!$capability) {
            $capability = 'manage_options';
        }

        return apply_filters('user_history_dashboard_access_capability', $capability);
    }

    /**
     * Whether the current user should be locked out of wp-admin.
     *
     * @return bool
     */
    public function should_restrict_current_user() {
        if (!$this->is_enabled()) {
            return false;
        }

        return !current_user_can($this->get_capability());
    }

    /**
     * Whether AJAX should honor the dashboard restriction.
     *
     * Does not read DOING_AJAX so tests can call it directly.
     *
     * @return bool
     */
    public function should_restrict_ajax_request() {
        if (!$this->should_restrict_current_user()) {
            return false;
        }

        $default_strict = $this->option_flag_is_enabled(get_option(self::OPTION_LOCK_AJAX, '0'));

        return (bool) apply_filters('user_history_strict_ajax', $default_strict, $this->get_capability());
    }

    /**
     * Whether the current admin request should be redirected.
     *
     * @param string|null $pagenow Optional pagenow override for tests.
     * @return bool
     */
    public function should_redirect_current_request($pagenow = null) {
        if (!$this->should_restrict_current_user()) {
            return false;
        }

        if ($pagenow === null) {
            global $pagenow;
        }

        if ($this->is_allowed_page($pagenow)) {
            return false;
        }

        $is_profile = ($pagenow === 'profile.php')
            && (!defined('IS_PROFILE_PAGE') || IS_PROFILE_PAGE);

        if ($is_profile && $this->is_profile_access_enabled()) {
            return false;
        }

        return true;
    }

    /**
     * Whether a request matches the configured allowlist.
     *
     * Separate from the registered-page check used at runtime for admin.php.
     *
     * @param string               $pagenow Current admin script.
     * @param array<string,mixed>  $query   GET parameters.
     * @return bool
     */
    public function request_matches_allowlist($pagenow, $query = []) {
        $allowlist = $this->get_allowlist();

        if (!is_string($pagenow) || $pagenow === '' || !array_key_exists($pagenow, $allowlist)) {
            return false;
        }

        if (empty($allowlist[ $pagenow ])) {
            return true;
        }

        foreach ($allowlist[ $pagenow ] as $allowed_params_set) {
            if ($this->params_set_matches($allowed_params_set, $query)) {
                return true;
            }
        }

        return false;
    }

    /**
     * One-time copy of Remove Dashboard Access options. Never auto-enables.
     */
    public function maybe_import_rda_settings() {
        if (get_option(self::MIGRATED_OPTION)) {
            return;
        }

        update_option(self::MIGRATED_OPTION, '1');

        if (get_option('rda_access_switch') === false) {
            return;
        }

        $map = [
            'rda_access_switch'  => self::OPTION_SWITCH,
            'rda_access_cap'     => self::OPTION_CAP,
            'rda_redirect_url'   => self::OPTION_REDIRECT,
            'rda_login_message'  => self::OPTION_LOGIN_MESSAGE,
            'rda_url_allowlist'  => self::OPTION_ALLOWLIST,
        ];

        $this->importing_rda = true;

        try {
            foreach ($map as $old_key => $new_key) {
                $value = get_option($old_key);
                if ($value === false || get_option($new_key) !== false) {
                    continue;
                }

                if ($new_key === self::OPTION_SWITCH) {
                    $value = $this->sanitize_access_switch($value);
                } elseif ($new_key === self::OPTION_CAP) {
                    $value = $this->sanitize_access_cap($value);
                } elseif ($new_key === self::OPTION_REDIRECT) {
                    $value = $this->sanitize_redirect_url($value);
                } elseif ($new_key === self::OPTION_LOGIN_MESSAGE) {
                    $value = sanitize_text_field((string) $value);
                } elseif ($new_key === self::OPTION_ALLOWLIST) {
                    $value = $this->sanitize_url_allowlist($value);
                }

                update_option($new_key, $value);
            }
        } finally {
            $this->importing_rda = false;
        }

        if (get_option(self::OPTION_PROFILE) === false) {
            update_option(
                self::OPTION_PROFILE,
                $this->option_flag_is_enabled(get_option('rda_enable_profile', 1)) ? '1' : '0'
            );
        }

        if (get_option(self::OPTION_LOCK_AJAX) === false) {
            update_option(
                self::OPTION_LOCK_AJAX,
                $this->option_flag_is_enabled(get_option('rda_lock_ajax', 0)) ? '1' : '0'
            );
        }
    }

    /**
     * Determine if the current user is allowed to access the dashboard.
     */
    public function maybe_restrict_access() {
        if (!$this->is_enabled()) {
            return;
        }

        if ($this->is_doing_ajax() && !$this->should_restrict_ajax_request()) {
            return;
        }

        if ($this->is_allowed_page()) {
            return;
        }

        if (!$this->should_restrict_current_user()) {
            return;
        }

        $this->lock_it_up();
    }

    /**
     * Hide admin menus other than profile.php.
     */
    public function hide_menus() {
        global $menu;

        if (!$menu || !is_array($menu)) {
            return;
        }

        foreach ($menu as $values) {
            if (isset($values[2]) && $values[2] !== 'profile.php') {
                remove_menu_page($values[2]);
            }
        }
    }

    /**
     * Redirect disallowed users to the configured URL.
     */
    public function dashboard_redirect() {
        if (!$this->should_redirect_current_request()) {
            return;
        }

        $redirect_url = $this->get_redirect_url();
        $redirect_host = wp_parse_url($redirect_url, PHP_URL_HOST);
        if ($redirect_host) {
            $filter = static function ($hosts) use ($redirect_host) {
                $hosts[] = $redirect_host;
                return $hosts;
            };
            add_filter('allowed_redirect_hosts', $filter);
            wp_safe_redirect($redirect_url);
            remove_filter('allowed_redirect_hosts', $filter);
        } else {
            wp_safe_redirect($redirect_url);
        }
        exit;
    }

    /**
     * Hide Toolbar items for disallowed users (front and back-end).
     *
     * @param WP_Admin_Bar $wp_admin_bar Admin bar instance.
     */
    public function hide_toolbar_items($wp_admin_bar) {
        $edit_profile = !$this->is_profile_access_enabled() ? 'edit-profile' : '';

        if (is_admin()) {
            $ids = ['about', 'comments', 'new-content', $edit_profile];
            $nodes = apply_filters('user_history_toolbar_nodes', $ids);
        } else {
            $ids = ['about', 'dashboard', 'comments', 'new-content', 'edit', $edit_profile];
            $nodes = apply_filters('user_history_frontend_toolbar_nodes', $ids);
        }

        foreach ($nodes as $id) {
            if ($id !== '') {
                $wp_admin_bar->remove_menu($id);
            }
        }
    }

    /**
     * Output the configured message above the login form.
     *
     * @param string $message Login message HTML.
     * @return string
     */
    public function output_login_message($message) {
        if (!$this->is_enabled()) {
            return $message;
        }

        $login_message = get_option(self::OPTION_LOGIN_MESSAGE, '');

        if (is_string($login_message) && $login_message !== '') {
            $message .= '<p class="message">' . esc_html($login_message) . '</p>';
        }

        return $message;
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
            self::OPTION_SWITCH,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_access_switch'],
                'default'           => 'manage_options',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_CAP,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_access_cap'],
                'default'           => 'manage_options',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_REDIRECT,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_redirect_url'],
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_PROFILE,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_enable_profile'],
                'default'           => '1',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_LOGIN_MESSAGE,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_login_message'],
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_LOCK_AJAX,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_lock_ajax'],
                'default'           => '0',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            self::OPTION_GROUP,
            self::OPTION_ALLOWLIST,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_url_allowlist'],
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );

        add_settings_section(
            'user_history_dashboard_section',
            __('Dashboard Access Controls', 'user-history'),
            [$this, 'render_section_description'],
            self::MENU_SLUG
        );

        add_settings_field(
            self::OPTION_ENABLED,
            __('Restrict Dashboard Access', 'user-history'),
            [$this, 'render_enabled_field'],
            self::MENU_SLUG,
            'user_history_dashboard_section'
        );

        add_settings_field(
            self::OPTION_SWITCH,
            __('Dashboard User Access', 'user-history'),
            [$this, 'render_access_switch_field'],
            self::MENU_SLUG,
            'user_history_dashboard_section'
        );

        add_settings_field(
            self::OPTION_REDIRECT,
            __('Redirect URL', 'user-history'),
            [$this, 'render_redirect_url_field'],
            self::MENU_SLUG,
            'user_history_dashboard_section'
        );

        add_settings_field(
            self::OPTION_PROFILE,
            __('User Profile Access', 'user-history'),
            [$this, 'render_enable_profile_field'],
            self::MENU_SLUG,
            'user_history_dashboard_section'
        );

        add_settings_field(
            self::OPTION_LOGIN_MESSAGE,
            __('Login Message', 'user-history'),
            [$this, 'render_login_message_field'],
            self::MENU_SLUG,
            'user_history_dashboard_section'
        );

        add_settings_section(
            'user_history_dashboard_advanced_section',
            __('Advanced', 'user-history'),
            [$this, 'render_advanced_section_description'],
            self::MENU_SLUG
        );

        add_settings_field(
            self::OPTION_LOCK_AJAX,
            __('AJAX Requests', 'user-history'),
            [$this, 'render_lock_ajax_field'],
            self::MENU_SLUG,
            'user_history_dashboard_advanced_section'
        );

        add_settings_field(
            self::OPTION_ALLOWLIST,
            __('Allowed URLs', 'user-history'),
            [$this, 'render_url_allowlist_field'],
            self::MENU_SLUG,
            'user_history_dashboard_advanced_section'
        );
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string '1' or '0'. Default stays off.
     */
    public function sanitize_enabled($value) {
        if (!$this->current_operator_can_enable()) {
            return $this->option_flag_is_enabled(get_option(self::OPTION_ENABLED, '0')) ? '1' : '0';
        }

        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Submitted value.
     * @return string
     */
    public function sanitize_access_switch($value) {
        if (!$this->can_write_dashboard_settings()) {
            $current = get_option(self::OPTION_SWITCH, 'manage_options');
            return is_string($current) && $current !== '' ? $current : 'manage_options';
        }

        $value = is_string($value) ? $value : '';
        $allowed = array_values(self::get_default_role_caps());
        $allowed[] = 'capability';

        if (in_array($value, $allowed, true)) {
            return $value;
        }

        return 'manage_options';
    }

    /**
     * @param mixed $value Submitted capability.
     * @return string
     */
    public function sanitize_access_cap($value) {
        if (!$this->can_write_dashboard_settings()) {
            $current = get_option(self::OPTION_CAP, 'manage_options');
            return is_string($current) && $current !== '' ? $current : 'manage_options';
        }

        $fallback = get_option(self::OPTION_SWITCH, 'manage_options');
        if ($fallback === 'capability' || !is_string($fallback) || $fallback === '') {
            $fallback = 'manage_options';
        }

        if (empty($value) || !is_string($value)) {
            return $fallback;
        }

        global $wp_roles;

        if (!isset($wp_roles) || !is_a($wp_roles, 'WP_Roles')) {
            return $fallback;
        }

        foreach ($wp_roles->role_objects as $role) {
            if (!empty($role->capabilities) && is_array($role->capabilities) && array_key_exists($value, $role->capabilities)) {
                return $value;
            }
        }

        return $fallback;
    }

    /**
     * @param mixed $value Submitted URL.
     * @return string
     */
    public function sanitize_redirect_url($value) {
        if (!$this->can_write_dashboard_settings()) {
            $current = get_option(self::OPTION_REDIRECT, '');
            return is_string($current) ? $current : '';
        }

        return empty($value) ? '' : esc_url_raw($value);
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string '1' or '0'
     */
    public function sanitize_enable_profile($value) {
        if (!$this->can_write_dashboard_settings()) {
            return $this->option_flag_is_enabled(get_option(self::OPTION_PROFILE, '1')) ? '1' : '0';
        }

        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Submitted message.
     * @return string
     */
    public function sanitize_login_message($value) {
        if (!$this->can_write_dashboard_settings()) {
            $current = get_option(self::OPTION_LOGIN_MESSAGE, '');
            return is_string($current) ? $current : '';
        }

        return sanitize_text_field((string) $value);
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string '1' or '0'
     */
    public function sanitize_lock_ajax($value) {
        if (!$this->can_write_dashboard_settings()) {
            return $this->option_flag_is_enabled(get_option(self::OPTION_LOCK_AJAX, '0')) ? '1' : '0';
        }

        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Raw textarea value.
     * @return string
     */
    public function sanitize_url_allowlist($value) {
        if (!$this->can_write_dashboard_settings()) {
            $current = get_option(self::OPTION_ALLOWLIST, '');
            return is_string($current) ? $current : '';
        }

        if (!is_string($value) || $value === '') {
            return '';
        }

        $lines = preg_split('/\R/', $value);
        $clean = [];

        foreach ((array) $lines as $line) {
            $line = preg_replace('/[\x00-\x08\x0E-\x1F\x7F]/', '', $line);
            $line = sanitize_text_field($line);
            if ($line === '') {
                continue;
            }

            $relative = $this->normalize_url_to_relative($line);
            if ($relative === null) {
                continue;
            }

            $parsed_path = wp_parse_url($relative, PHP_URL_PATH);
            $parsed_query = wp_parse_url($relative, PHP_URL_QUERY);
            if ($parsed_path && substr($parsed_path, -1) === '/' && empty($parsed_query)) {
                continue;
            }

            $clean[] = $relative;
        }

        $clean = array_values(array_unique($clean));

        return implode("\n", $clean);
    }

    /**
     * Settings intro.
     */
    public function render_section_description() {
        echo '<p>' . esc_html__('Optional. Leave this off to keep normal WordPress dashboard access. Turning it on can lock people out of /wp-admin.', 'user-history') . '</p>';
    }

    /**
     * Advanced section intro.
     */
    public function render_advanced_section_description() {
        echo '<p>' . esc_html__('AJAX stays unlocked by default so front-end forms keep working. Allowed URLs punch holes through the restriction.', 'user-history') . '</p>';
    }

    /**
     * Enable checkbox. Off by default; both caps required to turn it on.
     */
    public function render_enabled_field() {
        $option_on = $this->is_enabled();
        $can_enable = $this->current_operator_can_enable();

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_ENABLED); ?>" value="0" />
            <input
                type="checkbox"
                name="<?php echo esc_attr(self::OPTION_ENABLED); ?>"
                value="1"
                <?php checked($option_on); ?>
                <?php disabled(!$can_enable); ?>
            />
            <?php esc_html_e('Restrict /wp-admin to users with the capability chosen below', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Off by default. Enabling this requires manage_user_history and manage_options. An update or an old Remove Dashboard Access install will not turn this on for you.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Role preset radios plus an advanced capability dropdown.
     */
    public function render_access_switch_field() {
        $caps = self::get_default_role_caps();
        $switch = get_option(self::OPTION_SWITCH, 'manage_options');
        if (!is_string($switch) || $switch === '') {
            $switch = 'manage_options';
        }

        $choices = [
            $caps['admin']  => __('Administrators only', 'user-history'),
            $caps['editor'] => __('Editors and administrators', 'user-history'),
            $caps['author'] => __('Authors, editors, and administrators', 'user-history'),
            'capability'    => __('Advanced: choose a capability', 'user-history'),
        ];

        foreach ($choices as $value => $label) {
            ?>
            <label>
                <input
                    type="radio"
                    name="<?php echo esc_attr(self::OPTION_SWITCH); ?>"
                    value="<?php echo esc_attr($value); ?>"
                    <?php checked($switch, $value); ?>
                />
                <?php echo esc_html($label); ?>
            </label>
            <br />
            <?php
        }

        $this->render_caps_dropdown($switch === 'capability');
    }

    /**
     * Redirect URL field.
     */
    public function render_redirect_url_field() {
        $value = get_option(self::OPTION_REDIRECT, '');

        ?>
        <input
            type="url"
            class="regular-text"
            id="<?php echo esc_attr(self::OPTION_REDIRECT); ?>"
            name="<?php echo esc_attr(self::OPTION_REDIRECT); ?>"
            value="<?php echo esc_attr(is_string($value) ? $value : ''); ?>"
            placeholder="<?php echo esc_attr(home_url()); ?>"
        />
        <p class="description">
            <?php esc_html_e('Disallowed users are sent here. Leave empty to use the homepage.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Profile-access checkbox. Default on.
     */
    public function render_enable_profile_field() {
        $option_on = $this->is_profile_access_enabled();

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_PROFILE); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION_PROFILE); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Allow restricted users to open their own profile', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('On by default. Other admin screens still redirect.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Login message field.
     */
    public function render_login_message_field() {
        $value = get_option(self::OPTION_LOGIN_MESSAGE, '');

        ?>
        <input
            type="text"
            class="regular-text"
            id="<?php echo esc_attr(self::OPTION_LOGIN_MESSAGE); ?>"
            name="<?php echo esc_attr(self::OPTION_LOGIN_MESSAGE); ?>"
            value="<?php echo esc_attr(is_string($value) ? $value : ''); ?>"
        />
        <p class="description">
            <?php esc_html_e('Optional notice shown above the login form while the restriction is on.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * AJAX lock checkbox. Default off.
     */
    public function render_lock_ajax_field() {
        $option_on = $this->option_flag_is_enabled(get_option(self::OPTION_LOCK_AJAX, '0'));

        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_LOCK_AJAX); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION_LOCK_AJAX); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Also restrict admin-ajax.php', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Off by default. Leave this unchecked so individual AJAX handlers keep doing their own capability checks.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * URL allowlist textarea.
     */
    public function render_url_allowlist_field() {
        $value = get_option(self::OPTION_ALLOWLIST, '');

        ?>
        <textarea
            class="large-text code"
            rows="5"
            id="<?php echo esc_attr(self::OPTION_ALLOWLIST); ?>"
            name="<?php echo esc_attr(self::OPTION_ALLOWLIST); ?>"
            placeholder="<?php echo esc_attr('admin.php?page=example-*'); ?>"
        ><?php echo esc_textarea(is_string($value) ? $value : ''); ?></textarea>
        <p class="description">
            <?php esc_html_e('One path per line, relative to this site. Use * as a wildcard in a query value (for example admin.php?page=example-*). Absolute URLs on this site are converted to relative paths on save; external hosts are dropped.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Render the Dashboard Access screen.
     */
    public function render_settings_page() {
        if (!current_user_can($this->settings_capability())) {
            wp_die(esc_html__('You are not allowed to access User History settings.', 'user-history'));
        }

        ?>
        <div class="wrap user-history-settings">
            <h1><?php esc_html_e('Dashboard Access', 'user-history'); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields(self::OPTION_GROUP);
                do_settings_sections(self::MENU_SLUG);
                submit_button();
                ?>
            </form>
        </div>
        <script>
        (function () {
            var radios = document.querySelectorAll('input[name="<?php echo esc_js(self::OPTION_SWITCH); ?>"]');
            var select = document.querySelector('select[name="<?php echo esc_js(self::OPTION_CAP); ?>"]');
            if (!radios.length || !select) {
                return;
            }

            function toggle() {
                var capRadio = document.querySelector('input[name="<?php echo esc_js(self::OPTION_SWITCH); ?>"][value="capability"]');
                select.disabled = !(capRadio && capRadio.checked);
            }

            toggle();
            radios.forEach(function (radio) {
                radio.addEventListener('change', toggle);
            });
        })();
        </script>
        <?php
    }

    /**
     * Settings writes require both caps, except the one-time RDA import.
     *
     * @return bool
     */
    private function can_write_dashboard_settings() {
        return $this->importing_rda || $this->current_operator_can_enable();
    }

    /**
     * @return bool
     */
    private function is_profile_access_enabled() {
        return $this->option_flag_is_enabled(get_option(self::OPTION_PROFILE, '1'));
    }

    /**
     * @return string
     */
    private function get_redirect_url() {
        $redirect_url = get_option(self::OPTION_REDIRECT, '');

        return (is_string($redirect_url) && $redirect_url !== '') ? $redirect_url : home_url();
    }

    /**
     * @return bool
     */
    private function is_doing_ajax() {
        return defined('DOING_AJAX') && DOING_AJAX;
    }

    /**
     * Register the lock hooks for disallowed users.
     */
    private function lock_it_up() {
        add_action('admin_init', [$this, 'dashboard_redirect']);
        add_action('admin_head', [$this, 'hide_menus']);
        add_action('admin_bar_menu', [$this, 'hide_toolbar_items'], 999);
    }

    /**
     * @return array<string,array<int,array<string,string>>>
     */
    private function get_allowlist() {
        $allowlist = [
            'admin.php' => [
                [
                    'page' => 'WFLS',
                ],
            ],
            'admin-post.php' => [],
        ];

        $user_entries = $this->parse_url_allowlist((string) get_option(self::OPTION_ALLOWLIST, ''));

        foreach ($user_entries as $entry) {
            $pagenow = $entry['pagenow'];
            if (!isset($allowlist[ $pagenow ])) {
                $allowlist[ $pagenow ] = [];
            }

            if (empty($entry['params'])) {
                $allowlist[ $pagenow ] = [];
            } else {
                $allowlist[ $pagenow ][] = $entry['params'];
            }
        }

        return apply_filters('user_history_dashboard_allowlist', $allowlist);
    }

    /**
     * @param string $raw Newline-separated allowlist string.
     * @return array<int,array{pagenow:string,params:array<string,string>}>
     */
    private function parse_url_allowlist($raw) {
        if (!is_string($raw) || trim($raw) === '') {
            return [];
        }

        $entries = [];
        $lines = preg_split('/\R/', $raw);

        foreach ((array) $lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            $path = wp_parse_url($line, PHP_URL_PATH);
            $query = wp_parse_url($line, PHP_URL_QUERY);

            if (empty($path)) {
                continue;
            }

            $pagenow = $this->path_to_pagenow($path);
            if ($pagenow === '') {
                continue;
            }

            $params = [];
            if (!empty($query)) {
                wp_parse_str($query, $params);
            }

            $entries[] = [
                'pagenow' => $pagenow,
                'params'  => $params,
            ];
        }

        return $entries;
    }

    /**
     * @param string $path Path component.
     * @return string
     */
    private function path_to_pagenow($path) {
        if (!is_string($path) || $path === '') {
            return '';
        }

        $path = preg_replace('#^/wp-admin/(network/|user/)?#i', '', $path);
        $path = trim($path, '/');

        if ($path === '' || $path === 'index' || $path === 'index.php') {
            return 'index.php';
        }

        if (preg_match('#(.*?)(/|$)#', $path, $matches)) {
            $pagenow = strtolower($matches[1]);
        } else {
            $pagenow = strtolower($path);
        }

        if (substr($pagenow, -4) !== '.php') {
            $pagenow .= '.php';
        }

        return $pagenow;
    }

    /**
     * @param string|null $pagenow Optional pagenow override.
     * @return bool
     */
    private function is_allowed_page($pagenow = null) {
        if ($pagenow === null) {
            global $pagenow;
        }

        if (empty($pagenow) || !$this->request_matches_allowlist($pagenow, $_GET)) {
            return false;
        }

        return $this->is_target_page_registered($pagenow);
    }

    /**
     * @param string $pagenow Current admin page.
     * @return bool
     */
    private function is_target_page_registered($pagenow) {
        if ($pagenow !== 'admin.php') {
            return true;
        }

        if (empty($_GET['page'])) {
            return false;
        }

        $page_slug = wp_unslash($_GET['page']);
        if (!is_string($page_slug)) {
            return false;
        }

        if (!function_exists('get_plugin_page_hook')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        return get_plugin_page_hook($page_slug, $pagenow) !== null;
    }

    /**
     * @param array<string,mixed> $allowed_params_set Allowed GET parameters.
     * @param array<string,mixed> $query              Actual GET parameters.
     * @return bool
     */
    private function params_set_matches($allowed_params_set, $query) {
        if (!is_array($query) || !is_array($allowed_params_set)) {
            return false;
        }

        foreach ($allowed_params_set as $param_key => $param_value) {
            if (!isset($query[ $param_key ])) {
                return false;
            }

            $actual = wp_unslash($query[ $param_key ]);

            if (!is_string($actual) || !is_string($param_value)) {
                return false;
            }

            if (strpos($param_value, '*') !== false) {
                if (!$this->wildcard_match($param_value, $actual)) {
                    return false;
                }
                continue;
            }

            if ($actual !== $param_value) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param string $pattern Allowlist value possibly containing `*`.
     * @param string $subject Actual request value to test.
     * @return bool
     */
    private function wildcard_match($pattern, $subject) {
        if (strpos($pattern, '*') === false) {
            return $pattern === $subject;
        }

        $segments = explode('*', $pattern);
        $count = count($segments);

        $first = $segments[0];
        if ($first !== '' && strpos($subject, $first) !== 0) {
            return false;
        }
        $offset = strlen($first);

        for ($i = 1; $i < $count - 1; $i++) {
            $segment = $segments[ $i ];
            if ($segment === '') {
                continue;
            }

            $pos = strpos($subject, $segment, $offset);
            if ($pos === false) {
                return false;
            }
            $offset = $pos + strlen($segment);
        }

        $last = $segments[ $count - 1 ];
        if ($last === '') {
            return true;
        }

        $last_len = strlen($last);
        if (strlen($subject) < $offset + $last_len) {
            return false;
        }

        return substr($subject, -$last_len) === $last;
    }

    /**
     * @param string $url Raw URL string.
     * @return string|null
     */
    private function normalize_url_to_relative($url) {
        if (strpos($url, '//') === 0) {
            return null;
        }

        if (preg_match('#^https?://#i', $url)) {
            $url_host = wp_parse_url($url, PHP_URL_HOST);
            $home_host = wp_parse_url(home_url(), PHP_URL_HOST);

            if (empty($url_host) || empty($home_host) || strtolower($url_host) !== strtolower($home_host)) {
                return null;
            }

            $path = wp_parse_url($url, PHP_URL_PATH);
            $query = wp_parse_url($url, PHP_URL_QUERY);

            if (empty($path)) {
                return null;
            }

            return $path . ($query ? '?' . $query : '');
        }

        $hash_pos = strpos($url, '#');
        if ($hash_pos !== false) {
            $url = substr($url, 0, $hash_pos);
        }

        if ($url === '') {
            return null;
        }

        $colon_pos = strpos($url, ':');
        $slash_pos = strpos($url, '/');
        if ($colon_pos !== false && ($slash_pos === false || $colon_pos < $slash_pos)) {
            return null;
        }

        if ($url[0] !== '/') {
            $url = '/' . $url;
        }

        return $url;
    }

    /**
     * @param bool $enabled Whether the dropdown should be usable.
     */
    private function render_caps_dropdown($enabled) {
        global $wp_roles;

        if (!isset($wp_roles) || !is_a($wp_roles, 'WP_Roles')) {
            return;
        }

        $capabilities = [];
        foreach ($wp_roles->role_objects as $role) {
            if (is_array($role->capabilities)) {
                foreach ($role->capabilities as $cap => $grant) {
                    $capabilities[ $cap ] = $cap;
                }
            }
        }

        $capabilities = array_filter(
            $capabilities,
            static function ($cap) {
                return is_string($cap) && !preg_match('/^level_(?:\d|10)$/', $cap);
            },
            ARRAY_FILTER_USE_KEY
        );

        if (empty($capabilities)) {
            return;
        }

        ksort($capabilities);

        $access_cap = get_option(self::OPTION_CAP, 'manage_options');

        echo '<p><select name="' . esc_attr(self::OPTION_CAP) . '"' . disabled(!$enabled, true, false) . '>';
        foreach ($capabilities as $capability) {
            printf(
                '<option value="%1$s"%2$s>%3$s</option>',
                esc_attr($capability),
                selected($access_cap, $capability, false),
                esc_html($capability)
            );
        }
        echo '</select></p>';
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
