<?php

/**
 * Account lock/unlock for User History.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Lock {

    const META_KEY = 'user_history_locked';
    const MESSAGE_OPTION = 'user_history_locked_message';
    const MIGRATED_OPTION = 'user_history_migrated_lock';
    const AJAX_ACTION = 'user_history_toggle_lock';
    const NONCE_ACTION = 'user_history_lock';
    const MENU_SLUG = 'user-history-lock-accounts';
    const OPTION_GROUP = 'user_history_lock_settings';

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * @var User_History
     */
    private $plugin;

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

        add_filter('authenticate', [$this, 'block_locked_user_auth'], 1000, 3);
        add_action('wp_authenticate_application_password_errors', [$this, 'block_locked_user_app_password'], 10, 2);
        add_filter('determine_current_user', [$this, 'block_locked_user_session'], 9999);

        add_action('edit_user_profile', [$this, 'render_profile_lock_control'], 100);
        add_action('show_user_profile', [$this, 'render_profile_lock_control'], 100);

        add_action('wp_ajax_' . self::AJAX_ACTION, [$this, 'ajax_toggle_lock']);

        add_filter('user_row_actions', [$this, 'add_lock_row_action'], 10, 2);
        add_action('admin_init', [$this, 'process_lock_row_action']);
        add_action('admin_init', [$this, 'register_lock_settings']);
        add_filter('option_page_capability_' . self::OPTION_GROUP, [$this, 'settings_capability']);
        add_filter('manage_users_columns', [$this, 'add_locked_column']);
        add_filter('manage_users_custom_column', [$this, 'render_locked_column'], 10, 3);
        add_filter('bulk_actions-users', [$this, 'add_lock_bulk_actions']);
        add_filter('handle_bulk_actions-users', [$this, 'handle_lock_bulk_actions'], 10, 3);
        add_filter('views_users', [$this, 'add_locked_users_view']);
        add_action('pre_get_users', [$this, 'filter_locked_users_query']);
        add_action('admin_notices', [$this, 'lock_bulk_action_admin_notice']);
    }

    /**
     * @return string
     */
    public function settings_capability() {
        return User_History::CLEAR_HISTORY_CAPABILITY;
    }

    /**
     * One-time copy of Lock User Account plugin flags.
     */
    public function maybe_migrate_lock_user_account() {
        if (get_option(self::MIGRATED_OPTION)) {
            return;
        }

        $locked_users = get_users(
            [
                'meta_key'   => 'baba_user_locked',
                'meta_value' => 'yes',
                'fields'     => 'ID',
                'number'     => -1,
            ]
        );

        foreach ((array) $locked_users as $user_id) {
            $user_id = (int) $user_id;
            if ($user_id < 1) {
                continue;
            }

            update_user_meta($user_id, self::META_KEY, '1');
        }

        $current_message = get_option(self::MESSAGE_OPTION, '');
        if ($current_message === '' || $current_message === false) {
            $legacy_message = get_option('baba_locked_message', '');
            if (is_string($legacy_message) && $legacy_message !== '') {
                update_option(self::MESSAGE_OPTION, $legacy_message);
            }
        }

        update_option(self::MIGRATED_OPTION, '1');
    }

    /**
     * @param int $user_id User ID.
     * @return bool
     */
    public function is_user_locked($user_id) {
        return get_user_meta((int) $user_id, self::META_KEY, true) === '1';
    }

    /**
     * @param int $user_id User ID.
     * @return bool
     */
    public function current_operator_can_lock_user($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1 || !is_user_logged_in()) {
            return false;
        }

        if ($user_id === get_current_user_id()) {
            return false;
        }

        if (is_multisite() && is_super_admin($user_id)) {
            return false;
        }

        return current_user_can('edit_users') && current_user_can('edit_user', $user_id);
    }

    /**
     * @param int $user_id User ID.
     * @return true|WP_Error
     */
    public function lock_user($user_id) {
        $user_id = (int) $user_id;
        $user = get_userdata($user_id);
        if (!$user) {
            return new WP_Error('invalid_user', __('Invalid user.', 'user-history'));
        }

        if (!$this->current_operator_can_lock_user($user_id)) {
            if ($user_id === get_current_user_id()) {
                return new WP_Error('self_lock', __('You cannot lock your own account.', 'user-history'));
            }

            if (is_multisite() && is_super_admin($user_id)) {
                return new WP_Error('super_admin_lock', __('Super admins cannot be locked.', 'user-history'));
            }

            return new WP_Error('forbidden', __('You are not allowed to lock this user.', 'user-history'));
        }

        if ($this->is_user_locked($user_id)) {
            return true;
        }

        update_user_meta($user_id, self::META_KEY, '1');

        if (class_exists('WP_Session_Tokens')) {
            WP_Session_Tokens::get_instance($user_id)->destroy_all();
        }

        $this->plugin->record_change(
            $user_id,
            get_current_user_id(),
            'account_locked',
            __('Account Locked', 'user-history'),
            '',
            __('Locked', 'user-history'),
            'lock'
        );

        do_action('user_history_user_locked', $user_id);

        return true;
    }

    /**
     * @param int $user_id User ID.
     * @return true|WP_Error
     */
    public function unlock_user($user_id) {
        $user_id = (int) $user_id;
        $user = get_userdata($user_id);
        if (!$user) {
            return new WP_Error('invalid_user', __('Invalid user.', 'user-history'));
        }

        if (!$this->current_operator_can_lock_user($user_id)) {
            return new WP_Error('forbidden', __('You are not allowed to unlock this user.', 'user-history'));
        }

        if (!$this->is_user_locked($user_id)) {
            return true;
        }

        delete_user_meta($user_id, self::META_KEY);

        $this->plugin->record_change(
            $user_id,
            get_current_user_id(),
            'account_locked',
            __('Account Unlocked', 'user-history'),
            __('Locked', 'user-history'),
            '',
            'unlock'
        );

        do_action('user_history_user_unlocked', $user_id);

        return true;
    }

    /**
     * @return int
     */
    public function get_locked_user_count() {
        $users = get_users(
            [
                'meta_key'   => self::META_KEY,
                'meta_value' => '1',
                'fields'     => 'ID',
                'number'     => -1,
            ]
        );

        return count((array) $users);
    }

    /**
     * @param int $limit Max users.
     * @return WP_User[]
     */
    public function get_locked_users($limit = 10) {
        return get_users(
            [
                'meta_key'   => self::META_KEY,
                'meta_value' => '1',
                'number'     => (int) $limit,
                'orderby'    => 'ID',
                'order'      => 'DESC',
            ]
        );
    }

    /**
     * @return string
     */
    public function get_locked_message() {
        $message = get_option(self::MESSAGE_OPTION, '');
        if (!is_string($message) || $message === '') {
            return __('Your account has been locked. Please contact the administrator.', 'user-history');
        }

        return $message;
    }

    /**
     * @param WP_User|WP_Error|null $user Authenticated user or error.
     * @return WP_User|WP_Error|null
     */
    public function block_locked_user_auth($user, $username = '', $password = '') {
        if (!($user instanceof WP_User)) {
            return $user;
        }

        if ($this->is_user_locked($user->ID)) {
            return new WP_Error('user_locked', $this->get_locked_message());
        }

        return $user;
    }

    /**
     * @param WP_Error $error Error object.
     * @param WP_User  $user  User object.
     */
    public function block_locked_user_app_password($error, $user) {
        if ($user instanceof WP_User && $this->is_user_locked($user->ID)) {
            $error->add('user_locked', $this->get_locked_message());
        }
    }

    /**
     * @param int|false $user_id Current user ID.
     * @return int|false
     */
    public function block_locked_user_session($user_id) {
        if (!$user_id) {
            return $user_id;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return $user_id;
        }

        if ($this->is_user_locked((int) $user_id)) {
            return false;
        }

        return $user_id;
    }

    public function ajax_toggle_lock() {
        check_ajax_referer(self::NONCE_ACTION, 'nonce');

        $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
        $action = isset($_POST['lock_action']) ? sanitize_key(wp_unslash($_POST['lock_action'])) : '';

        if (!$user_id || !in_array($action, ['lock', 'unlock'], true)) {
            wp_send_json_error(['message' => __('Invalid request.', 'user-history')]);
        }

        if (!$this->current_operator_can_lock_user($user_id)) {
            wp_send_json_error(['message' => __('You are not allowed to lock or unlock this user.', 'user-history')]);
        }

        $result = ($action === 'lock') ? $this->lock_user($user_id) : $this->unlock_user($user_id);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }

        wp_send_json_success(
            [
                'message'  => $action === 'lock'
                    ? __('Account locked. All sessions have been destroyed.', 'user-history')
                    : __('Account unlocked.', 'user-history'),
                'isLocked' => $this->is_user_locked($user_id),
            ]
        );
    }

    /**
     * @param WP_User $user Profile user.
     */
    public function render_profile_lock_control($user) {
        if (!$this->current_operator_can_lock_user((int) $user->ID)) {
            return;
        }

        $is_locked = $this->is_user_locked((int) $user->ID);
        $action = $is_locked ? 'unlock' : 'lock';
        $label = $is_locked ? __('Unlock Account', 'user-history') : __('Lock Account', 'user-history');

        ?>
        <div class="user-history-section user-history-lock-section">
            <h2><?php esc_html_e('Lock Account', 'user-history'); ?></h2>
            <p class="description">
                <?php
                echo $is_locked
                    ? esc_html__('This account is locked. They cannot sign in until you unlock them.', 'user-history')
                    : esc_html__('Lock this account to sign them out and block further logins.', 'user-history');
                ?>
            </p>
            <p>
                <button
                    type="button"
                    id="user-history-toggle-lock"
                    class="button <?php echo $is_locked ? '' : 'user-history-lock-button'; ?>"
                    data-lock-action="<?php echo esc_attr($action); ?>"
                    data-user-id="<?php echo esc_attr((string) (int) $user->ID); ?>"
                >
                    <?php echo esc_html($label); ?>
                </button>
                <span id="user-history-lock-message" class="user-history-lock-message" role="status"></span>
            </p>
        </div>
        <?php
    }

    /**
     * @param array<string,string> $columns Users table columns.
     * @return array<string,string>
     */
    public function add_locked_column($columns) {
        $new_columns = [];
        foreach ((array) $columns as $key => $value) {
            $new_columns[$key] = $value;
            if ($key === 'role') {
                $new_columns['user_history_locked'] = __('Status', 'user-history');
            }
        }

        if (!isset($new_columns['user_history_locked'])) {
            $new_columns['user_history_locked'] = __('Status', 'user-history');
        }

        return $new_columns;
    }

    /**
     * @param string $output      Current output.
     * @param string $column_name Column key.
     * @param int    $user_id     User ID.
     * @return string
     */
    public function render_locked_column($output, $column_name, $user_id) {
        if ($column_name !== 'user_history_locked') {
            return $output;
        }

        if ($this->is_user_locked((int) $user_id)) {
            return '<span class="user-history-lock-badge locked">' . esc_html__('Locked', 'user-history') . '</span>';
        }

        return '&mdash;';
    }

    /**
     * @param array<string,string> $actions Row actions.
     * @param WP_User              $user_object User.
     * @return array<string,string>
     */
    public function add_lock_row_action($actions, $user_object) {
        if (!$this->current_operator_can_lock_user((int) $user_object->ID)) {
            return $actions;
        }

        $is_locked = $this->is_user_locked((int) $user_object->ID);
        $action = $is_locked ? 'user_history_unlock' : 'user_history_lock';
        $label = $is_locked ? __('Unlock', 'user-history') : __('Lock', 'user-history');
        $url = wp_nonce_url(
            add_query_arg(
                [
                    'action' => $action,
                    'user'   => (int) $user_object->ID,
                ],
                admin_url('users.php')
            ),
            self::NONCE_ACTION . '_' . (int) $user_object->ID
        );

        $actions[$is_locked ? 'user_history_unlock' : 'user_history_lock'] = '<a href="' . esc_url($url) . '">' . esc_html($label) . '</a>';

        return $actions;
    }

    public function process_lock_row_action() {
        global $pagenow;

        if ($pagenow !== 'users.php') {
            return;
        }

        $action = isset($_GET['action']) ? sanitize_key(wp_unslash($_GET['action'])) : '';
        if (!in_array($action, ['user_history_lock', 'user_history_unlock'], true)) {
            return;
        }

        $user_id = isset($_GET['user']) ? (int) $_GET['user'] : 0;
        if (!$user_id) {
            return;
        }

        check_admin_referer(self::NONCE_ACTION . '_' . $user_id);

        if ($action === 'user_history_lock') {
            $this->lock_user($user_id);
        } else {
            $this->unlock_user($user_id);
        }

        $redirect = wp_get_referer() ? wp_get_referer() : admin_url('users.php');
        wp_safe_redirect(remove_query_arg(['action', 'user', '_wpnonce'], $redirect));
        exit;
    }

    /**
     * @param array<string,string> $actions Bulk actions.
     * @return array<string,string>
     */
    public function add_lock_bulk_actions($actions) {
        if (!current_user_can('edit_users')) {
            return $actions;
        }

        $actions['user_history_lock_users'] = __('Lock', 'user-history');
        $actions['user_history_unlock_users'] = __('Unlock', 'user-history');

        return $actions;
    }

    /**
     * @param string   $redirect_url Redirect URL.
     * @param string   $action       Bulk action.
     * @param int[]    $user_ids     Selected IDs.
     * @return string
     */
    public function handle_lock_bulk_actions($redirect_url, $action, $user_ids) {
        if (!in_array($action, ['user_history_lock_users', 'user_history_unlock_users'], true)) {
            return $redirect_url;
        }

        $count = 0;
        foreach ((array) $user_ids as $user_id) {
            $user_id = (int) $user_id;
            if (!$this->current_operator_can_lock_user($user_id)) {
                continue;
            }

            $was_locked = $this->is_user_locked($user_id);
            $result = ($action === 'user_history_lock_users')
                ? $this->lock_user($user_id)
                : $this->unlock_user($user_id);

            if ($result !== true) {
                continue;
            }

            $now_locked = $this->is_user_locked($user_id);
            if ($was_locked !== $now_locked) {
                $count++;
            }
        }

        return add_query_arg(
            [
                'user_history_lock_action' => $action,
                'user_history_lock_count'  => $count,
            ],
            $redirect_url
        );
    }

    public function lock_bulk_action_admin_notice() {
        $action = isset($_GET['user_history_lock_action']) ? sanitize_key(wp_unslash($_GET['user_history_lock_action'])) : '';
        $count = isset($_GET['user_history_lock_count']) ? (int) $_GET['user_history_lock_count'] : 0;

        if ($action === '' || $count < 1) {
            return;
        }

        if ($action === 'user_history_lock_users') {
            $message = sprintf(
                /* translators: %d: number of users locked */
                _n('%d user locked.', '%d users locked.', $count, 'user-history'),
                $count
            );
        } else {
            $message = sprintf(
                /* translators: %d: number of users unlocked */
                _n('%d user unlocked.', '%d users unlocked.', $count, 'user-history'),
                $count
            );
        }

        printf('<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html($message));
    }

    /**
     * @param array<string,string> $views Users list views.
     * @return array<string,string>
     */
    public function add_locked_users_view($views) {
        $count = $this->get_locked_user_count();
        $current_filter = isset($_GET['user_history_filter']) ? sanitize_key(wp_unslash($_GET['user_history_filter'])) : '';
        $class = ($current_filter === 'locked') ? 'current' : '';

        $views['user_history_locked'] = sprintf(
            '<a href="%s" class="%s">%s <span class="count">(%d)</span></a>',
            esc_url(add_query_arg('user_history_filter', 'locked', admin_url('users.php'))),
            esc_attr($class),
            esc_html__('Locked', 'user-history'),
            $count
        );

        return $views;
    }

    /**
     * @param WP_User_Query $query User query.
     */
    public function filter_locked_users_query($query) {
        global $pagenow;

        if (!is_admin() || $pagenow !== 'users.php') {
            return;
        }

        $filter = isset($_GET['user_history_filter']) ? sanitize_key(wp_unslash($_GET['user_history_filter'])) : '';
        if ($filter !== 'locked') {
            return;
        }

        $query->set('meta_key', self::META_KEY);
        $query->set('meta_value', '1');
    }

    public function register_lock_settings() {
        register_setting(
            self::OPTION_GROUP,
            self::MESSAGE_OPTION,
            [
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_textarea_field',
                'default'           => '',
                'show_in_rest'      => false,
            ]
        );
    }

    public function render_settings_page() {
        if (!current_user_can($this->settings_capability())) {
            wp_die(esc_html__('You are not allowed to access User History settings.', 'user-history'));
        }

        $locked_users = $this->get_locked_users(20);
        $message = get_option(self::MESSAGE_OPTION, '');

        ?>
        <div class="wrap user-history-settings">
            <h1><?php esc_html_e('Lock Accounts', 'user-history'); ?></h1>
            <form action="options.php" method="post">
                <?php settings_fields(self::OPTION_GROUP); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">
                            <label for="user_history_locked_message"><?php esc_html_e('Custom lock message', 'user-history'); ?></label>
                        </th>
                        <td>
                            <textarea
                                class="large-text"
                                rows="3"
                                id="user_history_locked_message"
                                name="<?php echo esc_attr(self::MESSAGE_OPTION); ?>"
                            ><?php echo esc_textarea(is_string($message) ? $message : ''); ?></textarea>
                            <p class="description">
                                <?php esc_html_e('Shown on the login form to locked users. Leave empty for the default “contact the administrator” text.', 'user-history'); ?>
                            </p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <h2><?php esc_html_e('Locked users', 'user-history'); ?></h2>
            <?php if (empty($locked_users)) : ?>
                <p><?php esc_html_e('No accounts are locked.', 'user-history'); ?></p>
            <?php else : ?>
                <ul class="user-history-locked-user-list">
                    <?php foreach ($locked_users as $user) : ?>
                        <li>
                            <?php if (current_user_can('edit_user', $user->ID)) : ?>
                                <a href="<?php echo esc_url(get_edit_user_link($user->ID)); ?>">
                                    <?php echo esc_html($user->user_login); ?>
                                </a>
                            <?php else : ?>
                                <?php echo esc_html($user->user_login); ?>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
        <?php
    }
}
