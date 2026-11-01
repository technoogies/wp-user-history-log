<?php

/**
 * Login recording and session monitoring for User History.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Login_Tracker {

    const OPTION_KEY = 'user_history_login_tracking_enabled';
    const DESTROY_ACTION = 'user_history_destroy_sessions';
    const DESTROY_NONCE = 'user_history_destroy_sessions';
    const FIELD_NAME = 'user_session';

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

        add_action('wp_login', [$this, 'log_login'], 10, 2);
        add_action('wp_logout', [$this, 'log_logout'], 10, 1);
        add_action('wp_login_failed', [$this, 'log_failed_login'], 10, 2);
        add_action('wp_ajax_' . self::DESTROY_ACTION, [$this, 'ajax_destroy_sessions']);
    }

    /**
     * Login recording stays off until an operator enables it.
     *
     * @return bool
     */
    public function is_enabled() {
        $enabled = $this->option_flag_is_enabled(get_option(self::OPTION_KEY, '0'));

        return (bool) apply_filters('user_history_login_tracking_enabled', $enabled);
    }

    /**
     * @param string  $user_login Username.
     * @param WP_User $user       Authenticated user.
     */
    public function log_login($user_login, $user) {
        unset($user_login);

        if (!$this->is_enabled() || !($user instanceof WP_User)) {
            return;
        }

        $this->record_login_event(
            (int) $user->ID,
            (int) $user->ID,
            'login',
            __('Login', 'user-history')
        );
    }

    /**
     * @param int $user_id Logging-out user ID.
     */
    public function log_logout($user_id) {
        $user_id = (int) $user_id;
        if (!$this->is_enabled() || $user_id < 1) {
            return;
        }

        $this->record_login_event(
            $user_id,
            $user_id,
            'logout',
            __('Logout', 'user-history'),
            false
        );
    }

    /**
     * Failed logins are recorded only for existing accounts. Passwords are never stored.
     *
     * @param string        $username Attempted username or email.
     * @param WP_Error|null $error    Authentication error.
     */
    public function log_failed_login($username, $error = null) {
        unset($error);

        if (!$this->is_enabled()) {
            return;
        }

        $username = is_string($username) ? $username : '';
        if ($username === '') {
            return;
        }

        $user = get_user_by('login', $username);
        if (!$user) {
            $user = get_user_by('email', $username);
        }

        if (!$user) {
            return;
        }

        $this->record_login_event(
            (int) $user->ID,
            0,
            'login_failed',
            __('Failed Login', 'user-history')
        );
    }

    /**
     * @param int $user_id Target user.
     * @return bool
     */
    public function current_operator_can_destroy_sessions($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1 || !is_user_logged_in()) {
            return false;
        }

        return current_user_can('edit_users') && current_user_can('edit_user', $user_id);
    }

    /**
     * @param int $user_id Target user.
     * @return true|WP_Error
     */
    public function destroy_all_sessions($user_id) {
        $user_id = (int) $user_id;
        $user = get_userdata($user_id);
        if (!$user) {
            return new WP_Error('invalid_user', __('Invalid user.', 'user-history'));
        }

        if (!$this->current_operator_can_destroy_sessions($user_id)) {
            return new WP_Error('forbidden', __('You are not allowed to end this user’s sessions.', 'user-history'));
        }

        if (class_exists('WP_Session_Tokens')) {
            WP_Session_Tokens::get_instance($user_id)->destroy_all();
        }

        return true;
    }

    public function ajax_destroy_sessions() {
        check_ajax_referer(self::DESTROY_NONCE, 'nonce');

        $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
        $result = $this->destroy_all_sessions($user_id);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }

        wp_send_json_success(
            [
                'message' => __('All sessions have been destroyed.', 'user-history'),
            ]
        );
    }

    /**
     * Local browser/OS label. Does not call an external service.
     *
     * @param string $ua User-agent string.
     * @return string
     */
    public function parse_user_agent($ua) {
        $ua = is_string($ua) ? $ua : '';
        if ($ua === '') {
            return '';
        }

        $browser = __('Other', 'user-history');
        if (preg_match('/Edg[e\/]/i', $ua)) {
            $browser = 'Edge';
        } elseif (preg_match('/OPR|Opera/i', $ua)) {
            $browser = 'Opera';
        } elseif (preg_match('/Chrome/i', $ua)) {
            $browser = 'Chrome';
        } elseif (preg_match('/Safari/i', $ua) && !preg_match('/Chrome/i', $ua)) {
            $browser = 'Safari';
        } elseif (preg_match('/Firefox/i', $ua)) {
            $browser = 'Firefox';
        } elseif (preg_match('/MSIE|Trident/i', $ua)) {
            $browser = 'IE';
        }

        $os = __('Other', 'user-history');
        if (preg_match('/Windows/i', $ua)) {
            $os = 'Windows';
        } elseif (preg_match('/Macintosh|Mac OS/i', $ua)) {
            $os = 'macOS';
        } elseif (preg_match('/Linux/i', $ua) && !preg_match('/Android/i', $ua)) {
            $os = 'Linux';
        } elseif (preg_match('/Android/i', $ua)) {
            $os = 'Android';
        } elseif (preg_match('/iPhone|iPad|iPod/i', $ua)) {
            $os = 'iOS';
        }

        /* translators: 1: browser name, 2: operating system name */
        return sprintf(__('%1$s on %2$s', 'user-history'), $browser, $os);
    }

    /**
     * @param object[] $history Login history rows.
     * @return string
     */
    public function render_login_rows($history) {
        $output = '';

        foreach ((array) $history as $entry) {
            $user_agent = $this->plugin->get_history_row_display_value($entry, 'new');
            $ip = $this->plugin->get_history_row_ip($entry);
            $browser = $user_agent !== '' ? $this->parse_user_agent($user_agent) : '';

            $output .= '<tr class="user-history-entry type-' . esc_attr($entry->change_type) . '">';
            $output .= '<td class="column-date">';
            $output .= '<span class="history-date">' . esc_html(date_i18n(get_option('date_format'), strtotime($entry->created_at))) . '</span>';
            $output .= '<span class="history-time">' . esc_html(date_i18n(get_option('time_format'), strtotime($entry->created_at))) . '</span>';
            $output .= '</td>';
            $output .= '<td class="column-event"><strong>' . esc_html($entry->field_label) . '</strong></td>';
            $output .= '<td class="column-ip">' . ($ip !== '' ? esc_html($ip) : '&mdash;') . '</td>';
            $output .= '<td class="column-browser">' . ($browser !== '' ? esc_html($browser) : '&mdash;') . '</td>';
            $output .= '</tr>';
        }

        return $output;
    }

    /**
     * @param WP_User $user     Profile user.
     * @param array   $sessions Session token payloads.
     * @return string
     */
    public function render_sessions_tab($user, $sessions) {
        $current_token = '';
        if ((int) $user->ID === get_current_user_id()) {
            $cookie = wp_parse_auth_cookie('', 'logged_in');
            if (is_array($cookie) && isset($cookie['token'])) {
                $current_token = $cookie['token'];
            }
        }

        $output = '<table class="widefat user-history-table user-history-sessions-table">';
        $output .= '<thead><tr>';
        $output .= '<th class="column-date">' . esc_html__('Login Time', 'user-history') . '</th>';
        $output .= '<th class="column-ip">' . esc_html__('IP Address', 'user-history') . '</th>';
        $output .= '<th class="column-browser">' . esc_html__('Browser', 'user-history') . '</th>';
        $output .= '<th class="column-expires">' . esc_html__('Expires', 'user-history') . '</th>';
        $output .= '</tr></thead><tbody>';

        if (empty($sessions)) {
            $output .= '<tr><td colspan="4"><p class="user-history-empty">' . esc_html__('No active sessions.', 'user-history') . '</p></td></tr>';
        } else {
            foreach ($sessions as $verifier => $session) {
                $is_current = ($current_token !== '' && hash('sha256', $current_token) === $verifier);
                $is_expired = (isset($session['expiration']) && (int) $session['expiration'] < time());
                $row_class = $is_current ? ' session-current' : '';

                $output .= '<tr class="user-history-entry' . esc_attr($row_class) . '">';
                $output .= '<td class="column-date">';
                if (!empty($session['login'])) {
                    $output .= '<span class="history-date">' . esc_html(date_i18n(get_option('date_format'), (int) $session['login'])) . '</span>';
                    $output .= '<span class="history-time">' . esc_html(date_i18n(get_option('time_format'), (int) $session['login'])) . '</span>';
                } else {
                    $output .= '&mdash;';
                }
                if ($is_current) {
                    $output .= ' <span class="history-self">' . esc_html__('(current)', 'user-history') . '</span>';
                }
                $output .= '</td>';

                $output .= '<td class="column-ip">';
                $output .= !empty($session['ip']) ? esc_html((string) $session['ip']) : '&mdash;';
                $output .= '</td>';

                $output .= '<td class="column-browser">';
                if (!empty($session['ua'])) {
                    $output .= esc_html($this->parse_user_agent((string) $session['ua']));
                } else {
                    $output .= '&mdash;';
                }
                $output .= '</td>';

                $output .= '<td class="column-expires">';
                if ($is_expired) {
                    $output .= esc_html__('Expired', 'user-history');
                } elseif (!empty($session['expiration'])) {
                    $output .= esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), (int) $session['expiration']));
                } else {
                    $output .= '&mdash;';
                }
                $output .= '</td>';
                $output .= '</tr>';
            }
        }

        $output .= '</tbody></table>';

        if ($this->current_operator_can_destroy_sessions((int) $user->ID)) {
            $output .= '<p class="user-history-actions">';
            $output .= '<button type="button" class="button" id="user-history-destroy-sessions" data-user-id="' . esc_attr((string) (int) $user->ID) . '">';
            $output .= esc_html__('Log Out Everywhere', 'user-history');
            $output .= '</button>';
            $output .= ' <span id="user-history-destroy-sessions-message" class="user-history-lock-message" role="status"></span>';
            $output .= '</p>';
        }

        return $output;
    }

    /**
     * @param int    $user_id     Account the event belongs to.
     * @param int    $changed_by  Operator or 0 for failed login.
     * @param string $change_type login|logout|login_failed.
     * @param string $label       Event label.
     * @param bool   $store_ua    Whether to store the request user-agent.
     */
    private function record_login_event($user_id, $changed_by, $change_type, $label, $store_ua = true) {
        $user_agent = '';
        if ($store_ua && isset($_SERVER['HTTP_USER_AGENT'])) {
            $user_agent = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']));
        }

        $this->plugin->record_change(
            $user_id,
            $changed_by,
            self::FIELD_NAME,
            $label,
            '',
            $user_agent,
            $change_type,
            ['action' => $change_type]
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
