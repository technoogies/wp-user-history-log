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
    const LOAD_PAGES_ACTION = 'user_history_load_session_pages';
    const LOAD_PAGES_NONCE = 'user_history_load_session_pages';
    const FIELD_NAME = 'user_session';
    const SESSIONS_PREVIEW_LIMIT = 25;
    const SESSIONS_PAGE_SIZE = 100;

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * @var User_History
     */
    private $plugin;

    /**
     * Public client IP for a session created in this request, keyed by user ID.
     *
     * @var array<int,string>
     */
    private $pending_client_ips = [];

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
        add_action('wp_ajax_' . self::LOAD_PAGES_ACTION, [$this, 'ajax_load_session_pages']);
        add_filter('attach_session_information', [$this, 'remember_client_ip_for_new_session'], 10, 2);
        add_action('set_logged_in_cookie', [$this, 'store_client_ip_on_new_session'], 10, 6);
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
     * Older session pages. Reads the full token list and returns one display slice.
     */
    public function ajax_load_session_pages() {
        check_ajax_referer(self::LOAD_PAGES_NONCE, 'nonce');

        $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
        $page = isset($_POST['page']) ? (int) $_POST['page'] : 1;

        if ($user_id < 1 || !is_user_logged_in() || !current_user_can('edit_user', $user_id)) {
            wp_send_json_error(['message' => __('You are not allowed to view these sessions.', 'user-history')]);
        }

        $sessions = $this->active_sessions_by_verifier($user_id);
        $partition = $this->partition_sessions_for_display($sessions, $page);

        wp_send_json_success(
            [
                'html'       => $this->render_session_rows($partition['page_sessions'], $this->current_session_verifier($user_id)),
                'page'       => $partition['page'],
                'pages'      => $partition['page_count'],
                'olderCount' => $partition['older_count'],
            ]
        );
    }

    /**
     * Remember a public forwarded client IP while WordPress is creating a session.
     *
     * Core runs attach_session_information and then overwrites session ip from
     * REMOTE_ADDR. Setting ip here does not win on WordPress 6.0 through 6.9.
     * store_client_ip_on_new_session() runs from set_logged_in_cookie after create().
     *
     * @param array $session Session payload passed to the filter.
     * @param int   $user_id User ID.
     * @return array
     */
    public function remember_client_ip_for_new_session($session, $user_id) {
        if (!is_array($session)) {
            $session = [];
        }

        $user_id = (int) $user_id;
        $ip = $this->forwarded_public_client_ip();
        if ($ip === '') {
            unset($this->pending_client_ips[$user_id]);
            return $session;
        }

        $session['ip'] = $ip;
        $this->pending_client_ips[$user_id] = $ip;

        return $session;
    }

    /**
     * Store the forwarded client IP on a session that was just created.
     *
     * Does not walk existing session_tokens rows. A cookie refresh for an older
     * login time is ignored, and history/activity IP collection is not involved.
     *
     * @param string $logged_in_cookie Logged-in cookie value. Unused.
     * @param int    $expire           Grace-period expiry. Unused.
     * @param int    $expiration       Cookie expiration. Unused.
     * @param int    $user_id          User ID.
     * @param string $scheme           Cookie scheme. Unused.
     * @param string $token            Raw session token.
     */
    public function store_client_ip_on_new_session($logged_in_cookie, $expire, $expiration, $user_id, $scheme, $token) {
        unset($logged_in_cookie, $expire, $expiration, $scheme);

        $user_id = (int) $user_id;
        if ($user_id < 1 || !is_string($token) || $token === '' || !isset($this->pending_client_ips[$user_id])) {
            return;
        }

        $ip = $this->pending_client_ips[$user_id];
        if (!is_string($ip) || $ip === '' || !$this->is_public_ip($ip)) {
            return;
        }

        if (!class_exists('WP_Session_Tokens')) {
            return;
        }

        $manager = WP_Session_Tokens::get_instance($user_id);
        $session = $manager->get($token);
        if (!is_array($session)) {
            return;
        }

        $login = isset($session['login']) ? (int) $session['login'] : 0;
        if ($login < (time() - 15)) {
            return;
        }

        if (isset($session['ip']) && (string) $session['ip'] === $ip) {
            return;
        }

        $session['ip'] = $ip;
        $manager->update($token, $session);
    }

    /**
     * First public client IP from CF-Connecting-IP, X-Real-IP, or X-Forwarded-For.
     *
     * Empty headers and private-only client addresses are skipped.
     *
     * @return string
     */
    public function forwarded_public_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
        ];

        foreach ($headers as $header) {
            if (!isset($_SERVER[$header]) || !is_string($_SERVER[$header])) {
                continue;
            }

            $ip = $this->public_client_ip_from_forwarded_value(wp_unslash($_SERVER[$header]));
            if ($ip !== '') {
                return $ip;
            }
        }

        return '';
    }

    /**
     * Client address from one forwarded header. The client is the first address.
     *
     * @param string $value Raw header value.
     * @return string Public IP, or empty when the client address is missing, invalid, or private.
     */
    public function public_client_ip_from_forwarded_value($value) {
        if (!is_string($value)) {
            return '';
        }

        $value = trim($value);
        if ($value === '') {
            return '';
        }

        $first = trim(explode(',', $value, 2)[0]);
        $first = trim($first, "\"'");
        if ($first === '' || !$this->is_public_ip($first)) {
            return '';
        }

        return $first;
    }

    /**
     * @param string $ip Candidate address.
     * @return bool
     */
    private function is_public_ip($ip) {
        if (!is_string($ip) || $ip === '') {
            return false;
        }

        return false !== filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Newest login time first. Ties keep the later stored session ahead of the earlier one.
     *
     * @param array $sessions Session payloads keyed by verifier.
     * @return array
     */
    public function sort_sessions_newest_first($sessions) {
        if (!is_array($sessions)) {
            return [];
        }

        $indexed = [];
        $position = 0;
        foreach ($sessions as $verifier => $session) {
            if (!is_array($session)) {
                continue;
            }

            $indexed[] = [
                'verifier' => (string) $verifier,
                'session'  => $session,
                'login'    => isset($session['login']) ? (int) $session['login'] : 0,
                'position' => $position,
            ];
            $position++;
        }

        usort(
            $indexed,
            static function ($left, $right) {
                if ($left['login'] === $right['login']) {
                    return $right['position'] <=> $left['position'];
                }

                return $right['login'] <=> $left['login'];
            }
        );

        $sorted = [];
        foreach ($indexed as $item) {
            $sorted[$item['verifier']] = $item['session'];
        }

        return $sorted;
    }

    /**
     * Split a full session list into the newest 25 and one page of the older remainder.
     *
     * Does not change stored tokens. The caller still passes the full get_all() result.
     *
     * @param array $sessions Session payloads keyed by verifier.
     * @param int   $page     1-based page of the sessions after the newest 25.
     * @return array{preview:array,page_sessions:array,page:int,page_count:int,older_count:int,total:int}
     */
    public function partition_sessions_for_display($sessions, $page = 1) {
        $sorted = $this->sort_sessions_newest_first($sessions);
        $preview = array_slice($sorted, 0, self::SESSIONS_PREVIEW_LIMIT, true);
        $older = array_slice($sorted, self::SESSIONS_PREVIEW_LIMIT, null, true);
        $older_count = count($older);
        $page_count = $older_count > 0
            ? (int) ceil($older_count / self::SESSIONS_PAGE_SIZE)
            : 0;

        $page = (int) $page;
        if ($page < 1) {
            $page = 1;
        }
        if ($page_count > 0 && $page > $page_count) {
            $page = $page_count;
        }

        $page_sessions = [];
        if ($page_count > 0) {
            $offset = ($page - 1) * self::SESSIONS_PAGE_SIZE;
            $page_sessions = array_slice($older, $offset, self::SESSIONS_PAGE_SIZE, true);
        }

        return [
            'preview'       => $preview,
            'page_sessions' => $page_sessions,
            'page'          => $page_count > 0 ? $page : 0,
            'page_count'    => $page_count,
            'older_count'   => $older_count,
            'total'         => count($sorted),
        ];
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
     * @param array   $sessions Full session token payloads from get_all().
     * @return string
     */
    public function render_sessions_tab($user, $sessions) {
        $user_id = (int) $user->ID;
        $sessions = $this->sessions_with_verifiers($user_id, $sessions);
        $partition = $this->partition_sessions_for_display($sessions, 1);
        $verifier = $this->current_session_verifier($user_id);

        $output = '<table class="widefat user-history-table user-history-sessions-table" id="user-history-sessions-table">';
        $output .= '<thead><tr>';
        $output .= '<th class="column-date">' . esc_html__('Login Time', 'user-history') . '</th>';
        $output .= '<th class="column-ip">' . esc_html__('IP Address', 'user-history') . '</th>';
        $output .= '<th class="column-browser">' . esc_html__('Browser', 'user-history') . '</th>';
        $output .= '<th class="column-expires">' . esc_html__('Expires', 'user-history') . '</th>';
        $output .= '</tr></thead>';
        $output .= '<tbody id="user-history-sessions-newest">';

        if ($partition['total'] === 0) {
            $output .= '<tr><td colspan="4"><p class="user-history-empty">' . esc_html__('No active sessions.', 'user-history') . '</p></td></tr>';
        } else {
            $output .= $this->render_session_rows($partition['preview'], $verifier);
        }

        $output .= '</tbody>';
        $output .= '<tbody id="user-history-sessions-older" hidden></tbody>';
        $output .= '</table>';

        if ($partition['older_count'] > 0) {
            $output .= '<nav id="user-history-sessions-pagination" class="user-history-sessions-pagination" aria-label="' . esc_attr__('Older sessions', 'user-history') . '" hidden></nav>';
        }

        if ($partition['older_count'] > 0 || $this->current_operator_can_destroy_sessions($user_id)) {
            $output .= '<p class="user-history-actions">';
            if ($partition['older_count'] > 0) {
                $output .= '<button type="button" class="button" id="user-history-load-session-pages" data-user-id="' . esc_attr((string) $user_id) . '">';
                $output .= esc_html__('Load Pages', 'user-history');
                $output .= '</button>';
                $output .= ' <span id="user-history-sessions-pages-message" class="user-history-lock-message" role="status"></span>';
            }
            if ($this->current_operator_can_destroy_sessions($user_id)) {
                $output .= ' <button type="button" class="button" id="user-history-destroy-sessions" data-user-id="' . esc_attr((string) $user_id) . '">';
                $output .= esc_html__('Log Out Everywhere', 'user-history');
                $output .= '</button>';
                $output .= ' <span id="user-history-destroy-sessions-message" class="user-history-lock-message" role="status"></span>';
            }
            $output .= '</p>';
        }

        return $output;
    }

    /**
     * Session rows keyed by the sha256 verifier stored in session_tokens.
     *
     * WP_Session_Tokens::get_all() runs array_values() and drops those keys.
     * The logged-in cookie can be matched only against the verifier, and the
     * verifier is never written into the page.
     *
     * @param int   $user_id  Profile user.
     * @param array $sessions Sessions passed by the caller, often from get_all().
     * @return array
     */
    private function sessions_with_verifiers($user_id, $sessions) {
        if ($this->sessions_are_verifier_keyed($sessions)) {
            return $sessions;
        }

        return $this->active_sessions_by_verifier($user_id);
    }

    /**
     * @param array $sessions Session payloads.
     * @return bool
     */
    private function sessions_are_verifier_keyed($sessions) {
        if (!is_array($sessions) || $sessions === []) {
            return false;
        }

        foreach ($sessions as $verifier => $session) {
            if (!is_string($verifier) || !is_array($session) || !preg_match('/\A[a-f0-9]{64}\z/', $verifier)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Active session_tokens rows, still keyed by verifier.
     *
     * Mirrors WP_User_Meta_Session_Tokens::get_sessions(): legacy integer
     * expirations become session arrays, and expired rows are left out.
     * This does not write usermeta.
     *
     * @param int $user_id Profile user.
     * @return array
     */
    private function active_sessions_by_verifier($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1) {
            return [];
        }

        $stored = get_user_meta($user_id, 'session_tokens', true);
        if (!is_array($stored)) {
            return [];
        }

        $sessions = [];
        $now = time();
        foreach ($stored as $verifier => $session) {
            if (is_int($session)) {
                $session = ['expiration' => $session];
            }
            if (!is_array($session)) {
                continue;
            }
            if (!isset($session['expiration']) || (int) $session['expiration'] < $now) {
                continue;
            }

            $sessions[(string) $verifier] = $session;
        }

        return $sessions;
    }

    /**
     * @param int $user_id Profile user.
     * @return string Sha256 verifier for this request's logged-in cookie, or empty.
     */
    private function current_session_verifier($user_id) {
        if ((int) $user_id !== get_current_user_id()) {
            return '';
        }

        $cookie = wp_parse_auth_cookie('', 'logged_in');
        if (!is_array($cookie) || empty($cookie['token']) || !is_string($cookie['token'])) {
            return '';
        }

        return hash('sha256', $cookie['token']);
    }

    /**
     * @param array  $sessions        Session payloads keyed by verifier.
     * @param string $current_verifier Verifier for the operator's own session.
     * @return string
     */
    private function render_session_rows($sessions, $current_verifier) {
        $output = '';

        foreach ((array) $sessions as $verifier => $session) {
            if (!is_array($session)) {
                continue;
            }

            $verifier = (string) $verifier;
            $is_current = (
                $current_verifier !== ''
                && strlen($verifier) === strlen($current_verifier)
                && hash_equals($current_verifier, $verifier)
            );
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
