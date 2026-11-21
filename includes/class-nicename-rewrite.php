<?php

/**
 * Users-screen button that rewrites nicenames still equal to the username.
 *
 * Nothing runs on page load. The toolbar button only counts matches and asks
 * for confirmation. The confirm form is a separate POST with its own nonce.
 * Accounts whose nicename already differs from user_login are skipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Nicename_Rewrite {

    const PREVIEW_ACTION = 'user_history_nicename_rewrite_preview';
    const CONFIRM_ACTION = 'user_history_nicename_rewrite_confirm';
    const NONCE_ACTION = 'user_history_rewrite_login_nicenames';
    const NONCE_FIELD = 'user_history_nicename_rewrite_nonce';
    const PREVIEW_FLAG = 'user_history_nicename_preview';
    const RESULT_FLAG = 'user_history_nicename_rewritten';

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * @var User_History
     */
    private $plugin;

    /**
     * @param User_History|null $plugin Main plugin instance.
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

        add_action('restrict_manage_users', [$this, 'render_users_button']);
        add_action('load-users.php', [$this, 'handle_request']);
        add_action('admin_notices', [$this, 'render_admin_notice']);
    }

    /**
     * People who can edit users, or manage users on a multisite network.
     *
     * On multisite, WordPress maps edit_users to manage_network_users.
     * A subsite administrator without that capability cannot rewrite nicenames.
     *
     * @return bool
     */
    public function current_operator_can_rewrite() {
        if (!is_user_logged_in()) {
            return false;
        }

        if (current_user_can('edit_users')) {
            return true;
        }

        return is_multisite() && current_user_can('manage_network_users');
    }

    /**
     * Toolbar control on wp-admin/users.php. Top of the list only.
     *
     * @param string $which "top" or "bottom".
     */
    public function render_users_button($which) {
        if ($which !== 'top' || !$this->is_site_users_screen() || !$this->current_operator_can_rewrite()) {
            return;
        }

        wp_nonce_field(self::NONCE_ACTION, self::NONCE_FIELD, false, true);
        ?>
        <button
            type="submit"
            name="<?php echo esc_attr(self::PREVIEW_ACTION); ?>"
            value="1"
            class="button user-history-rewrite-nicenames"
        >
            <?php esc_html_e('Rewrite matching nicenames', 'user-history'); ?>
        </button>
        <?php
    }

    /**
     * Count on the first POST. Rewrite only after the confirm POST.
     */
    public function handle_request() {
        if (!$this->is_site_users_screen() || !$this->is_post_request()) {
            return;
        }

        $preview = isset($_POST[self::PREVIEW_ACTION]);
        $confirm = isset($_POST[self::CONFIRM_ACTION]);
        if (!$preview && !$confirm) {
            return;
        }

        if (!$this->current_operator_can_rewrite()) {
            wp_die(
                esc_html__('You are not allowed to rewrite nicenames.', 'user-history'),
                '',
                ['response' => 403]
            );
        }

        $nonce = isset($_POST[self::NONCE_FIELD])
            ? sanitize_text_field(wp_unslash($_POST[self::NONCE_FIELD]))
            : '';
        if (!wp_verify_nonce($nonce, self::NONCE_ACTION)) {
            wp_die(
                esc_html__('The nicename rewrite request could not be verified. Reload Users and try again.', 'user-history'),
                '',
                ['response' => 403]
            );
        }

        if ($confirm) {
            $result = $this->rewrite_matching_nicenames();
            delete_transient($this->preview_transient_key());
            set_transient($this->result_transient_key(), $result, MINUTE_IN_SECONDS);
            $this->redirect_to_users([self::RESULT_FLAG => '1']);
            return;
        }

        set_transient($this->preview_transient_key(), '1', MINUTE_IN_SECONDS);
        $this->redirect_to_users([self::PREVIEW_FLAG => '1']);
    }

    /**
     * Confirm step, then the changed and skipped counts.
     */
    public function render_admin_notice() {
        if (!$this->is_site_users_screen() || !$this->current_operator_can_rewrite()) {
            return;
        }

        $this->render_result_notice();
        $this->render_preview_notice();
    }

    /**
     * Read-only counts for the current site.
     *
     * @return array{matches:int,skipped:int}
     */
    public function summarize() {
        $matches = 0;
        $skipped = 0;

        if (!$this->current_operator_can_rewrite()) {
            return [
                'matches' => 0,
                'skipped' => 0,
            ];
        }

        $generator = $this->generator();
        $this->each_site_user(function ($user) use ($generator, &$matches, &$skipped) {
            $class = $this->classify_user($user, $generator);
            if ($class === 'match') {
                $matches++;
                return;
            }
            if ($class === 'skipped') {
                $skipped++;
            }
        });

        return [
            'matches' => $matches,
            'skipped' => $skipped,
        ];
    }

    /**
     * Update nicenames that still equal the username.
     *
     * @return array{changed:int,skipped:int}
     */
    public function rewrite_matching_nicenames() {
        $changed = 0;
        $skipped = 0;

        if (!$this->current_operator_can_rewrite()) {
            return [
                'changed' => 0,
                'skipped' => 0,
            ];
        }

        $generator = $this->generator();
        $this->each_site_user(function ($user) use ($generator, &$changed, &$skipped) {
            $class = $this->classify_user($user, $generator);
            if ($class === 'skipped') {
                $skipped++;
                return;
            }
            if ($class !== 'match') {
                return;
            }

            $old = (string) $user->user_nicename;
            $new = $generator->nicename_for_existing_user($user);
            if ($new === '' || $new === $old || $generator->nicename_matches_login($new, $user->user_login)) {
                return;
            }

            $result = wp_update_user(
                [
                    'ID'            => (int) $user->ID,
                    'user_nicename' => $new,
                ]
            );
            if (is_wp_error($result)) {
                return;
            }

            clean_user_cache((int) $user->ID);
            $fresh = get_userdata((int) $user->ID);
            if (
                $fresh instanceof WP_User
                && (string) $fresh->user_nicename !== $old
                && !$generator->nicename_matches_login($fresh->user_nicename, $fresh->user_login)
            ) {
                $changed++;
            }
        });

        return [
            'changed' => $changed,
            'skipped' => $skipped,
        ];
    }

    /**
     * @param int $matches Users whose nicename still matches the username.
     * @param int $skipped Users whose nicename already differs.
     * @return string
     */
    public function preview_message($matches, $skipped) {
        $matches = (int) $matches;
        $skipped = (int) $skipped;

        $match_text = sprintf(
            _n(
                '%d user still has a nicename that matches their username.',
                '%d users still have a nicename that matches their username.',
                $matches,
                'user-history'
            ),
            $matches
        );
        $skip_text = sprintf(
            _n(
                '%d user already has a different nicename and will be skipped.',
                '%d users already have a different nicename and will be skipped.',
                $skipped,
                'user-history'
            ),
            $skipped
        );

        return $match_text . ' ' . $skip_text . ' ' . __('Usernames are not changed.', 'user-history');
    }

    /**
     * @param int $changed Nicenames written.
     * @param int $skipped Accounts left alone because the nicename already differed.
     * @return string
     */
    public function result_message($changed, $skipped) {
        $changed = (int) $changed;
        $skipped = (int) $skipped;

        $changed_text = sprintf(
            _n(
                'Updated %d nicename.',
                'Updated %d nicenames.',
                $changed,
                'user-history'
            ),
            $changed
        );
        $skipped_text = sprintf(
            _n(
                'Skipped %d account that already differed from the username.',
                'Skipped %d accounts that already differed from the username.',
                $skipped,
                'user-history'
            ),
            $skipped
        );

        return $changed_text . ' ' . $skipped_text;
    }

    /**
     * @param WP_User                      $user      Site user.
     * @param User_History_New_User_Nicename $generator Nicename rules.
     * @return string match, skipped, or ignore
     */
    private function classify_user($user, $generator) {
        if (!$user instanceof WP_User) {
            return 'ignore';
        }

        if (!$generator->nicename_matches_login($user->user_nicename, $user->user_login)) {
            return 'skipped';
        }

        if (!$this->operator_can_edit_user((int) $user->ID)) {
            return 'ignore';
        }

        return 'match';
    }

    /**
     * @param callable $callback Receives a WP_User.
     */
    private function each_site_user($callback) {
        $page = 1;
        $per_page = 200;

        do {
            $users = get_users(
                [
                    'blog_id'     => get_current_blog_id(),
                    'number'      => $per_page,
                    'paged'       => $page,
                    'orderby'     => 'ID',
                    'order'       => 'ASC',
                    'count_total' => false,
                ]
            );

            if (!is_array($users) || !$users) {
                break;
            }

            foreach ($users as $user) {
                if ($user instanceof WP_User) {
                    $callback($user);
                }
            }

            $found = count($users);
            $page++;
        } while ($found === $per_page && $page < 10000);
    }

    /**
     * @param int $user_id User ID.
     * @return bool
     */
    private function operator_can_edit_user($user_id) {
        return is_user_logged_in() && current_user_can('edit_user', (int) $user_id);
    }

    /**
     * @return User_History_New_User_Nicename
     */
    private function generator() {
        return User_History_New_User_Nicename::get_instance($this->plugin);
    }

    /**
     * @return bool
     */
    private function is_site_users_screen() {
        if (is_network_admin()) {
            return false;
        }

        global $pagenow;

        return isset($pagenow) && $pagenow === 'users.php';
    }

    /**
     * @return bool
     */
    private function is_post_request() {
        if (!isset($_SERVER['REQUEST_METHOD'])) {
            return false;
        }

        return strtoupper((string) wp_unslash($_SERVER['REQUEST_METHOD'])) === 'POST';
    }

    private function render_result_notice() {
        if (!isset($_GET[self::RESULT_FLAG])) {
            return;
        }

        $result = get_transient($this->result_transient_key());
        delete_transient($this->result_transient_key());
        if (!is_array($result) || !isset($result['changed'], $result['skipped'])) {
            return;
        }

        $message = $this->result_message((int) $result['changed'], (int) $result['skipped']);
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';
    }

    private function render_preview_notice() {
        if (!isset($_GET[self::PREVIEW_FLAG])) {
            return;
        }

        if (get_transient($this->preview_transient_key()) === false) {
            return;
        }

        $summary = $this->summarize();
        $message = $this->preview_message($summary['matches'], $summary['skipped']);
        $confirm = __('Update nicenames that are still the same as the username? Accounts that already have a different nicename are skipped.', 'user-history');
        ?>
        <div class="notice notice-warning">
            <p><?php echo esc_html($message); ?></p>
            <?php if ($summary['matches'] > 0) : ?>
                <form method="post" action="<?php echo esc_url(admin_url('users.php')); ?>">
                    <?php wp_nonce_field(self::NONCE_ACTION, self::NONCE_FIELD, false, true); ?>
                    <input type="hidden" name="<?php echo esc_attr(self::CONFIRM_ACTION); ?>" value="1" />
                    <p>
                        <button
                            type="submit"
                            class="button button-primary"
                            data-confirm="<?php echo esc_attr($confirm); ?>"
                            onclick="return window.confirm(this.getAttribute('data-confirm'));"
                        >
                            <?php esc_html_e('Update matching nicenames', 'user-history'); ?>
                        </button>
                    </p>
                </form>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * @param array<string,string> $args Query arguments.
     */
    private function redirect_to_users($args) {
        $url = add_query_arg($args, admin_url('users.php'));
        wp_safe_redirect($url);

        if (!function_exists('tests_add_filter')) {
            exit;
        }
    }

    /**
     * @return string
     */
    private function preview_transient_key() {
        return 'uh_nicename_preview_' . get_current_user_id();
    }

    /**
     * @return string
     */
    private function result_transient_key() {
        return 'uh_nicename_result_' . get_current_user_id();
    }
}
