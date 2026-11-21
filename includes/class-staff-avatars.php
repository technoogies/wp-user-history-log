<?php

/**
 * Optional Gravatar and profile-photo suppression for staff accounts.
 *
 * Off until an operator checks the Settings box. Subscribers, customers,
 * and guests keep the photos WordPress already shows. No new tables.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Staff_Avatars {

    const OPTION_KEY = 'user_history_disable_staff_gravatar';

    /**
     * @var self|null
     */
    private static $instance = null;

    /**
     * Avoid nested avatar lookups while the decision filter runs.
     *
     * @var bool
     */
    private $filtering = false;

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
        add_filter('pre_get_avatar_data', [$this, 'filter_avatar_data'], 100, 2);
        add_filter('get_avatar_data', [$this, 'filter_avatar_data'], 100, 2);
        add_filter('get_avatar', [$this, 'filter_avatar_html'], 100, 6);
    }

    /**
     * Replace a staff avatar URL with a local blank image.
     *
     * @param mixed $args        Avatar arguments from WordPress.
     * @param mixed $id_or_email User ID, email, user, post, or comment.
     * @return mixed
     */
    public function filter_avatar_data($args, $id_or_email) {
        if (!is_array($args) || !$this->should_suppress($id_or_email, $args)) {
            return $args;
        }

        $args['url'] = $this->placeholder_url();
        $args['found_avatar'] = true;

        return $args;
    }

    /**
     * Replace plugin profile-photo markup for a suppressed user.
     *
     * @param mixed $avatar      Existing avatar HTML.
     * @param mixed $id_or_email User ID, email, user, post, or comment.
     * @param mixed $size        Requested size.
     * @param mixed $default     Unused WordPress default.
     * @param mixed $alt         Alt text.
     * @param mixed $args        Avatar arguments, when WordPress passes them.
     * @return mixed
     */
    public function filter_avatar_html($avatar, $id_or_email, $size, $default, $alt, $args = null) {
        $avatar_args = is_array($args) ? $args : [];
        if (!$this->should_suppress($id_or_email, $avatar_args)) {
            return $avatar;
        }

        $dimension = 96;
        if (isset($avatar_args['size'])) {
            $dimension = (int) $avatar_args['size'];
        } elseif (is_numeric($size)) {
            $dimension = (int) $size;
        }
        if ($dimension < 1) {
            $dimension = 96;
        }

        $alt_text = is_string($alt) ? $alt : '';

        return sprintf(
            '<img alt="%1$s" src="%2$s" class="avatar avatar-%3$d photo avatar-default" height="%3$d" width="%3$d" />',
            esc_attr($alt_text),
            esc_url($this->placeholder_url()),
            $dimension
        );
    }

    /**
     * Whether this user's Gravatar or profile photo should be turned off.
     *
     * The filter receives false until the setting is on and the user is staff.
     * Return true to suppress, false to leave the photo alone.
     *
     * @param int $user_id Avatar subject. 0 when the address is not a user.
     * @return bool
     */
    public function should_disable($user_id) {
        $user_id = (int) $user_id;
        $disable = ($user_id > 0 && $this->is_enabled() && $this->is_staff($user_id));

        return (bool) apply_filters('user_history_disable_staff_gravatar', $disable, $user_id);
    }

    /**
     * Staff can edit content or manage the site. Subscribers and customers do not.
     *
     * @param int $user_id User ID.
     * @return bool
     */
    public function is_staff($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1) {
            return false;
        }

        if (is_multisite() && is_super_admin($user_id)) {
            return true;
        }

        $user = get_userdata($user_id);
        if (!$user instanceof WP_User) {
            return false;
        }

        foreach ($this->staff_capabilities() as $capability) {
            if (!empty($user->allcaps[$capability])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return bool
     */
    public function is_enabled() {
        return $this->option_flag_is_enabled(get_option(self::OPTION_KEY, '0'));
    }

    /**
     * @return string Local image. The browser does not contact Gravatar.
     */
    public function placeholder_url() {
        return includes_url('images/blank.gif');
    }

    /**
     * @param mixed                $id_or_email User ID, email, user, post, or comment.
     * @param array<string,mixed>  $args        Avatar arguments.
     * @return bool
     */
    private function should_suppress($id_or_email, $args) {
        if ($this->filtering || !$this->may_disable()) {
            return false;
        }

        $this->filtering = true;
        $disable = $this->should_disable($this->resolve_user_id($id_or_email, $args));
        $this->filtering = false;

        return $disable;
    }

    /**
     * Skip the user lookup when nothing would change the photo.
     *
     * @return bool
     */
    private function may_disable() {
        if ($this->is_enabled()) {
            return true;
        }

        return false !== has_filter('user_history_disable_staff_gravatar');
    }

    /**
     * @param mixed               $id_or_email User ID, email, user, post, or comment.
     * @param array<string,mixed> $args        Avatar arguments.
     * @return int
     */
    private function resolve_user_id($id_or_email, $args) {
        if (isset($args['user_id']) && (int) $args['user_id'] > 0) {
            return (int) $args['user_id'];
        }

        if ($id_or_email instanceof WP_User) {
            return (int) $id_or_email->ID;
        }

        if ($id_or_email instanceof WP_Post) {
            return (int) $id_or_email->post_author;
        }

        if ($id_or_email instanceof WP_Comment) {
            if (!empty($id_or_email->user_id)) {
                return (int) $id_or_email->user_id;
            }

            if (!empty($id_or_email->comment_author_email) && is_email($id_or_email->comment_author_email)) {
                $comment_user = get_user_by('email', $id_or_email->comment_author_email);
                if ($comment_user instanceof WP_User) {
                    return (int) $comment_user->ID;
                }
            }

            return 0;
        }

        if (is_numeric($id_or_email)) {
            return (int) $id_or_email;
        }

        if (is_string($id_or_email) && is_email($id_or_email)) {
            $user = get_user_by('email', $id_or_email);
            if ($user instanceof WP_User) {
                return (int) $user->ID;
            }
        }

        return 0;
    }

    /**
     * Capabilities that mean the account works on the site.
     *
     * @return array<int,string>
     */
    private function staff_capabilities() {
        return [
            'edit_posts',
            'edit_pages',
            'publish_posts',
            'upload_files',
            'moderate_comments',
            'manage_categories',
            'manage_options',
            'edit_users',
            'manage_woocommerce',
        ];
    }

    /**
     * @param mixed $value Stored option or submitted flag.
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
