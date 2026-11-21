<?php

/**
 * Per-user Gravatar and profile-photo control.
 *
 * Unchecked until someone checks that user. Subscribers and staff are the
 * same: only the checked account is blank. No new role and no new tables.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Profile_Photo {

    const META_KEY = 'user_history_disable_gravatar';

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
        add_action('show_user_profile', [$this, 'render_profile_field']);
        add_action('edit_user_profile', [$this, 'render_profile_field']);
        add_action('personal_options_update', [$this, 'save_profile_field']);
        add_action('edit_user_profile_update', [$this, 'save_profile_field']);
        add_filter('pre_get_avatar_data', [$this, 'filter_avatar_data'], 100, 2);
        add_filter('get_avatar_data', [$this, 'filter_avatar_data'], 100, 2);
        add_filter('get_avatar', [$this, 'filter_avatar_html'], 100, 6);
    }

    /**
     * Checkbox on the user's own profile and on Users → Edit user.
     *
     * @param WP_User $user Profile being edited.
     */
    public function render_profile_field($user) {
        if (!$user instanceof WP_User || !$this->current_operator_can_edit((int) $user->ID)) {
            return;
        }

        $checked = $this->user_has_photo_disabled((int) $user->ID);
        ?>
        <h2><?php esc_html_e('Profile photo', 'user-history'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e('Gravatar', 'user-history'); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="<?php echo esc_attr(self::META_KEY); ?>" value="0" />
                        <input type="checkbox" name="<?php echo esc_attr(self::META_KEY); ?>" id="user_history_disable_gravatar" value="1" <?php checked($checked); ?> />
                        <?php esc_html_e('Turn off Gravatar and profile photo for this user', 'user-history'); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e('Unchecked until you check it. Only this user gets a blank image from this site. Other users keep their photos.', 'user-history'); ?>
                    </p>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * Save the checkbox from the profile form. Missing POST leaves the value alone.
     *
     * @param int $user_id Profile being saved.
     */
    public function save_profile_field($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1 || !isset($_POST[self::META_KEY])) {
            return;
        }

        if (!$this->current_operator_can_edit($user_id)) {
            return;
        }

        $disable = $this->flag_is_enabled(wp_unslash($_POST[self::META_KEY]));
        if ($disable) {
            update_user_meta($user_id, self::META_KEY, '1');
            return;
        }

        delete_user_meta($user_id, self::META_KEY);
    }

    /**
     * Replace a disabled user's avatar URL with a local blank image.
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
     * Replace plugin profile-photo markup for a disabled user.
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
     * The filter receives false until that user's checkbox is checked.
     * Return true to suppress, false to leave the photo alone.
     *
     * @param int $user_id Avatar subject. 0 when the address is not a user.
     * @return bool
     */
    public function should_disable($user_id) {
        $user_id = (int) $user_id;
        $disable = $user_id > 0 && $this->user_has_photo_disabled($user_id);

        return (bool) apply_filters('user_history_disable_gravatar', $disable, $user_id);
    }

    /**
     * @param int $user_id User ID.
     * @return bool
     */
    public function user_has_photo_disabled($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1) {
            return false;
        }

        return $this->flag_is_enabled(get_user_meta($user_id, self::META_KEY, true));
    }

    /**
     * @param int $user_id Profile user.
     * @return bool
     */
    public function current_operator_can_edit($user_id) {
        return $user_id > 0 && current_user_can('edit_user', $user_id);
    }

    /**
     * @return string Local image. The browser does not contact Gravatar.
     */
    public function placeholder_url() {
        return includes_url('images/blank.gif');
    }

    /**
     * @param mixed               $id_or_email User ID, email, user, post, or comment.
     * @param array<string,mixed> $args        Avatar arguments.
     * @return bool
     */
    private function should_suppress($id_or_email, $args) {
        if ($this->filtering) {
            return false;
        }

        $this->filtering = true;
        $disable = $this->should_disable($this->resolve_user_id($id_or_email, $args));
        $this->filtering = false;

        return $disable;
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
     * @param mixed $value Stored meta or submitted flag.
     * @return bool
     */
    private function flag_is_enabled($value) {
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
