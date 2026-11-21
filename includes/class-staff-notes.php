<?php

/**
 * Private staff notes and tags on a user.
 *
 * One note meta value, plus one meta key with one row per tag.
 * No new table. Visible only to people who can edit users.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_Staff_Notes {

    const META_NOTE = 'user_history_staff_note';
    const META_TAG = 'user_history_staff_tag';
    const TAGS_INPUT = 'user_history_staff_tags';
    const QUERY_ARG = 'user_history_tag';
    const MAX_NOTE_LENGTH = 5000;
    const MAX_TAG_LENGTH = 40;
    const MAX_TAGS = 20;
    const MAX_TAG_VIEWS = 40;

    /**
     * @var self|null
     */
    private static $instance = null;

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
        add_action('show_user_profile', [$this, 'render_profile_fields'], 15);
        add_action('edit_user_profile', [$this, 'render_profile_fields'], 15);
        add_action('personal_options_update', [$this, 'save_profile_fields']);
        add_action('edit_user_profile_update', [$this, 'save_profile_fields']);
        add_filter('views_users', [$this, 'add_tag_views']);
        add_action('restrict_manage_users', [$this, 'preserve_tag_query_arg']);
        add_filter('users_list_table_query_args', [$this, 'filter_list_table_args']);
        add_filter('wp_privacy_personal_data_exporters', [$this, 'register_exporter']);
        add_filter('wp_privacy_personal_data_erasers', [$this, 'register_eraser']);
    }

    /**
     * Staff note and tags. Hidden from the account holder.
     *
     * @param WP_User $user Profile being edited.
     */
    public function render_profile_fields($user) {
        if (!$user instanceof WP_User || !$this->current_operator_can_manage((int) $user->ID)) {
            return;
        }

        $user_id = (int) $user->ID;
        $tags = $this->get_tags($user_id);
        ?>
        <h2><?php esc_html_e('Staff notes', 'user-history'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">
                    <label for="user_history_staff_note"><?php esc_html_e('Staff note', 'user-history'); ?></label>
                </th>
                <td>
                    <textarea
                        name="<?php echo esc_attr(self::META_NOTE); ?>"
                        id="user_history_staff_note"
                        rows="6"
                        class="large-text"
                    ><?php echo esc_textarea($this->get_note($user_id)); ?></textarea>
                    <p class="description">
                        <?php esc_html_e('Only people who can edit users can see or change this. Someone who cannot edit users does not see it, including on their own profile.', 'user-history'); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row">
                    <label for="user_history_staff_tags"><?php esc_html_e('Tags', 'user-history'); ?></label>
                </th>
                <td>
                    <input
                        type="text"
                        name="<?php echo esc_attr(self::TAGS_INPUT); ?>"
                        id="user_history_staff_tags"
                        class="regular-text"
                        value="<?php echo esc_attr(implode(', ', $tags)); ?>"
                    />
                    <p class="description">
                        <?php esc_html_e('Comma-separated labels, such as vip, needs follow up. Users then has a filter for each tag. Saved tags use short labels like needs-follow-up.', 'user-history'); ?>
                    </p>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * Save from the profile form. A missing field leaves the stored value alone.
     *
     * @param int $user_id Profile being saved.
     */
    public function save_profile_fields($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1 || !$this->current_operator_can_manage($user_id)) {
            return;
        }

        if (isset($_POST[self::META_NOTE]) && is_string($_POST[self::META_NOTE])) {
            $this->store_note($user_id, wp_unslash($_POST[self::META_NOTE]));
        }

        if (isset($_POST[self::TAGS_INPUT]) && is_string($_POST[self::TAGS_INPUT])) {
            $this->store_tags($user_id, wp_unslash($_POST[self::TAGS_INPUT]));
        }
    }

    /**
     * Tag links above All Users, same pattern as the Locked view.
     *
     * @param array<string,string> $views Existing view links.
     * @return array<string,string>
     */
    public function add_tag_views($views) {
        if (!is_array($views) || !$this->is_site_users_screen() || !$this->current_operator_can_filter()) {
            return $views;
        }

        $counts = $this->tag_counts();
        if ($counts === []) {
            return $views;
        }

        $current = $this->requested_tag();
        if (count($counts) > self::MAX_TAG_VIEWS) {
            $shown = array_slice($counts, 0, self::MAX_TAG_VIEWS, true);
            if ($current !== '' && !isset($shown[$current]) && isset($counts[$current])) {
                $shown[$current] = $counts[$current];
            }
            $counts = $shown;
        }

        foreach ($counts as $tag => $total) {
            $views['user_history_tag_' . $tag] = sprintf(
                '<a href="%1$s" class="%2$s">%3$s <span class="count">(%4$d)</span></a>',
                esc_url(add_query_arg(self::QUERY_ARG, $tag, admin_url('users.php'))),
                $current === $tag ? 'current' : '',
                esc_html(
                    sprintf(
                        /* translators: %s: staff tag */
                        __('Tag: %s', 'user-history'),
                        $tag
                    )
                ),
                (int) $total
            );
        }

        return $views;
    }

    /**
     * Keep the current tag when the Users search form is submitted.
     *
     * @param string $which "top" or "bottom".
     */
    public function preserve_tag_query_arg($which) {
        if ($which !== 'top' || !$this->is_site_users_screen() || !$this->current_operator_can_filter()) {
            return;
        }

        $tag = $this->requested_tag();
        if ($tag === '') {
            return;
        }

        echo '<input type="hidden" name="' . esc_attr(self::QUERY_ARG) . '" value="' . esc_attr($tag) . '" />';
    }

    /**
     * Limit the All Users list to one tag. Other user queries are left alone.
     *
     * @param mixed $args Arguments for the users list table.
     * @return mixed
     */
    public function filter_list_table_args($args) {
        if (!is_array($args) || !$this->is_site_users_screen() || !$this->current_operator_can_filter()) {
            return $args;
        }

        $tag = $this->requested_tag();
        if ($tag === '') {
            return $args;
        }

        if (!isset($args['meta_query']) || !is_array($args['meta_query'])) {
            $args['meta_query'] = [];
        }

        $args['meta_query'][] = [
            'key'     => self::META_TAG,
            'value'   => $tag,
            'compare' => '=',
        ];

        return $args;
    }

    /**
     * @param array<string,array<string,mixed>> $exporters Exporters.
     * @return array<string,array<string,mixed>>
     */
    public function register_exporter($exporters) {
        if (!is_array($exporters)) {
            $exporters = [];
        }

        $exporters['user-history-staff-notes'] = [
            'exporter_friendly_name' => __('Staff notes', 'user-history'),
            'callback'               => [$this, 'export_personal_data'],
        ];

        return $exporters;
    }

    /**
     * @param array<string,array<string,mixed>> $erasers Erasers.
     * @return array<string,array<string,mixed>>
     */
    public function register_eraser($erasers) {
        if (!is_array($erasers)) {
            $erasers = [];
        }

        $erasers['user-history-staff-notes'] = [
            'eraser_friendly_name' => __('Staff notes', 'user-history'),
            'callback'             => [$this, 'erase_personal_data'],
        ];

        return $erasers;
    }

    /**
     * @param string $email_address User email.
     * @param int    $page          Page number. Notes fit on one page.
     * @return array{data:array<int,array<string,mixed>>,done:bool}
     */
    public function export_personal_data($email_address, $page = 1) {
        unset($page);

        $user = get_user_by('email', $email_address);
        if (!$user instanceof WP_User) {
            return [
                'data' => [],
                'done' => true,
            ];
        }

        $user_id = (int) $user->ID;
        $note = $this->get_note($user_id);
        $tags = $this->get_tags($user_id);
        if ($note === '' && $tags === []) {
            return [
                'data' => [],
                'done' => true,
            ];
        }

        return [
            'data' => [
                [
                    'group_id'    => 'user-history-staff-notes',
                    'group_label' => __('Staff notes', 'user-history'),
                    'item_id'     => 'user-history-staff-notes-' . $user_id,
                    'data'        => [
                        [
                            'name'  => __('Note', 'user-history'),
                            'value' => $note,
                        ],
                        [
                            'name'  => __('Tags', 'user-history'),
                            'value' => implode(', ', $tags),
                        ],
                    ],
                ],
            ],
            'done' => true,
        ];
    }

    /**
     * Remove the note and tags. Account history is a separate eraser.
     *
     * @param string $email_address User email.
     * @param int    $page          Unused page number.
     * @return array{items_removed:bool,items_retained:bool,messages:array<int,string>,done:bool}
     */
    public function erase_personal_data($email_address, $page = 1) {
        unset($page);

        $user = get_user_by('email', $email_address);
        if (!$user instanceof WP_User) {
            return [
                'items_removed'  => false,
                'items_retained' => false,
                'messages'       => [],
                'done'           => true,
            ];
        }

        $user_id = (int) $user->ID;
        $removed = false;

        if ($this->get_note($user_id) !== '') {
            delete_user_meta($user_id, self::META_NOTE);
            $removed = true;
        }

        if ($this->get_tags($user_id) !== []) {
            delete_user_meta($user_id, self::META_TAG);
            $removed = true;
        }

        return [
            'items_removed'  => $removed,
            'items_retained' => false,
            'messages'       => [],
            'done'           => true,
        ];
    }

    /**
     * People who can edit users, and who can edit this account.
     * Editing your own profile is not enough.
     *
     * @param int $user_id Profile user.
     * @return bool
     */
    public function current_operator_can_manage($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1 || !is_user_logged_in()) {
            return false;
        }

        if (!current_user_can('edit_user', $user_id)) {
            return false;
        }

        if (current_user_can('edit_users')) {
            return true;
        }

        return is_multisite() && current_user_can('manage_network_users');
    }

    /**
     * @param int $user_id User ID.
     * @return string
     */
    public function get_note($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1) {
            return '';
        }

        $note = get_user_meta($user_id, self::META_NOTE, true);
        if (!is_string($note)) {
            return '';
        }

        return $note;
    }

    /**
     * @param int $user_id User ID.
     * @return array<int,string>
     */
    public function get_tags($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1) {
            return [];
        }

        $values = get_user_meta($user_id, self::META_TAG, false);
        if (!is_array($values)) {
            return [];
        }

        $tags = [];
        foreach ($values as $value) {
            $tag = $this->sanitize_tag($value);
            if ($tag === '' || in_array($tag, $tags, true)) {
                continue;
            }
            $tags[] = $tag;
        }

        return $tags;
    }

    /**
     * Tag from the All Users query string. Empty when it is missing or not a tag.
     *
     * @return string
     */
    public function requested_tag() {
        if (!isset($_GET[self::QUERY_ARG]) || is_array($_GET[self::QUERY_ARG])) {
            return '';
        }

        return $this->sanitize_tag(wp_unslash($_GET[self::QUERY_ARG]));
    }

    /**
     * @return bool
     */
    private function current_operator_can_filter() {
        if (!is_user_logged_in()) {
            return false;
        }

        if (current_user_can('edit_users')) {
            return true;
        }

        return is_multisite() && current_user_can('manage_network_users');
    }

    /**
     * @param int    $user_id User ID.
     * @param string $raw     Submitted note.
     */
    private function store_note($user_id, $raw) {
        $note = $this->sanitize_note($raw);
        if ($this->get_note($user_id) === $note) {
            return;
        }

        if ($note === '') {
            delete_user_meta($user_id, self::META_NOTE);
            return;
        }

        update_user_meta($user_id, self::META_NOTE, $note);
    }

    /**
     * @param int    $user_id User ID.
     * @param string $raw     Comma-separated tags.
     */
    private function store_tags($user_id, $raw) {
        $tags = $this->parse_tags($raw);
        if ($this->get_tags($user_id) === $tags) {
            return;
        }

        delete_user_meta($user_id, self::META_TAG);
        foreach ($tags as $tag) {
            add_user_meta($user_id, self::META_TAG, $tag, false);
        }
    }

    /**
     * @param string $raw Submitted note.
     * @return string
     */
    private function sanitize_note($raw) {
        $note = sanitize_textarea_field((string) $raw);
        if (function_exists('mb_substr')) {
            return mb_substr($note, 0, self::MAX_NOTE_LENGTH);
        }

        return substr($note, 0, self::MAX_NOTE_LENGTH);
    }

    /**
     * @param string $raw Comma-separated tags.
     * @return array<int,string>
     */
    private function parse_tags($raw) {
        $parts = preg_split('/\s*,\s*/', (string) $raw);
        if (!is_array($parts)) {
            return [];
        }

        $tags = [];
        foreach ($parts as $part) {
            if (count($tags) >= self::MAX_TAGS) {
                break;
            }

            $tag = $this->sanitize_tag($part);
            if ($tag === '' || in_array($tag, $tags, true)) {
                continue;
            }

            $tags[] = $tag;
        }

        return $tags;
    }

    /**
     * @param mixed $raw Tag text.
     * @return string
     */
    private function sanitize_tag($raw) {
        $tag = remove_accents((string) $raw);
        $tag = strtolower($tag);
        $tag = preg_replace('/[^a-z0-9]+/', '-', $tag);
        $tag = trim((string) $tag, '-');
        if ($tag === '' || strlen($tag) > self::MAX_TAG_LENGTH) {
            return '';
        }

        return $tag;
    }

    /**
     * @return array<string,int> Tag => users on this site.
     */
    private function tag_counts() {
        global $wpdb;

        $cap_key = $wpdb->get_blog_prefix() . 'capabilities';
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT t.meta_value AS meta_value, COUNT(DISTINCT t.user_id) AS total
                FROM {$wpdb->usermeta} t
                INNER JOIN {$wpdb->usermeta} c
                    ON c.user_id = t.user_id
                    AND c.meta_key = %s
                WHERE t.meta_key = %s
                GROUP BY t.meta_value
                ORDER BY t.meta_value ASC",
                $cap_key,
                self::META_TAG
            ),
            ARRAY_A
        );

        $counts = [];
        foreach ((array) $rows as $row) {
            if (!is_array($row) || !isset($row['meta_value'])) {
                continue;
            }

            $tag = $this->sanitize_tag($row['meta_value']);
            if ($tag === '') {
                continue;
            }

            if (!isset($counts[$tag])) {
                $counts[$tag] = 0;
            }
            $counts[$tag] += isset($row['total']) ? (int) $row['total'] : 0;
        }

        ksort($counts);

        return $counts;
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
}
