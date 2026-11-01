<?php
/**
 * Site-wide Activity Log for User History.
 *
 * Ported from upstream activity-log. Storage is InnoDB, the feature stays
 * off until enabled, and cleanup reuses the existing daily prune hook.
 *
 * A lightweight site-wide log of actions performed by users: content
 * changes, media, comments, user management, logins, plugin/theme/core
 * changes and settings changes. Entries live in a dedicated table and are
 * shown under User History > Activity Log.
 *
 * @package UserHistory
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Records and reads activity log entries.
 *
 * Every entry stores a machine-readable `action` key plus the object it
 * concerns (`object_type`, `object_id`, `object_name`) and an optional
 * `context` array (JSON). Human-readable descriptions are built at display
 * time by describe(), so stored rows stay language-neutral.
 */
class User_History_Activity_Log {

    /**
     * Database table name (without prefix).
     */
    const TABLE_NAME = 'user_activity_log';
    const MENU_SLUG = 'user-history-activity-log';
    const OPTION_ENABLED = 'user_history_activity_log_enabled';
    const OPTION_EVENTS = 'user_history_activity_log_events';
    const PER_PAGE_OPTION = 'user_history_activity_per_page';
    const CLEAR_ACTION = 'user_history_clear_activity_log';
    const CLEAR_NONCE = 'user_history_clear_activity_log';

    /**
     * Main plugin instance.
     *
     * @var User_History
     */
    private $plugin;

    /**
     * Post IDs already logged during this request (avoids duplicate
     * "created" + "updated" rows for the same save).
     *
     * @var array
     */
    private $logged_posts = [];

    /**
     * User IDs created during this request (their follow-up profile_update
     * and set_user_role calls are part of creation, not separate events).
     *
     * @var array
     */
    private $created_users = [];

    /**
     * @var self|null
     */
    private static $instance = null;

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

        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'register_screen_options']);
        add_filter('set-screen-option', [$this, 'save_screen_option'], 10, 3);
        add_filter('option_page_capability_' . User_History_Settings::OPTION_GROUP, [$this, 'settings_capability']);
        add_action('wp_ajax_' . self::CLEAR_ACTION, [$this, 'ajax_clear']);

        // Event hooks stay registered so enabling the log takes effect without a reload.
        add_action('transition_post_status', [$this, 'on_transition_post_status'], 10, 3);
        add_action('post_updated', [$this, 'on_post_updated'], 10, 3);
        add_action('wp_after_insert_post', [$this, 'on_after_insert_post']);
        add_action('deleted_post', [$this, 'on_deleted_post'], 10, 2);
        add_action('created_term', [$this, 'on_created_term'], 10, 3);
        add_action('edited_term', [$this, 'on_edited_term'], 10, 3);
        add_action('delete_term', [$this, 'on_delete_term'], 10, 4);
        add_action('add_attachment', [$this, 'on_add_attachment']);
        add_action('attachment_updated', [$this, 'on_attachment_updated'], 10, 3);
        add_action('delete_attachment', [$this, 'on_delete_attachment'], 10, 2);
        add_action('wp_insert_comment', [$this, 'on_insert_comment'], 10, 2);
        add_action('transition_comment_status', [$this, 'on_transition_comment_status'], 10, 3);
        add_action('delete_comment', [$this, 'on_delete_comment'], 10, 2);
        add_action('user_register', [$this, 'on_user_register'], 10, 2);
        add_action('deleted_user', [$this, 'on_deleted_user'], 10, 3);
        add_action('profile_update', [$this, 'on_profile_update'], 10, 3);
        add_action('set_user_role', [$this, 'on_set_user_role'], 10, 3);
        add_action('after_password_reset', [$this, 'on_password_reset']);
        add_action('user_history_username_changed', [$this, 'on_username_changed'], 10, 3);
        add_action('user_history_user_locked', [$this, 'on_user_locked']);
        add_action('user_history_user_unlocked', [$this, 'on_user_unlocked']);
        add_action('wp_login', [$this, 'on_login'], 10, 2);
        add_action('wp_logout', [$this, 'on_logout']);
        add_action('wp_login_failed', [$this, 'on_login_failed']);
        add_action('activated_plugin', [$this, 'on_activated_plugin'], 10, 2);
        add_action('deactivated_plugin', [$this, 'on_deactivated_plugin'], 10, 2);
        add_action('deleted_plugin', [$this, 'on_deleted_plugin'], 10, 2);
        add_action('upgrader_process_complete', [$this, 'on_upgrader_process_complete'], 10, 2);
        add_action('switch_theme', [$this, 'on_switch_theme'], 10, 3);
        add_action('deleted_theme', [$this, 'on_deleted_theme'], 10, 2);
        add_action('_core_updated_successfully', [$this, 'on_core_updated']);
        add_action('updated_option', [$this, 'on_updated_option'], 10, 3);
    }

    /**
     * @return string
     */
    public function settings_capability() {
        return User_History::CLEAR_HISTORY_CAPABILITY;
    }

    // =========================================================================
    // Settings helpers
    // =========================================================================

    /**
     * Whether the activity log is enabled.
     *
     * @return bool
     */
    public function is_enabled() {
        return $this->option_flag_is_enabled(get_option(self::OPTION_ENABLED, '0'));
    }

    /**
     * Event group slugs (translation-free, safe to call before `init`).
     *
     * @return string[]
     */
    public static function get_event_group_slugs() {
        return ['content', 'media', 'comments', 'users', 'logins', 'extensions', 'settings'];
    }

    /**
     * Available event groups (used by the settings UI and the log filter).
     *
     * @return array Group labels keyed by group slug.
     */
    public static function get_event_groups() {
        return [
            'content'    => __('Content (posts, pages, custom post types, categories & tags)', 'user-history'),
            'media'      => __('Media (uploads)', 'user-history'),
            'comments'   => __('Comments', 'user-history'),
            'users'      => __('Users (created, deleted, profile & role changes, locks)', 'user-history'),
            'logins'     => __('Logins (successful, failed, logouts)', 'user-history'),
            'extensions' => __('Plugins, themes & WordPress core', 'user-history'),
            'settings'   => __('Settings changes', 'user-history'),
        ];
    }

    /**
     * Enabled event groups.
     *
     * @return string[]
     */
    public function get_enabled_groups() {
        $all    = self::get_event_group_slugs();
        $groups = get_option(self::OPTION_EVENTS, $all);

        if (!is_array($groups)) {
            return $all;
        }

        return array_values(array_intersect($all, $groups));
    }

    /**
     * Map of action keys to their event group.
     *
     * @return array
     */
    public static function get_action_groups() {
        return [
            'post_created'         => 'content',
            'post_updated'         => 'content',
            'post_published'       => 'content',
            'post_unpublished'     => 'content',
            'post_trashed'         => 'content',
            'post_restored'        => 'content',
            'post_deleted'         => 'content',
            'term_created'         => 'content',
            'term_updated'         => 'content',
            'term_deleted'         => 'content',
            'attachment_uploaded'  => 'media',
            'attachment_updated'   => 'media',
            'attachment_deleted'   => 'media',
            'comment_created'      => 'comments',
            'comment_approved'     => 'comments',
            'comment_unapproved'   => 'comments',
            'comment_spammed'      => 'comments',
            'comment_trashed'      => 'comments',
            'comment_restored'     => 'comments',
            'comment_deleted'      => 'comments',
            'user_registered'      => 'users',
            'user_created'         => 'users',
            'user_deleted'         => 'users',
            'user_updated'         => 'users',
            'user_role_changed'    => 'users',
            'user_password_reset'  => 'users',
            'username_changed'     => 'users',
            'user_locked'          => 'users',
            'user_unlocked'        => 'users',
            'user_login'           => 'logins',
            'user_logout'          => 'logins',
            'login_failed'         => 'logins',
            'plugin_activated'     => 'extensions',
            'plugin_deactivated'   => 'extensions',
            'plugin_installed'     => 'extensions',
            'plugin_updated'       => 'extensions',
            'plugin_deleted'       => 'extensions',
            'theme_switched'       => 'extensions',
            'theme_installed'      => 'extensions',
            'theme_updated'        => 'extensions',
            'theme_deleted'        => 'extensions',
            'core_updated'         => 'extensions',
            'option_updated'       => 'settings',
        ];
    }

    /**
     * Human-readable labels for action keys (used in the filter dropdown).
     *
     * @return array
     */
    public static function get_action_labels() {
        return [
            'post_created'         => __('Content created', 'user-history'),
            'post_updated'         => __('Content updated', 'user-history'),
            'post_published'       => __('Content published', 'user-history'),
            'post_unpublished'     => __('Content unpublished', 'user-history'),
            'post_trashed'         => __('Content trashed', 'user-history'),
            'post_restored'        => __('Content restored', 'user-history'),
            'post_deleted'         => __('Content deleted', 'user-history'),
            'term_created'         => __('Term created', 'user-history'),
            'term_updated'         => __('Term updated', 'user-history'),
            'term_deleted'         => __('Term deleted', 'user-history'),
            'attachment_uploaded'  => __('File uploaded', 'user-history'),
            'attachment_updated'   => __('File updated', 'user-history'),
            'attachment_deleted'   => __('File deleted', 'user-history'),
            'comment_created'      => __('Comment posted', 'user-history'),
            'comment_approved'     => __('Comment approved', 'user-history'),
            'comment_unapproved'   => __('Comment unapproved', 'user-history'),
            'comment_spammed'      => __('Comment marked as spam', 'user-history'),
            'comment_trashed'      => __('Comment trashed', 'user-history'),
            'comment_restored'     => __('Comment restored', 'user-history'),
            'comment_deleted'      => __('Comment deleted', 'user-history'),
            'user_registered'      => __('User registered', 'user-history'),
            'user_created'         => __('User created', 'user-history'),
            'user_deleted'         => __('User deleted', 'user-history'),
            'user_updated'         => __('Profile updated', 'user-history'),
            'user_role_changed'    => __('Role changed', 'user-history'),
            'user_password_reset'  => __('Password reset', 'user-history'),
            'username_changed'     => __('Username changed', 'user-history'),
            'user_locked'          => __('Account locked', 'user-history'),
            'user_unlocked'        => __('Account unlocked', 'user-history'),
            'user_login'           => __('Login', 'user-history'),
            'user_logout'          => __('Logout', 'user-history'),
            'login_failed'         => __('Failed login', 'user-history'),
            'plugin_activated'     => __('Plugin activated', 'user-history'),
            'plugin_deactivated'   => __('Plugin deactivated', 'user-history'),
            'plugin_installed'     => __('Plugin installed', 'user-history'),
            'plugin_updated'       => __('Plugin updated', 'user-history'),
            'plugin_deleted'       => __('Plugin deleted', 'user-history'),
            'theme_switched'       => __('Theme switched', 'user-history'),
            'theme_installed'      => __('Theme installed', 'user-history'),
            'theme_updated'        => __('Theme updated', 'user-history'),
            'theme_deleted'        => __('Theme deleted', 'user-history'),
            'core_updated'         => __('WordPress updated', 'user-history'),
            'option_updated'       => __('Setting changed', 'user-history'),
        ];
    }

    // =========================================================================
    // Writing
    // =========================================================================

    /**
     * Record an activity log entry.
     *
     * @param string $action      Action key (see get_action_groups()).
     * @param string $object_type Object type (post, attachment, term, comment, user, plugin, theme, core, option).
     * @param int    $object_id   Object ID (0 if not applicable).
     * @param string $object_name Object name/title at the time of the event.
     * @param array  $context     Optional extra data (stored as JSON).
     * @param int    $user_id     Acting user ID. Defaults to the current user.
     * @return int|false Inserted row ID or false.
     */
    public function log($action, $object_type, $object_id = 0, $object_name = '', $context = [], $user_id = null) {
        global $wpdb;

        if (!$this->should_record_action($action)) {
            return false;
        }

        if ($user_id === null) {
            $user_id = get_current_user_id();
        }

        $entry = [
            'user_id'     => (int) $user_id,
            'action'      => (string) $action,
            'object_type' => (string) $object_type,
            'object_id'   => (int) $object_id,
            'object_name' => mb_substr(wp_strip_all_tags((string) $object_name), 0, 255),
            'context'     => is_array($context) ? $context : [],
        ];

        if (defined('WP_CLI') && WP_CLI) {
            $entry['context']['via'] = 'wp-cli';
        } elseif (wp_doing_cron()) {
            $entry['context']['via'] = 'cron';
        } elseif (defined('REST_REQUEST') && REST_REQUEST) {
            $entry['context']['via'] = 'rest';
        }

        /**
         * Filter an activity log entry before it is saved.
         *
         * Return false (or an empty value) to skip logging.
         *
         * @param array $entry {
         *     @type int    $user_id     Acting user ID.
         *     @type string $action      Action key.
         *     @type string $object_type Object type.
         *     @type int    $object_id   Object ID.
         *     @type string $object_name Object name.
         *     @type array  $context     Extra data.
         * }
         */
        $entry = apply_filters('user_history_activity_log_entry', $entry);
        if (empty($entry) || !is_array($entry)) {
            return false;
        }

        $ip_address = $this->collect_ip_address();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Inserting into custom plugin table
        $result = $wpdb->insert(
            $wpdb->prefix . self::TABLE_NAME,
            [
                'user_id'     => (int) $entry['user_id'],
                'action'      => $entry['action'],
                'object_type' => $entry['object_type'],
                'object_id'   => (int) $entry['object_id'],
                'object_name' => $entry['object_name'],
                'context'     => empty($entry['context']) ? '' : wp_json_encode($entry['context']),
                'ip_address'  => $ip_address,
                'created_at'  => current_time('mysql'),
            ],
            ['%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
        );

        if (!$result) {
            return false;
        }

        $insert_id = (int) $wpdb->insert_id;

        /**
         * Fires after an activity log entry has been saved.
         *
         * @param int   $insert_id Row ID.
         * @param array $entry     The saved entry.
         */
        do_action('user_history_activity_logged', $insert_id, $entry);

        return $insert_id;
    }

    // =========================================================================
    // Content hooks
    // =========================================================================

    /**
     * Post types that are never logged.
     *
     * @return string[]
     */
    private function get_ignored_post_types() {
        /**
         * Filter the post types excluded from the activity log.
         *
         * @param string[] $post_types Post type slugs.
         */
        return apply_filters('user_history_activity_log_ignored_post_types', [
            'revision',
            'nav_menu_item',
            'customize_changeset',
            'custom_css',
            'oembed_cache',
            'user_request',
            'wp_block',
            'wp_template',
            'wp_template_part',
            'wp_global_styles',
            'wp_navigation',
            'wp_font_family',
            'wp_font_face',
            'scheduled-action',
            'shop_order_placehold',
        ]);
    }

    /**
     * Whether a post should be logged at all.
     *
     * @param WP_Post $post Post object.
     * @return bool
     */
    private function should_log_post($post) {
        if (!$post instanceof WP_Post) {
            return false;
        }
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return false;
        }
        if (wp_is_post_revision($post->ID) || wp_is_post_autosave($post->ID)) {
            return false;
        }
        if ($post->post_type === 'attachment') {
            return false; // Media hooks handle attachments.
        }
        if (in_array($post->post_type, $this->get_ignored_post_types(), true)) {
            return false;
        }
        return true;
    }

    /**
     * Context array for a post.
     *
     * @param WP_Post $post Post object.
     * @return array
     */
    private function post_context($post) {
        $type_object = get_post_type_object($post->post_type);
        return [
            'post_type'  => $post->post_type,
            'type_label' => $type_object ? $type_object->labels->singular_name : $post->post_type,
            'status'     => $post->post_status,
        ];
    }

    /**
     * Post title with fallback.
     *
     * @param WP_Post $post Post object.
     * @return string
     */
    private function post_title($post) {
        $title = trim($post->post_title);
        if ($title === '') {
            /* translators: %d: post ID */
            $title = sprintf(__('(no title) #%d', 'user-history'), $post->ID);
        }
        return $title;
    }

    /**
     * `transition_post_status`: created / published / unpublished / trashed / restored.
     *
     * @param string  $new_status New status.
     * @param string  $old_status Old status.
     * @param WP_Post $post       Post object.
     */
    public function on_transition_post_status($new_status, $old_status, $post) {
        if (!$this->should_log_post($post) || $new_status === 'auto-draft' || $new_status === 'inherit') {
            return;
        }

        $action = null;

        if ($old_status === 'new' || $old_status === 'auto-draft') {
            $action = ($new_status === 'publish') ? 'post_published' : 'post_created';
        } elseif ($new_status === 'trash' && $old_status !== 'trash') {
            $action = 'post_trashed';
        } elseif ($old_status === 'trash' && $new_status !== 'trash') {
            $action = 'post_restored';
        } elseif ($new_status === 'publish' && $old_status !== 'publish') {
            $action = 'post_published';
        } elseif ($old_status === 'publish' && $new_status !== 'publish') {
            $action = 'post_unpublished';
        }

        if ($action === null) {
            return;
        }

        $context = $this->post_context($post);
        if ($action === 'post_unpublished' || $action === 'post_created') {
            $context['old_status'] = $old_status;
        }

        $this->logged_posts[ $post->ID ] = true;
        $this->log($action, 'post', $post->ID, $this->post_title($post), $context);
    }

    /**
     * `post_updated`: log edits to existing posts when something meaningful changed.
     *
     * @param int     $post_id     Post ID.
     * @param WP_Post $post_after  Post after update.
     * @param WP_Post $post_before Post before update.
     */
    public function on_post_updated($post_id, $post_after, $post_before) {
        if (isset($this->logged_posts[ $post_id ]) || !$this->should_log_post($post_after)) {
            return;
        }

        // Status changes are handled by transition_post_status.
        if ($post_after->post_status !== $post_before->post_status) {
            return;
        }

        if (in_array($post_after->post_status, ['auto-draft', 'trash'], true)) {
            return;
        }

        $fields  = ['post_title', 'post_content', 'post_excerpt', 'post_name', 'post_author', 'post_parent', 'menu_order', 'post_date', 'post_password', 'comment_status'];
        $changed = [];
        foreach ($fields as $field) {
            if ((string) $post_after->$field !== (string) $post_before->$field) {
                $changed[] = $field;
            }
        }

        if (empty($changed)) {
            return;
        }

        $context            = $this->post_context($post_after);
        $context['changed'] = $changed;

        $this->logged_posts[ $post_id ] = true;
        $this->log('post_updated', 'post', $post_id, $this->post_title($post_after), $context);
    }

    /**
     * `wp_after_insert_post`: a save is complete — forget the dedupe marker so
     * a later update of the same post in this request is logged normally.
     *
     * @param int|WP_Post $post Post ID or object.
     */
    public function on_after_insert_post($post) {
        $post_id = $post instanceof WP_Post ? $post->ID : (int) $post;
        unset($this->logged_posts[ $post_id ]);
    }

    /**
     * `deleted_post`: permanent deletion.
     *
     * @param int     $post_id Post ID.
     * @param WP_Post $post    Post object.
     */
    public function on_deleted_post($post_id, $post = null) {
        if (!$post instanceof WP_Post) {
            $post = get_post($post_id);
        }
        if (!$this->should_log_post($post)) {
            return;
        }

        $this->log('post_deleted', 'post', $post_id, $this->post_title($post), $this->post_context($post));
    }

    /**
     * Context array for a term.
     *
     * @param string $taxonomy Taxonomy slug.
     * @return array
     */
    private function term_context($taxonomy) {
        $tax = get_taxonomy($taxonomy);
        return [
            'taxonomy'  => $taxonomy,
            'tax_label' => $tax ? $tax->labels->singular_name : $taxonomy,
        ];
    }

    /**
     * `created_term`.
     *
     * @param int    $term_id  Term ID.
     * @param int    $tt_id    Term taxonomy ID.
     * @param string $taxonomy Taxonomy.
     */
    public function on_created_term($term_id, $tt_id, $taxonomy) {
        if ($taxonomy === 'nav_menu') {
            return;
        }
        $term = get_term($term_id, $taxonomy);
        if ($term && !is_wp_error($term)) {
            $this->log('term_created', 'term', $term_id, $term->name, $this->term_context($taxonomy));
        }
    }

    /**
     * `edited_term`.
     *
     * @param int    $term_id  Term ID.
     * @param int    $tt_id    Term taxonomy ID.
     * @param string $taxonomy Taxonomy.
     */
    public function on_edited_term($term_id, $tt_id, $taxonomy) {
        if ($taxonomy === 'nav_menu') {
            return;
        }
        $term = get_term($term_id, $taxonomy);
        if ($term && !is_wp_error($term)) {
            $this->log('term_updated', 'term', $term_id, $term->name, $this->term_context($taxonomy));
        }
    }

    /**
     * `delete_term`.
     *
     * @param int     $term_id      Term ID.
     * @param int     $tt_id        Term taxonomy ID.
     * @param string  $taxonomy     Taxonomy.
     * @param WP_Term $deleted_term Deleted term object.
     */
    public function on_delete_term($term_id, $tt_id, $taxonomy, $deleted_term) {
        if ($taxonomy === 'nav_menu') {
            return;
        }
        $name = ($deleted_term instanceof WP_Term) ? $deleted_term->name : (string) $term_id;
        $this->log('term_deleted', 'term', $term_id, $name, $this->term_context($taxonomy));
    }

    // =========================================================================
    // Media hooks
    // =========================================================================

    /**
     * `add_attachment`.
     *
     * @param int $post_id Attachment ID.
     */
    public function on_add_attachment($post_id) {
        $post = get_post($post_id);
        if ($post) {
            $this->log('attachment_uploaded', 'attachment', $post_id, $this->attachment_name($post), ['mime_type' => $post->post_mime_type]);
        }
    }

    /**
     * `attachment_updated`.
     *
     * @param int     $post_id     Attachment ID.
     * @param WP_Post $post_after  After.
     * @param WP_Post $post_before Before.
     */
    public function on_attachment_updated($post_id, $post_after, $post_before) {
        $this->log('attachment_updated', 'attachment', $post_id, $this->attachment_name($post_after), ['mime_type' => $post_after->post_mime_type]);
    }

    /**
     * `delete_attachment`.
     *
     * @param int     $post_id Attachment ID.
     * @param WP_Post $post    Attachment object.
     */
    public function on_delete_attachment($post_id, $post = null) {
        if (!$post instanceof WP_Post) {
            $post = get_post($post_id);
        }
        $name = $post ? $this->attachment_name($post) : (string) $post_id;
        $this->log('attachment_deleted', 'attachment', $post_id, $name, $post ? ['mime_type' => $post->post_mime_type] : []);
    }

    /**
     * Attachment display name: file name, falling back to title.
     *
     * @param WP_Post $post Attachment.
     * @return string
     */
    private function attachment_name($post) {
        $file = get_attached_file($post->ID);
        if ($file) {
            return wp_basename($file);
        }
        return $post->post_title !== '' ? $post->post_title : (string) $post->ID;
    }

    // =========================================================================
    // Comment hooks
    // =========================================================================

    /**
     * Title of the post a comment belongs to.
     *
     * @param WP_Comment $comment Comment.
     * @return string
     */
    private function comment_post_title($comment) {
        $post = get_post($comment->comment_post_ID);
        return $post ? $this->post_title($post) : (string) $comment->comment_post_ID;
    }

    /**
     * Context array for a comment.
     *
     * @param WP_Comment $comment Comment.
     * @return array
     */
    private function comment_context($comment) {
        return [
            'post_id' => (int) $comment->comment_post_ID,
            'author'  => $comment->comment_author,
        ];
    }

    /**
     * `wp_insert_comment`.
     *
     * @param int        $id      Comment ID.
     * @param WP_Comment $comment Comment.
     */
    public function on_insert_comment($id, $comment) {
        if (!empty($comment->comment_type) && !in_array($comment->comment_type, ['comment', ''], true)) {
            return; // Skip pingbacks, WooCommerce order notes, etc.
        }
        $this->log('comment_created', 'comment', $id, $this->comment_post_title($comment), $this->comment_context($comment), (int) $comment->user_id);
    }

    /**
     * `transition_comment_status`.
     *
     * @param string     $new_status New status.
     * @param string     $old_status Old status.
     * @param WP_Comment $comment    Comment.
     */
    public function on_transition_comment_status($new_status, $old_status, $comment) {
        // 'delete' is fired by wp_delete_comment(), which is logged separately.
        if ($new_status === $old_status || $new_status === 'delete') {
            return;
        }

        $map = [
            'approved'   => 'comment_approved',
            'unapproved' => 'comment_unapproved',
            'spam'       => 'comment_spammed',
            'trash'      => 'comment_trashed',
        ];

        if ($old_status === 'trash' || $old_status === 'spam') {
            $action = 'comment_restored';
        } elseif (isset($map[ $new_status ])) {
            $action = $map[ $new_status ];
        } else {
            return;
        }

        $this->log($action, 'comment', $comment->comment_ID, $this->comment_post_title($comment), $this->comment_context($comment));
    }

    /**
     * `delete_comment`.
     *
     * @param int        $comment_id Comment ID.
     * @param WP_Comment $comment    Comment.
     */
    public function on_delete_comment($comment_id, $comment = null) {
        if (!$comment instanceof WP_Comment) {
            $comment = get_comment($comment_id);
        }
        if (!$comment) {
            return;
        }
        $this->log('comment_deleted', 'comment', $comment_id, $this->comment_post_title($comment), $this->comment_context($comment));
    }

    // =========================================================================
    // User hooks
    // =========================================================================

    /**
     * Display name for a user ID (or the stored login for deleted users).
     *
     * @param int $user_id User ID.
     * @return string
     */
    private function user_name($user_id) {
        $user = get_userdata($user_id);
        return $user ? $user->user_login : (string) $user_id;
    }

    /**
     * `user_register`.
     *
     * @param int   $user_id  New user ID.
     * @param array $userdata Raw user data.
     */
    public function on_user_register($user_id, $userdata = []) {
        $user  = get_userdata($user_id);
        $roles = $user ? implode(', ', $user->roles) : '';

        $this->created_users[ $user_id ] = true;

        if (get_current_user_id()) {
            $this->log('user_created', 'user', $user_id, $this->user_name($user_id), ['roles' => $roles]);
        } else {
            // Self-registration: the new user is the actor.
            $this->log('user_registered', 'user', $user_id, $this->user_name($user_id), ['roles' => $roles], $user_id);
        }
    }

    /**
     * `deleted_user`.
     *
     * @param int      $id       Deleted user ID.
     * @param int|null $reassign Reassign ID.
     * @param WP_User  $user     Deleted user.
     */
    public function on_deleted_user($id, $reassign = null, $user = null) {
        $name    = ($user instanceof WP_User) ? $user->user_login : (string) $id;
        $context = [];
        if ($reassign) {
            $context['reassigned_to'] = $this->user_name($reassign);
        }
        $this->log('user_deleted', 'user', $id, $name, $context);
    }

    /**
     * `profile_update`.
     *
     * @param int     $user_id       User ID.
     * @param WP_User $old_user_data Old user data.
     * @param array   $userdata      New user data.
     */
    public function on_profile_update($user_id, $old_user_data = null, $userdata = []) {
        if (isset($this->created_users[ $user_id ])) {
            return;
        }
        $this->log('user_updated', 'user', $user_id, $this->user_name($user_id));
    }

    /**
     * `set_user_role`.
     *
     * @param int      $user_id   User ID.
     * @param string   $role      New role.
     * @param string[] $old_roles Old roles.
     */
    public function on_set_user_role($user_id, $role, $old_roles) {
        // The initial role assignment during user creation is not a change
        // (set_user_role fires before user_register, so also treat "no
        // previous roles" as creation).
        if (isset($this->created_users[ $user_id ]) || empty($old_roles)) {
            return;
        }
        $this->log('user_role_changed', 'user', $user_id, $this->user_name($user_id), [
            'old_roles' => implode(', ', (array) $old_roles),
            'new_role'  => (string) $role,
        ]);
    }

    /**
     * `after_password_reset`.
     *
     * @param WP_User $user User.
     */
    public function on_password_reset($user) {
        if ($user instanceof WP_User) {
            $this->log('user_password_reset', 'user', $user->ID, $user->user_login, [], $user->ID);
        }
    }

    /**
     * `user_history_username_changed`.
     *
     * @param int    $user_id      User ID.
     * @param string $old_username Old username.
     * @param string $new_username New username.
     */
    public function on_username_changed($user_id, $old_username, $new_username) {
        $this->log('username_changed', 'user', $user_id, $new_username, ['old' => $old_username, 'new' => $new_username]);
    }

    /**
     * `user_history_user_locked`.
     *
     * @param int $user_id User ID.
     */
    public function on_user_locked($user_id) {
        $this->log('user_locked', 'user', $user_id, $this->user_name($user_id));
    }

    /**
     * `user_history_user_unlocked`.
     *
     * @param int $user_id User ID.
     */
    public function on_user_unlocked($user_id) {
        $this->log('user_unlocked', 'user', $user_id, $this->user_name($user_id));
    }

    // =========================================================================
    // Login hooks
    // =========================================================================

    /**
     * `wp_login`.
     *
     * @param string  $user_login Username.
     * @param WP_User $user       User.
     */
    public function on_login($user_login, $user) {
        if ($user instanceof WP_User) {
            $this->log('user_login', 'user', $user->ID, $user->user_login, [], $user->ID);
        }
    }

    /**
     * `wp_logout`.
     *
     * @param int $user_id User ID.
     */
    public function on_logout($user_id = 0) {
        if ($user_id) {
            $this->log('user_logout', 'user', $user_id, $this->user_name($user_id), [], $user_id);
        }
    }

    /**
     * `wp_login_failed`.
     *
     * @param string $username Attempted username.
     */
    public function on_login_failed($username) {
        $username = sanitize_user((string) $username, true);
        $user     = $username ? get_user_by('login', $username) : false;
        if (!$user && is_email($username)) {
            $user = get_user_by('email', $username);
        }
        $this->log('login_failed', 'user', $user ? $user->ID : 0, $username, ['exists' => (bool) $user], 0);
    }

    // =========================================================================
    // Plugin / theme / core hooks
    // =========================================================================

    /**
     * Plugin name from a plugin file path.
     *
     * @param string $plugin_file Plugin basename.
     * @return string
     */
    private function plugin_name($plugin_file) {
        if (!function_exists('get_plugin_data')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $path = WP_PLUGIN_DIR . '/' . $plugin_file;
        if (file_exists($path)) {
            $data = get_plugin_data($path, false, false);
            if (!empty($data['Name'])) {
                return $data['Name'];
            }
        }
        return $plugin_file;
    }

    /**
     * `activated_plugin`.
     *
     * @param string $plugin       Plugin basename.
     * @param bool   $network_wide Network wide.
     */
    public function on_activated_plugin($plugin, $network_wide = false) {
        $this->log('plugin_activated', 'plugin', 0, $this->plugin_name($plugin), ['file' => $plugin, 'network_wide' => (bool) $network_wide]);
    }

    /**
     * `deactivated_plugin`.
     *
     * @param string $plugin       Plugin basename.
     * @param bool   $network_wide Network wide.
     */
    public function on_deactivated_plugin($plugin, $network_wide = false) {
        $this->log('plugin_deactivated', 'plugin', 0, $this->plugin_name($plugin), ['file' => $plugin, 'network_wide' => (bool) $network_wide]);
    }

    /**
     * `deleted_plugin`.
     *
     * @param string $plugin_file Plugin basename.
     * @param bool   $deleted     Whether deletion succeeded.
     */
    public function on_deleted_plugin($plugin_file, $deleted) {
        if ($deleted) {
            $this->log('plugin_deleted', 'plugin', 0, $plugin_file, ['file' => $plugin_file]);
        }
    }

    /**
     * `upgrader_process_complete`: plugin/theme installs & updates.
     *
     * @param WP_Upgrader $upgrader Upgrader instance.
     * @param array       $options  Options (type, action, plugins/themes...).
     */
    public function on_upgrader_process_complete($upgrader, $options) {
        $type   = isset($options['type']) ? $options['type'] : '';
        $action = isset($options['action']) ? $options['action'] : '';

        if ($type === 'plugin') {
            if ($action === 'install' && !empty($upgrader->plugin_info())) {
                $this->log('plugin_installed', 'plugin', 0, $this->plugin_name($upgrader->plugin_info()), ['file' => $upgrader->plugin_info()]);
            } elseif ($action === 'update') {
                $plugins = !empty($options['plugins']) ? (array) $options['plugins'] : (isset($options['plugin']) ? [$options['plugin']] : []);
                foreach ($plugins as $file) {
                    $this->log('plugin_updated', 'plugin', 0, $this->plugin_name($file), ['file' => $file]);
                }
            }
        } elseif ($type === 'theme') {
            if ($action === 'install' && !empty($upgrader->theme_info())) {
                $theme = $upgrader->theme_info();
                $this->log('theme_installed', 'theme', 0, $theme->get('Name'), ['stylesheet' => $theme->get_stylesheet()]);
            } elseif ($action === 'update') {
                $themes = !empty($options['themes']) ? (array) $options['themes'] : (isset($options['theme']) ? [$options['theme']] : []);
                foreach ($themes as $stylesheet) {
                    $theme = wp_get_theme($stylesheet);
                    $this->log('theme_updated', 'theme', 0, $theme->exists() ? $theme->get('Name') : $stylesheet, ['stylesheet' => $stylesheet]);
                }
            }
        }
    }

    /**
     * `switch_theme`.
     *
     * @param string   $new_name  New theme name.
     * @param WP_Theme $new_theme New theme.
     * @param WP_Theme $old_theme Old theme.
     */
    public function on_switch_theme($new_name, $new_theme = null, $old_theme = null) {
        $context = [];
        if ($old_theme instanceof WP_Theme) {
            $context['old'] = $old_theme->get('Name');
        }
        if ($new_theme instanceof WP_Theme) {
            $context['stylesheet'] = $new_theme->get_stylesheet();
        }
        $this->log('theme_switched', 'theme', 0, $new_name, $context);
    }

    /**
     * `deleted_theme`.
     *
     * @param string $stylesheet Theme stylesheet.
     * @param bool   $deleted    Whether deletion succeeded.
     */
    public function on_deleted_theme($stylesheet, $deleted) {
        if ($deleted) {
            $this->log('theme_deleted', 'theme', 0, $stylesheet, ['stylesheet' => $stylesheet]);
        }
    }

    /**
     * `_core_updated_successfully`.
     *
     * @param string $wp_version New WordPress version.
     */
    public function on_core_updated($wp_version) {
        $this->log('core_updated', 'core', 0, $wp_version, ['version' => $wp_version]);
    }

    // =========================================================================
    // Settings hooks
    // =========================================================================

    /**
     * Core options whose changes are logged.
     *
     * @return string[]
     */
    private function get_tracked_options() {
        /**
         * Filter the list of options whose changes are recorded in the activity log.
         *
         * Options starting with `user_history_` are always tracked, except version and crypto options.
         *
         * @param string[] $options Option names.
         */
        return apply_filters('user_history_activity_log_tracked_options', [
            'blogname',
            'blogdescription',
            'siteurl',
            'home',
            'admin_email',
            'new_admin_email',
            'users_can_register',
            'default_role',
            'WPLANG',
            'timezone_string',
            'gmt_offset',
            'date_format',
            'time_format',
            'start_of_week',
            'permalink_structure',
            'category_base',
            'tag_base',
            'posts_per_page',
            'show_on_front',
            'page_on_front',
            'page_for_posts',
            'blog_public',
            'default_comment_status',
            'comment_registration',
            'comment_moderation',
            'require_name_email',
            'default_pingback_flag',
            'thread_comments',
            'close_comments_for_old_posts',
            'moderation_keys',
            'disallowed_keys',
            'avatar_default',
            'show_avatars',
            'thumbnail_size_w',
            'thumbnail_size_h',
            'medium_size_w',
            'medium_size_h',
            'large_size_w',
            'large_size_h',
            'uploads_use_yearmonth_folders',
            'upload_path',
            'upload_url_path',
            'template',
            'stylesheet',
            'active_plugins',
            'auto_update_core_major',
            'auto_update_core_minor',
            'auto_update_core_dev',
        ]);
    }

    /**
     * `updated_option`.
     *
     * @param string $option    Option name.
     * @param mixed  $old_value Old value.
     * @param mixed  $value     New value.
     */
    public function on_updated_option($option, $old_value, $value) {
        // Theme switches and plugin (de)activations have dedicated events.
        if (in_array($option, ['template', 'stylesheet', 'active_plugins'], true)) {
            return;
        }

        $is_own = strpos($option, 'user_history_') === 0;

        if ($is_own && $this->is_skipped_own_option($option)) {
            return;
        }

        if (!$is_own && !in_array($option, $this->get_tracked_options(), true)) {
            return;
        }

        $this->log('option_updated', 'option', 0, $option, [
            'old' => $this->stringify_option_value($old_value),
            'new' => $this->stringify_option_value($value),
        ]);
    }

    /**
     * Compact string representation of an option value for storage.
     *
     * @param mixed $value Value.
     * @return string
     */
    private function stringify_option_value($value) {
        if (is_bool($value)) {
            $value = $value ? '1' : '0';
        } elseif (is_array($value) || is_object($value)) {
            $value = wp_json_encode($value);
        }
        return mb_substr((string) $value, 0, 200);
    }

    // =========================================================================
    // Reading
    // =========================================================================

    /**
     * Query activity entries.
     *
     * @param array $args {
     *     @type int    $per_page Rows per page. Default 30.
     *     @type int    $page     Page number (1-based).
     *     @type int    $user_id  Filter by acting user (0 = any; -1 = guests only).
     *     @type string $action   Filter by action key.
     *     @type string $group    Filter by event group.
     *     @type string $search   Search object_name.
     *     @type string $orderby  'created_at' or 'id'.
     *     @type string $order    'ASC' or 'DESC'.
     * }
     * @return array { items: array, total: int }
     */
    public function get_entries($args = []) {
        global $wpdb;

        $args = wp_parse_args($args, [
            'per_page' => 30,
            'page'     => 1,
            'user_id'  => 0,
            'action'   => '',
            'group'    => '',
            'search'   => '',
            'order'    => 'DESC',
        ]);

        $table  = $wpdb->prefix . self::TABLE_NAME;
        $where  = ['1=1'];
        $params = [];

        if ((int) $args['user_id'] > 0) {
            $where[]  = 'user_id = %d';
            $params[] = (int) $args['user_id'];
        } elseif ((int) $args['user_id'] === -1) {
            $where[] = 'user_id = 0';
        }

        if ($args['action'] !== '') {
            $where[]  = 'action = %s';
            $params[] = $args['action'];
        } elseif ($args['group'] !== '') {
            $actions = array_keys(array_filter(self::get_action_groups(), static function ($g) use ($args) {
                return $g === $args['group'];
            }));
            if (empty($actions)) {
                return ['items' => [], 'total' => 0];
            }
            $where[] = 'action IN (' . implode(',', array_fill(0, count($actions), '%s')) . ')';
            $params  = array_merge($params, $actions);
        }

        if ($args['search'] !== '') {
            $like     = '%' . $wpdb->esc_like($args['search']) . '%';
            $where[]  = '(object_name LIKE %s OR ip_address LIKE %s OR context LIKE %s)';
            $params[] = $like;
            $params[] = $like;
            $params[] = $like;
        }

        $where_sql = implode(' AND ', $where);
        $order     = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';
        $per_page  = max(1, (int) $args['per_page']);
        $offset    = max(0, ((int) $args['page'] - 1) * $per_page);

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table name from $wpdb->prefix; WHERE built from prepared fragments
        $count_sql = "SELECT COUNT(*) FROM $table WHERE $where_sql";
        $total     = (int) $wpdb->get_var($params ? $wpdb->prepare($count_sql, $params) : $count_sql);

        $items_sql = "SELECT * FROM $table WHERE $where_sql ORDER BY created_at $order, id $order LIMIT %d OFFSET %d";
        $items     = $wpdb->get_results($wpdb->prepare($items_sql, array_merge($params, [$per_page, $offset])));
        // phpcs:enable

        return ['items' => $items ?: [], 'total' => $total];
    }

    /**
     * IDs of users who appear in the log (for the filter dropdown).
     *
     * @param int $limit Max number of users.
     * @return int[]
     */
    public function get_actor_ids($limit = 200) {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_NAME;
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table name from $wpdb->prefix
        return array_map('intval', (array) $wpdb->get_col($wpdb->prepare("SELECT DISTINCT user_id FROM $table WHERE user_id > 0 ORDER BY user_id ASC LIMIT %d", (int) $limit)));
    }

    /**
     * Delete every activity row. Caller must wrap this in a transaction.
     *
     * @return int|false Number of deleted rows, or false on failure.
     */
    public function delete_all_rows() {
        global $wpdb;

        $table = $this->table_name();
        if ($table === '') {
            return false;
        }

        $deleted = $wpdb->query("DELETE FROM `{$table}`");
        return $deleted === false ? false : (int) $deleted;
    }

    /**
     * Delete activity rows older than a cutoff timestamp.
     *
     * @param string $cutoff MySQL datetime.
     * @return int|false Number of deleted rows, or false on failure.
     */
    public function delete_expired_rows($cutoff) {
        global $wpdb;

        $table = $this->table_name();
        if ($table === '') {
            return false;
        }

        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM `{$table}` WHERE created_at < %s",
                $cutoff
            )
        );

        return $deleted === false ? false : (int) $deleted;
    }

    // =========================================================================
    // Display
    // =========================================================================

    /**
     * Decode a row's context JSON.
     *
     * @param object $row Log row.
     * @return array
     */
    public static function get_context($row) {
        if (empty($row->context)) {
            return [];
        }
        $context = json_decode($row->context, true);
        return is_array($context) ? $context : [];
    }

    /**
     * Build the human-readable description for a log row (HTML, escaped).
     *
     * @param object $row Log row.
     * @return string
     */
    public function describe($row) {
        $context = self::get_context($row);
        $name    = $row->object_name;
        $link    = $this->object_link($row, $context);
        $obj     = $link ? '<a href="' . esc_url($link) . '">' . esc_html($name) . '</a>' : '<strong>' . esc_html($name) . '</strong>';

        $type_label = isset($context['type_label']) ? mb_strtolower($context['type_label']) : __('post', 'user-history');
        $tax_label  = isset($context['tax_label']) ? mb_strtolower($context['tax_label']) : __('term', 'user-history');

        switch ($row->action) {
            /* translators: 1: post type (e.g. post, page), 2: linked title */
            case 'post_created':     $text = sprintf(__('Created %1$s %2$s', 'user-history'), esc_html($type_label), $obj); break;
            /* translators: 1: post type, 2: linked title */
            case 'post_updated':     $text = sprintf(__('Updated %1$s %2$s', 'user-history'), esc_html($type_label), $obj); break;
            /* translators: 1: post type, 2: linked title */
            case 'post_published':   $text = sprintf(__('Published %1$s %2$s', 'user-history'), esc_html($type_label), $obj); break;
            /* translators: 1: post type, 2: linked title, 3: new status */
            case 'post_unpublished': $text = sprintf(__('Unpublished %1$s %2$s (now %3$s)', 'user-history'), esc_html($type_label), $obj, esc_html(isset($context['status']) ? $context['status'] : '')); break;
            /* translators: 1: post type, 2: linked title */
            case 'post_trashed':     $text = sprintf(__('Moved %1$s %2$s to Trash', 'user-history'), esc_html($type_label), $obj); break;
            /* translators: 1: post type, 2: linked title */
            case 'post_restored':    $text = sprintf(__('Restored %1$s %2$s from Trash', 'user-history'), esc_html($type_label), $obj); break;
            /* translators: 1: post type, 2: title */
            case 'post_deleted':     $text = sprintf(__('Permanently deleted %1$s %2$s', 'user-history'), esc_html($type_label), $obj); break;

            /* translators: 1: taxonomy (e.g. category), 2: linked term name */
            case 'term_created':     $text = sprintf(__('Created %1$s %2$s', 'user-history'), esc_html($tax_label), $obj); break;
            /* translators: 1: taxonomy, 2: linked term name */
            case 'term_updated':     $text = sprintf(__('Updated %1$s %2$s', 'user-history'), esc_html($tax_label), $obj); break;
            /* translators: 1: taxonomy, 2: term name */
            case 'term_deleted':     $text = sprintf(__('Deleted %1$s %2$s', 'user-history'), esc_html($tax_label), $obj); break;

            /* translators: %s: linked file name */
            case 'attachment_uploaded': $text = sprintf(__('Uploaded file %s', 'user-history'), $obj); break;
            /* translators: %s: linked file name */
            case 'attachment_updated':  $text = sprintf(__('Updated file %s', 'user-history'), $obj); break;
            /* translators: %s: file name */
            case 'attachment_deleted':  $text = sprintf(__('Deleted file %s', 'user-history'), $obj); break;

            /* translators: %s: linked post title */
            case 'comment_created':    $text = sprintf(__('Posted a comment on %s', 'user-history'), $obj); break;
            /* translators: %s: linked post title */
            case 'comment_approved':   $text = sprintf(__('Approved a comment on %s', 'user-history'), $obj); break;
            /* translators: %s: linked post title */
            case 'comment_unapproved': $text = sprintf(__('Unapproved a comment on %s', 'user-history'), $obj); break;
            /* translators: %s: linked post title */
            case 'comment_spammed':    $text = sprintf(__('Marked a comment on %s as spam', 'user-history'), $obj); break;
            /* translators: %s: linked post title */
            case 'comment_trashed':    $text = sprintf(__('Trashed a comment on %s', 'user-history'), $obj); break;
            /* translators: %s: linked post title */
            case 'comment_restored':   $text = sprintf(__('Restored a comment on %s', 'user-history'), $obj); break;
            /* translators: %s: linked post title */
            case 'comment_deleted':    $text = sprintf(__('Permanently deleted a comment on %s', 'user-history'), $obj); break;

            /* translators: %s: role */
            case 'user_registered':    $text = sprintf(__('Registered an account (%s)', 'user-history'), esc_html(isset($context['roles']) ? $context['roles'] : '')); break;
            /* translators: 1: linked username, 2: role */
            case 'user_created':       $text = sprintf(__('Created user %1$s (%2$s)', 'user-history'), $obj, esc_html(isset($context['roles']) ? $context['roles'] : '')); break;
            /* translators: %s: username */
            case 'user_deleted':       $text = sprintf(__('Deleted user %s', 'user-history'), $obj);
                if (!empty($context['reassigned_to'])) {
                    /* translators: %s: username content was reassigned to */
                    $text .= ' ' . sprintf(__('(content reassigned to %s)', 'user-history'), esc_html($context['reassigned_to']));
                }
                break;
            case 'user_updated':
                if ((int) $row->user_id === (int) $row->object_id) {
                    $text = __('Updated their own profile', 'user-history');
                } else {
                    /* translators: %s: linked username */
                    $text = sprintf(__('Updated the profile of %s', 'user-history'), $obj);
                }
                break;
            /* translators: 1: linked username, 2: old role(s), 3: new role */
            case 'user_role_changed':  $text = sprintf(__('Changed the role of %1$s from %2$s to %3$s', 'user-history'), $obj, esc_html(!empty($context['old_roles']) ? $context['old_roles'] : '—'), esc_html(isset($context['new_role']) ? $context['new_role'] : '')); break;
            case 'user_password_reset': $text = __('Reset their password', 'user-history'); break;
            /* translators: 1: old username, 2: linked new username */
            case 'username_changed':   $text = sprintf(__('Changed username %1$s to %2$s', 'user-history'), esc_html(isset($context['old']) ? $context['old'] : ''), $obj); break;
            /* translators: %s: linked username */
            case 'user_locked':        $text = sprintf(__('Locked the account of %s', 'user-history'), $obj); break;
            /* translators: %s: linked username */
            case 'user_unlocked':      $text = sprintf(__('Unlocked the account of %s', 'user-history'), $obj); break;

            case 'user_login':         $text = __('Logged in', 'user-history'); break;
            case 'user_logout':        $text = __('Logged out', 'user-history'); break;
            /* translators: %s: attempted username */
            case 'login_failed':       $text = sprintf(__('Failed login attempt for %s', 'user-history'), $obj); break;

            /* translators: %s: plugin name */
            case 'plugin_activated':   $text = sprintf(__('Activated plugin %s', 'user-history'), $obj); break;
            /* translators: %s: plugin name */
            case 'plugin_deactivated': $text = sprintf(__('Deactivated plugin %s', 'user-history'), $obj); break;
            /* translators: %s: plugin name */
            case 'plugin_installed':   $text = sprintf(__('Installed plugin %s', 'user-history'), $obj); break;
            /* translators: %s: plugin name */
            case 'plugin_updated':     $text = sprintf(__('Updated plugin %s', 'user-history'), $obj); break;
            /* translators: %s: plugin file */
            case 'plugin_deleted':     $text = sprintf(__('Deleted plugin %s', 'user-history'), $obj); break;
            /* translators: %s: theme name */
            case 'theme_switched':     $text = sprintf(__('Switched theme to %s', 'user-history'), $obj);
                if (!empty($context['old'])) {
                    /* translators: %s: previous theme name */
                    $text .= ' ' . sprintf(__('(from %s)', 'user-history'), esc_html($context['old']));
                }
                break;
            /* translators: %s: theme name */
            case 'theme_installed':    $text = sprintf(__('Installed theme %s', 'user-history'), $obj); break;
            /* translators: %s: theme name */
            case 'theme_updated':      $text = sprintf(__('Updated theme %s', 'user-history'), $obj); break;
            /* translators: %s: theme stylesheet */
            case 'theme_deleted':      $text = sprintf(__('Deleted theme %s', 'user-history'), $obj); break;
            /* translators: %s: WordPress version */
            case 'core_updated':       $text = sprintf(__('Updated WordPress to %s', 'user-history'), $obj); break;

            case 'option_updated':
                /* translators: %s: option name */
                $text = sprintf(__('Changed setting %s', 'user-history'), '<code>' . esc_html($name) . '</code>');
                if (isset($context['old'], $context['new'])) {
                    $text .= '<br><span class="user-history-activity-diff">'
                        . '<del>' . esc_html($this->truncate($context['old'])) . '</del> &rarr; '
                        . '<ins>' . esc_html($this->truncate($context['new'])) . '</ins></span>';
                }
                break;

            default:
                /**
                 * Filter the description for an unknown/third-party action.
                 *
                 * @param string $text    Description HTML (empty by default).
                 * @param object $row     Log row.
                 * @param array  $context Decoded context.
                 */
                $text = apply_filters('user_history_activity_log_description', '', $row, $context);
                if ($text === '') {
                    $text = esc_html($row->action) . ' ' . $obj;
                }
        }

        if (!empty($context['via'])) {
            $via = [
                'wp-cli' => __('via WP-CLI', 'user-history'),
                'cron'   => __('via cron', 'user-history'),
                'rest'   => __('via REST API', 'user-history'),
            ];
            if (isset($via[ $context['via'] ])) {
                $text .= ' <span class="user-history-activity-via">' . esc_html($via[ $context['via'] ]) . '</span>';
            }
        }

        return $text;
    }

    /**
     * Admin link for the object a row concerns, if it still exists.
     *
     * @param object $row     Log row.
     * @param array  $context Decoded context.
     * @return string Empty if no link.
     */
    private function object_link($row, $context) {
        if (!$row->object_id) {
            return '';
        }

        switch ($row->object_type) {
            case 'post':
            case 'attachment':
                if (in_array($row->action, ['post_deleted', 'attachment_deleted'], true) || !get_post($row->object_id)) {
                    return '';
                }
                if (!current_user_can('edit_post', $row->object_id)) {
                    return '';
                }
                return (string) get_edit_post_link($row->object_id, 'raw');

            case 'comment':
                if (!empty($context['post_id']) && get_post($context['post_id']) && current_user_can('edit_post', $context['post_id'])) {
                    return (string) get_edit_post_link($context['post_id'], 'raw');
                }
                return '';

            case 'term':
                if ($row->action === 'term_deleted' || empty($context['taxonomy'])) {
                    return '';
                }
                $term = get_term($row->object_id, $context['taxonomy']);
                if (!$term || is_wp_error($term)) {
                    return '';
                }
                $link = get_edit_term_link($term, $context['taxonomy']);
                return $link ? $link : '';

            case 'user':
                if ($row->action === 'user_deleted' || !get_userdata($row->object_id) || !current_user_can('edit_user', $row->object_id)) {
                    return '';
                }
                return get_edit_user_link($row->object_id);
        }

        return '';
    }

    /**
     * Truncate a value for display.
     *
     * @param string $value  Value.
     * @param int    $length Max length.
     * @return string
     */
    private function truncate($value, $length = 60) {
        $value = (string) $value;
        if ($value === '') {
            return __('(empty)', 'user-history');
        }
        return mb_strlen($value) > $length ? mb_substr($value, 0, $length) . '…' : $value;
    }

    /**
     * Whether this action should be written.
     *
     * @param string $action Action key.
     * @return bool
     */
    public function should_record_action($action) {
        if (!$this->is_enabled()) {
            return false;
        }

        $groups = $this->get_enabled_groups();
        $map = self::get_action_groups();
        $group = isset($map[ $action ]) ? $map[ $action ] : '';

        if ($group === '') {
            return true;
        }

        return in_array($group, $groups, true);
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

    /**
     * @return string
     */
    public function table_name() {
        global $wpdb;

        $table = $wpdb->prefix . self::TABLE_NAME;
        return preg_match('/^[A-Za-z0-9_]+$/', $table) ? $table : '';
    }

    /**
     * Create the InnoDB activity table.
     */
    public function create_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL DEFAULT 0,
            action varchar(64) NOT NULL,
            object_type varchar(32) NOT NULL DEFAULT '',
            object_id bigint(20) unsigned NOT NULL DEFAULT 0,
            object_name varchar(255) NOT NULL DEFAULT '',
            context longtext,
            ip_address varchar(45) NOT NULL DEFAULT '',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY action (action),
            KEY object_type_id (object_type, object_id),
            KEY created_at (created_at)
        ) ENGINE=InnoDB $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
        $this->ensure_table_engine();
    }

    /**
     * Convert the activity table to InnoDB when another engine is in use.
     */
    public function ensure_table_engine() {
        global $wpdb;

        $table = $this->table_name();
        if ($table === '') {
            return;
        }

        $previous_suppress = $wpdb->suppress_errors(true);
        $create_table = $wpdb->get_row("SHOW CREATE TABLE `{$table}`", ARRAY_N);
        $wpdb->suppress_errors($previous_suppress);

        $engine = '';
        if (is_array($create_table) && isset($create_table[1]) && is_string($create_table[1])) {
            if (preg_match('/\bENGINE=([A-Za-z0-9_]+)/i', $create_table[1], $matches)) {
                $engine = $matches[1];
            }
        }

        if ($engine !== '' && strcasecmp($engine, 'InnoDB') !== 0) {
            $wpdb->query("ALTER TABLE `{$table}` ENGINE=InnoDB");
        }
    }

    /**
     * Client IP for a new activity row. Honors USER_HISTORY_COLLECT_IP and REMOTE_ADDR only.
     *
     * @return string
     */
    private function collect_ip_address() {
        if (defined('USER_HISTORY_COLLECT_IP')) {
            $collect = (bool) USER_HISTORY_COLLECT_IP;
        } else {
            $collect = $this->option_flag_is_enabled(get_option('user_history_collect_ip', '1'));
        }

        $collect = (bool) apply_filters('user_history_collect_ip', $collect);
        if (!$collect) {
            return '';
        }

        if (empty($_SERVER['REMOTE_ADDR'])) {
            return '';
        }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    /**
     * Skip version and crypto options from the settings group.
     *
     * @param string $option Option name.
     * @return bool
     */
    private function is_skipped_own_option($option) {
        $skipped = [
            'user_history_version',
            'user_history_key_version',
            'user_history_retired_key_versions',
            'user_history_crypto_current',
        ];

        if (in_array($option, $skipped, true)) {
            return true;
        }

        return strpos($option, 'user_history_crypto') === 0;
    }

    /**
     * Register the Activity Log fields on the shared Settings page.
     */
    public function register_settings() {
        register_setting(
            User_History_Settings::OPTION_GROUP,
            self::OPTION_ENABLED,
            [
                'type'              => 'string',
                'sanitize_callback' => [$this, 'sanitize_enabled'],
                'default'           => '0',
                'show_in_rest'      => false,
            ]
        );

        register_setting(
            User_History_Settings::OPTION_GROUP,
            self::OPTION_EVENTS,
            [
                'type'              => 'array',
                'sanitize_callback' => [$this, 'sanitize_events'],
                'default'           => self::get_event_group_slugs(),
                'show_in_rest'      => false,
            ]
        );

        add_settings_section(
            'user_history_activity',
            __('Activity Log', 'user-history'),
            [$this, 'render_activity_section'],
            User_History_Settings::MENU_SLUG
        );

        add_settings_field(
            self::OPTION_ENABLED,
            __('Activity Log', 'user-history'),
            [$this, 'render_enabled_field'],
            User_History_Settings::MENU_SLUG,
            'user_history_activity'
        );

        add_settings_field(
            self::OPTION_EVENTS,
            __('Events to record', 'user-history'),
            [$this, 'render_events_field'],
            User_History_Settings::MENU_SLUG,
            'user_history_activity'
        );
    }

    /**
     * @param mixed $value Raw submitted value.
     * @return string '1' or '0'. Default stays off.
     */
    public function sanitize_enabled($value) {
        return $this->option_flag_is_enabled($value) ? '1' : '0';
    }

    /**
     * @param mixed $value Submitted group slugs.
     * @return string[]
     */
    public function sanitize_events($value) {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_intersect(self::get_event_group_slugs(), array_map('sanitize_key', $value)));
    }

    /**
     * Screen option for rows per page.
     */
    public function register_screen_options() {
        if (!is_admin() || !function_exists('get_plugin_page_hookname')) {
            return;
        }

        $hook = get_plugin_page_hookname(self::MENU_SLUG, User_History_Settings::MENU_SLUG);
        if ($hook) {
            add_action('load-' . $hook, [$this, 'add_screen_options']);
        }
    }

    /**
     * Add the Activity Log rows-per-page screen option.
     */
    public function add_screen_options() {
        add_screen_option(
            'per_page',
            [
                'label'   => __('Activity entries per page', 'user-history'),
                'default' => 30,
                'option'  => self::PER_PAGE_OPTION,
            ]
        );
    }

    /**
     * @param mixed  $status Unused.
     * @param string $option Option name.
     * @param mixed  $value  Submitted value.
     * @return mixed
     */
    public function save_screen_option($status, $option, $value) {
        if ($option === self::PER_PAGE_OPTION) {
            return max(1, (int) $value);
        }

        return $status;
    }

    /**
     * Settings intro for the Activity Log section.
     */
    public function render_activity_section() {
        echo '<p>' . esc_html__('A lighter site-wide log of content, media, comments, users, logins, extensions, and settings. Off by default so an update does not start recording posts or plugin changes.', 'user-history') . '</p>';
    }

    /**
     * Enable checkbox. Default off.
     */
    public function render_enabled_field() {
        $option_on = $this->is_enabled();
        ?>
        <label>
            <input type="hidden" name="<?php echo esc_attr(self::OPTION_ENABLED); ?>" value="0" />
            <input type="checkbox" name="<?php echo esc_attr(self::OPTION_ENABLED); ?>" value="1" <?php checked($option_on); ?> />
            <?php esc_html_e('Enable the activity log', 'user-history'); ?>
        </label>
        <p class="description">
            <?php esc_html_e('Off by default. New events are recorded only after you turn this on.', 'user-history'); ?>
        </p>
        <?php
    }

    /**
     * Event group checkboxes.
     */
    public function render_events_field() {
        $enabled = $this->get_enabled_groups();
        foreach (self::get_event_groups() as $slug => $label) :
            ?>
            <label style="display:block; margin: 4px 0;">
                <input type="checkbox" name="<?php echo esc_attr(self::OPTION_EVENTS); ?>[]" value="<?php echo esc_attr($slug); ?>" <?php checked(in_array($slug, $enabled, true)); ?> />
                <?php echo esc_html($label); ?>
            </label>
            <?php
        endforeach;
    }

    /**
     * Render the Activity Log list page.
     */
    public function render_activity_log_page() {
        if (!current_user_can($this->settings_capability())) {
            wp_die(esc_html__('You are not allowed to access the Activity Log.', 'user-history'));
        }

        require_once USER_HISTORY_PLUGIN_DIR . 'includes/class-activity-list-table.php';
        $table = new User_History_Activity_List_Table($this);
        $table->prepare_items();
        $settings_url = admin_url('admin.php?page=' . User_History_Settings::MENU_SLUG);
        ?>
        <div class="wrap user-history-activity-wrap">
            <h1 class="wp-heading-inline"><?php esc_html_e('Activity Log', 'user-history'); ?></h1>
            <a href="<?php echo esc_url($settings_url); ?>" class="page-title-action"><?php esc_html_e('Settings', 'user-history'); ?></a>
            <button type="button" class="page-title-action user-history-clear-activity" id="user-history-clear-activity-log"><?php esc_html_e('Clear Activity Log', 'user-history'); ?></button>
            <hr class="wp-header-end">

            <?php if (!$this->is_enabled()) : ?>
                <div class="notice notice-warning inline">
                    <p>
                        <?php esc_html_e('The activity log is currently disabled — new events are not being recorded.', 'user-history'); ?>
                        <a href="<?php echo esc_url($settings_url); ?>"><?php esc_html_e('Enable it in Settings.', 'user-history'); ?></a>
                    </p>
                </div>
            <?php endif; ?>

            <p id="user-history-clear-activity-log-message" class="user-history-clear-all-message" role="status"></p>

            <form method="get">
                <input type="hidden" name="page" value="<?php echo esc_attr(self::MENU_SLUG); ?>" />
                <?php
                $table->search_box(__('Search activity', 'user-history'), 'user-history-activity');
                $table->display();
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * AJAX: clear every activity row behind manage_user_history.
     */
    public function ajax_clear() {
        check_ajax_referer(self::CLEAR_NONCE, 'nonce');

        $result = $this->plugin->clear_activity_log();
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }

        wp_send_json_success(
            [
                'message' => __('The activity log was cleared. A maintenance note was written.', 'user-history'),
                'deleted' => (int) $result,
            ]
        );
    }
}
