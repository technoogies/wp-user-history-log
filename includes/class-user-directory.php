<?php

/**
 * Last login on All Users, a read-only duplicate finder, and a user CSV.
 *
 * The stamp is only a time. It is written on wp_login even when login
 * recording is off. The duplicate screen and the CSV both use query_site_users().
 * Neither one locks, disables, or edits an account.
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_User_Directory {

    const META_LAST_LOGIN = 'user_history_last_login';
    const COLUMN_LAST_LOGIN = 'user_history_last_login';
    const MENU_SLUG = 'user-history-duplicates';
    const EXPORT_ACTION = 'user_history_export_users';
    const EXPORT_NONCE = 'user_history_export_users';
    const QUERY_PAGE_SIZE = 200;

    const CSV_HEADERS = [
        'id',
        'username',
        'email',
        'display_name',
        'roles',
        'registered',
        'last_login',
    ];

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
        add_action('wp_login', [$this, 'stamp_last_login'], 10, 2);
        add_filter('manage_users_columns', [$this, 'add_last_login_column'], 20);
        add_filter('manage_users_custom_column', [$this, 'render_last_login_column'], 10, 3);
        add_action('admin_post_' . self::EXPORT_ACTION, [$this, 'export_users_csv']);
        add_filter('wp_privacy_personal_data_exporters', [$this, 'register_exporter']);
        add_filter('wp_privacy_personal_data_erasers', [$this, 'register_eraser']);
    }

    /**
     * Record the time of a successful login. Login recording can stay off.
     *
     * @param string       $user_login Username.
     * @param WP_User|mixed $user      Authenticated user.
     */
    public function stamp_last_login($user_login, $user) {
        unset($user_login);

        if (!$user instanceof WP_User) {
            return;
        }

        $user_id = (int) $user->ID;
        if ($user_id < 1) {
            return;
        }

        update_user_meta($user_id, self::META_LAST_LOGIN, (string) time());
    }

    /**
     * @param int $user_id User ID.
     * @return int Unix timestamp, or 0 when this account has no stamp.
     */
    public function last_login_timestamp($user_id) {
        $user_id = (int) $user_id;
        if ($user_id < 1) {
            return 0;
        }

        $raw = get_user_meta($user_id, self::META_LAST_LOGIN, true);
        if (!is_scalar($raw) || !is_numeric($raw)) {
            return 0;
        }

        $timestamp = (int) $raw;

        return $timestamp > 0 ? $timestamp : 0;
    }

    /**
     * @param array<string,string> $columns Users table columns.
     * @return array<string,string>
     */
    public function add_last_login_column($columns) {
        if (!is_array($columns)) {
            $columns = [];
        }

        if (isset($columns[self::COLUMN_LAST_LOGIN])) {
            return $columns;
        }

        $label = __('Last login', 'user-history');
        $updated = [];
        $inserted = false;

        foreach ($columns as $key => $value) {
            $updated[$key] = $value;
            $after_status = ($key === 'user_history_locked');
            $after_role = ($key === 'role' && !isset($columns['user_history_locked']));
            if (!$inserted && ($after_status || $after_role)) {
                $updated[self::COLUMN_LAST_LOGIN] = $label;
                $inserted = true;
            }
        }

        if (!$inserted) {
            $updated[self::COLUMN_LAST_LOGIN] = $label;
        }

        return $updated;
    }

    /**
     * @param string $output      Current cell output.
     * @param string $column_name Column key.
     * @param int    $user_id     User ID.
     * @return string
     */
    public function render_last_login_column($output, $column_name, $user_id) {
        if ($column_name !== self::COLUMN_LAST_LOGIN) {
            return $output;
        }

        return esc_html($this->format_last_login_for_display($this->last_login_timestamp($user_id)));
    }

    /**
     * Site-timezone time for the Users screen. Never when there is no stamp.
     *
     * @param int $timestamp Unix timestamp.
     * @return string
     */
    public function format_last_login_for_display($timestamp) {
        $timestamp = (int) $timestamp;
        if ($timestamp < 1) {
            return __('Never', 'user-history');
        }

        $format = trim((string) get_option('date_format') . ' ' . (string) get_option('time_format'));
        if ($format === '') {
            $format = 'Y-m-d H:i';
        }

        return wp_date($format, $timestamp);
    }

    /**
     * ISO 8601 in the site timezone. Blank when there is no stamp.
     *
     * @param int $timestamp Unix timestamp.
     * @return string
     */
    public function format_last_login_for_csv($timestamp) {
        $timestamp = (int) $timestamp;
        if ($timestamp < 1) {
            return '';
        }

        return wp_date('c', $timestamp);
    }

    /**
     * People who can open User History and list users.
     *
     * @return bool
     */
    public function current_operator_can_export() {
        if (!is_user_logged_in()) {
            return false;
        }

        return current_user_can(User_History::CLEAR_HISTORY_CAPABILITY)
            && current_user_can('list_users');
    }

    /**
     * Users on this site, including last login.
     * The duplicate screen and the CSV download both use this list.
     *
     * @return array<int,array<string,mixed>>
     */
    public function query_site_users() {
        $rows = [];
        $page = 1;

        do {
            $users = get_users(
                [
                    'blog_id' => get_current_blog_id(),
                    'orderby' => 'login',
                    'order'   => 'ASC',
                    'number'  => self::QUERY_PAGE_SIZE,
                    'paged'   => $page,
                    'fields'  => 'all',
                ]
            );

            foreach ((array) $users as $user) {
                if (!$user instanceof WP_User) {
                    continue;
                }

                $rows[] = $this->row_from_user($user);
            }

            $page++;
        } while (count((array) $users) === self::QUERY_PAGE_SIZE);

        return $rows;
    }

    /**
     * The same rows as query_site_users(), after the export capability and nonce checks.
     *
     * @return array<int,array<string,mixed>>
     */
    public function export_rows() {
        if (!$this->current_operator_can_export()) {
            wp_die(
                esc_html__('You are not allowed to export users.', 'user-history'),
                '',
                ['response' => 403]
            );
        }

        $nonce = isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::EXPORT_NONCE)) {
            wp_die(
                esc_html__('The export link expired. Go back to Duplicate users and try again.', 'user-history'),
                '',
                ['response' => 403]
            );
        }

        return $this->query_site_users();
    }

    /**
     * Download the site user list. This does not change any account.
     */
    public function export_users_csv() {
        $this->send_csv($this->export_rows());
    }

    /**
     * @param array<int,array<string,mixed>> $rows Rows from query_site_users().
     * @return string
     */
    public function build_csv(array $rows) {
        $handle = fopen('php://temp', 'r+');
        if (false === $handle) {
            return '';
        }

        fputcsv($handle, self::CSV_HEADERS);
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }
            fputcsv($handle, $this->csv_line($row));
        }

        rewind($handle);
        $csv = stream_get_contents($handle);
        fclose($handle);

        return is_string($csv) ? $csv : '';
    }

    /**
     * Case-insensitive email and username groups with at least two accounts.
     * Blank values are not a match. The rows are not modified.
     *
     * @param array<int,array<string,mixed>> $rows Rows from query_site_users().
     * @return array{email:array<int,array<string,mixed>>,login:array<int,array<string,mixed>>}
     */
    public function duplicate_groups(array $rows) {
        return [
            'email' => $this->groups_for_field($rows, 'email'),
            'login' => $this->groups_for_field($rows, 'username'),
        ];
    }

    /**
     * @return array{rows:array<int,array<string,mixed>>,groups:array{email:array<int,array<string,mixed>>,login:array<int,array<string,mixed>>}}
     */
    public function directory_report() {
        $rows = $this->query_site_users();

        return [
            'rows'   => $rows,
            'groups' => $this->duplicate_groups($rows),
        ];
    }

    /**
     * Read-only duplicate screen. The CSV link uses the same user list.
     */
    public function render_page() {
        if (!$this->current_operator_can_export()) {
            wp_die(
                esc_html__('You are not allowed to view duplicate users.', 'user-history'),
                '',
                ['response' => 403]
            );
        }

        $report = $this->directory_report();
        $export_url = wp_nonce_url(
            admin_url('admin-post.php?action=' . self::EXPORT_ACTION),
            self::EXPORT_NONCE
        );
        ?>
        <div class="wrap user-history-duplicates">
            <h1><?php esc_html_e('Duplicate users', 'user-history'); ?></h1>
            <p><?php esc_html_e('This page only looks. It does not change, lock, or disable any account.', 'user-history'); ?></p>
            <p>
                <?php esc_html_e('It lists usernames or email addresses shared by more than one account on this site. Capital letters are ignored. A blank value is not a match.', 'user-history'); ?>
            </p>
            <p>
                <a class="button button-primary" href="<?php echo esc_url($export_url); ?>">
                    <?php esc_html_e('Download users CSV', 'user-history'); ?>
                </a>
            </p>
            <p class="description">
                <?php esc_html_e('The CSV is that same user list, including last login. A blank last login means there is no stamp yet. The file does not include passwords, staff notes, or sessions. You need manage_user_history and list_users.', 'user-history'); ?>
            </p>

            <h2><?php esc_html_e('Duplicate emails', 'user-history'); ?></h2>
            <?php $this->render_groups($report['groups']['email']); ?>

            <h2><?php esc_html_e('Duplicate usernames', 'user-history'); ?></h2>
            <?php $this->render_groups($report['groups']['login']); ?>
        </div>
        <?php
    }

    /**
     * @param array<string,array<string,mixed>> $exporters Exporters.
     * @return array<string,array<string,mixed>>
     */
    public function register_exporter($exporters) {
        if (!is_array($exporters)) {
            $exporters = [];
        }

        $exporters['user-history-last-login'] = [
            'exporter_friendly_name' => __('Last login', 'user-history'),
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

        $erasers['user-history-last-login'] = [
            'eraser_friendly_name' => __('Last login', 'user-history'),
            'callback'             => [$this, 'erase_personal_data'],
        ];

        return $erasers;
    }

    /**
     * @param string $email_address User email.
     * @param int    $page          Unused page number.
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

        $timestamp = $this->last_login_timestamp((int) $user->ID);
        if ($timestamp < 1) {
            return [
                'data' => [],
                'done' => true,
            ];
        }

        return [
            'data' => [
                [
                    'group_id'    => 'user-history-last-login',
                    'group_label' => __('Last login', 'user-history'),
                    'item_id'     => 'user-history-last-login-' . (int) $user->ID,
                    'data'        => [
                        [
                            'name'  => __('Last login', 'user-history'),
                            'value' => $this->format_last_login_for_display($timestamp),
                        ],
                    ],
                ],
            ],
            'done' => true,
        ];
    }

    /**
     * Remove the last-login stamp. Account history is a separate eraser.
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
        $existing = get_user_meta($user_id, self::META_LAST_LOGIN, false);
        $removed = false;
        if (is_array($existing) && $existing !== []) {
            delete_user_meta($user_id, self::META_LAST_LOGIN);
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
     * @param WP_User $user User.
     * @return array<string,mixed>
     */
    private function row_from_user($user) {
        $roles = array_map('strval', (array) $user->roles);
        sort($roles);

        return [
            'id'           => (int) $user->ID,
            'username'     => (string) $user->user_login,
            'email'        => (string) $user->user_email,
            'display_name' => (string) $user->display_name,
            'roles'        => implode(', ', $roles),
            'registered'   => (string) $user->user_registered,
            'last_login'   => $this->last_login_timestamp((int) $user->ID),
        ];
    }

    /**
     * @param array<int,array<string,mixed>> $rows  User rows.
     * @param string                         $field email or username.
     * @return array<int,array<string,mixed>>
     */
    private function groups_for_field(array $rows, $field) {
        $buckets = [];

        foreach ($rows as $row) {
            if (!is_array($row) || !isset($row[$field])) {
                continue;
            }

            $display = trim((string) $row[$field]);
            $key = $this->normalize_identity($display);
            if ($key === '') {
                continue;
            }

            if (!isset($buckets[$key])) {
                $buckets[$key] = [
                    'value' => $display,
                    'users' => [],
                ];
            }

            $buckets[$key]['users'][] = $row;
        }

        $groups = [];
        foreach ($buckets as $bucket) {
            if (count($bucket['users']) < 2) {
                continue;
            }
            $groups[] = $bucket;
        }

        usort(
            $groups,
            static function ($left, $right) {
                return strcasecmp((string) $left['value'], (string) $right['value']);
            }
        );

        return $groups;
    }

    /**
     * @param string $value Email or username.
     * @return string
     */
    private function normalize_identity($value) {
        $value = trim((string) $value);
        if ($value === '') {
            return '';
        }

        if (function_exists('mb_strtolower')) {
            return mb_strtolower($value, 'UTF-8');
        }

        return strtolower($value);
    }

    /**
     * @param array<string,mixed> $row User row.
     * @return array<int,string>
     */
    private function csv_line(array $row) {
        $last_login = isset($row['last_login']) ? (int) $row['last_login'] : 0;
        $values = [
            isset($row['id']) ? (string) (int) $row['id'] : '',
            isset($row['username']) ? (string) $row['username'] : '',
            isset($row['email']) ? (string) $row['email'] : '',
            isset($row['display_name']) ? (string) $row['display_name'] : '',
            isset($row['roles']) ? (string) $row['roles'] : '',
            isset($row['registered']) ? (string) $row['registered'] : '',
            $this->format_last_login_for_csv($last_login),
        ];

        $line = [];
        foreach ($values as $value) {
            $line[] = $this->csv_cell($value);
        }

        return $line;
    }

    /**
     * Stop a spreadsheet from treating a cell as a formula.
     *
     * @param string $value Cell value.
     * @return string
     */
    private function csv_cell($value) {
        $value = str_replace("\0", '', (string) $value);
        $check = ltrim($value, " \t\r\n");
        if ($check !== '' && preg_match('/^[=+\\-@]/', $check)) {
            return "'" . $value;
        }

        return $value;
    }

    /**
     * @param array<int,array<string,mixed>> $rows User rows.
     */
    private function send_csv(array $rows) {
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $this->csv_filename() . '"');
        header('X-Content-Type-Options: nosniff');
        echo "\xEF\xBB\xBF";
        echo $this->build_csv($rows);
        exit;
    }

    /**
     * @return string
     */
    private function csv_filename() {
        return 'user-history-users-' . gmdate('Y-m-d') . '.csv';
    }

    /**
     * @param array<int,array<string,mixed>> $groups Duplicate groups.
     */
    private function render_groups(array $groups) {
        if ($groups === []) {
            echo '<p>' . esc_html__('None.', 'user-history') . '</p>';
            return;
        }

        foreach ($groups as $group) {
            if (!is_array($group) || !isset($group['users']) || !is_array($group['users'])) {
                continue;
            }

            $value = isset($group['value']) ? (string) $group['value'] : '';
            echo '<h3>';
            echo esc_html($value);
            echo ' <span class="count">(' . esc_html(number_format_i18n(count($group['users']))) . ')</span>';
            echo '</h3>';
            echo '<table class="widefat striped"><thead><tr>';
            echo '<th>' . esc_html__('ID', 'user-history') . '</th>';
            echo '<th>' . esc_html__('Username', 'user-history') . '</th>';
            echo '<th>' . esc_html__('Email', 'user-history') . '</th>';
            echo '<th>' . esc_html__('Display name', 'user-history') . '</th>';
            echo '<th>' . esc_html__('Last login', 'user-history') . '</th>';
            echo '</tr></thead><tbody>';

            foreach ($group['users'] as $user_row) {
                if (!is_array($user_row)) {
                    continue;
                }
                $this->render_user_row($user_row);
            }

            echo '</tbody></table>';
        }
    }

    /**
     * @param array<string,mixed> $user_row User row.
     */
    private function render_user_row(array $user_row) {
        $user_id = isset($user_row['id']) ? (int) $user_row['id'] : 0;
        $username = isset($user_row['username']) ? (string) $user_row['username'] : '';
        $email = isset($user_row['email']) ? (string) $user_row['email'] : '';
        $display_name = isset($user_row['display_name']) ? (string) $user_row['display_name'] : '';
        $last_login = isset($user_row['last_login']) ? (int) $user_row['last_login'] : 0;
        $edit_link = ($user_id > 0 && current_user_can('edit_user', $user_id)) ? get_edit_user_link($user_id) : '';

        echo '<tr>';
        echo '<td>' . esc_html((string) $user_id) . '</td>';
        echo '<td>';
        if (is_string($edit_link) && $edit_link !== '') {
            echo '<a href="' . esc_url($edit_link) . '">' . esc_html($username) . '</a>';
        } else {
            echo esc_html($username);
        }
        echo '</td>';
        echo '<td>' . esc_html($email) . '</td>';
        echo '<td>' . esc_html($display_name) . '</td>';
        echo '<td>' . esc_html($this->format_last_login_for_display($last_login)) . '</td>';
        echo '</tr>';
    }
}
