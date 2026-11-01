<?php

/**
 * Unique nicename generation for new WordPress accounts.
 *
 * New users only. Existing user_nicename values are never rewritten.
 * Slug comes from display name or first+last, is never equal to user_login,
 * and gets a numeric suffix when needed. Sanitize and uniqueness reuse
 * User_History::sanitize_nicename_value() and User_History::is_nicename_unique().
 */

if (!defined('ABSPATH')) {
    exit;
}

class User_History_New_User_Nicename {

    const MAX_LENGTH = 50;

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

        add_filter('wp_pre_insert_user_data', [$this, 'filter_pre_insert_user_data'], 20, 4);
    }

    /**
     * Assign a unique nicename while WordPress is creating a user.
     *
     * @param array<string,mixed> $data     Prepared users-table columns.
     * @param bool                $update   Whether this is an existing account.
     * @param int                 $user_id  User ID, or 0 when inserting.
     * @param array<string,mixed> $userdata Original wp_insert_user() input.
     * @return array<string,mixed>
     */
    public function filter_pre_insert_user_data($data, $update, $user_id, $userdata = []) {
        if ($update || !is_array($data)) {
            return $data;
        }

        if (!is_array($userdata)) {
            $userdata = [];
        }

        $data['user_nicename'] = $this->generate_unique_nicename($data, $userdata, (int) $user_id);

        return $data;
    }

    /**
     * Build a unique nicename for a new account.
     *
     * @param array<string,mixed> $data     Prepared users-table columns.
     * @param array<string,mixed> $userdata Original wp_insert_user() input.
     * @param int                 $user_id  User ID to exclude from uniqueness, or 0.
     * @return string
     */
    public function generate_unique_nicename($data, $userdata, $user_id = 0) {
        $login = $this->string_from($data, 'user_login');
        if ($login === '') {
            $login = $this->string_from($userdata, 'user_login');
        }

        $seed = $this->seed_from_userdata($userdata, $login);
        if ($seed === '') {
            $seed = $this->string_from($data, 'user_nicename');
        }
        if ($seed === '') {
            $seed = $login;
        }

        return $this->uniquify($seed, $login, (int) $user_id);
    }

    /**
     * Prefer a real display name, then first+last.
     *
     * @param array<string,mixed> $userdata Original wp_insert_user() input.
     * @param string              $login    user_login for the new account.
     * @return string
     */
    private function seed_from_userdata($userdata, $login) {
        $display = $this->string_from($userdata, 'display_name');
        $first = $this->string_from($userdata, 'first_name');
        $last = $this->string_from($userdata, 'last_name');
        $full = trim($first . ' ' . $last);

        if ($display !== '' && !$this->same_login($display, $login)) {
            return $display;
        }

        if ($full !== '') {
            return $full;
        }

        return '';
    }

    /**
     * Sanitize, keep the value off user_login, and add -2, -3, ... if needed.
     *
     * @param string $seed    Display name, first+last, or WordPress default slug.
     * @param string $login   user_login that the nicename must not equal.
     * @param int    $user_id User ID to exclude from uniqueness.
     * @return string
     */
    private function uniquify($seed, $login, $user_id) {
        $base = $this->plugin->sanitize_nicename_value($seed);
        if ($base === '') {
            $base = 'user';
        }

        $suffix = 0;
        $attempts = 0;

        do {
            if ($suffix === 0) {
                $candidate = $this->truncate($base, self::MAX_LENGTH);
                $suffix = 2;
            } else {
                $suffix_string = '-' . $suffix;
                $candidate = $this->truncate($base, self::MAX_LENGTH - strlen($suffix_string)) . $suffix_string;
                $suffix++;
            }

            $attempts++;
        } while (
            $attempts < 10000
            && (
                $this->same_login($candidate, $login)
                || !$this->plugin->is_nicename_unique($candidate, $user_id)
            )
        );

        return $candidate;
    }

    /**
     * @param array<string,mixed> $source Input array.
     * @param string              $key    Array key.
     * @return string
     */
    private function string_from($source, $key) {
        if (!is_array($source) || !isset($source[$key]) || !is_scalar($source[$key])) {
            return '';
        }

        return trim((string) $source[$key]);
    }

    /**
     * @param string $value Candidate nicename or display name.
     * @param string $login user_login.
     * @return bool
     */
    private function same_login($value, $login) {
        if ($login === '') {
            return false;
        }

        return strtolower($value) === strtolower($login);
    }

    /**
     * @param string $value  Slug to fit.
     * @param int    $length Maximum characters.
     * @return string
     */
    private function truncate($value, $length) {
        $length = (int) $length;
        if ($length < 1) {
            return '';
        }

        if (function_exists('mb_substr')) {
            return mb_substr($value, 0, $length);
        }

        return substr($value, 0, $length);
    }
}
