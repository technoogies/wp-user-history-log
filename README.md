# User History

A WordPress plugin that tracks changes made to user accounts and allows admins to change usernames.

<img width="1547" height="1071" alt="image" src="https://github.com/user-attachments/assets/1ba77413-4e63-416b-8ca4-242e499acadb" />


## Features

- **Track Profile Changes** - Automatically logs changes to username, email, display name, first/last name, nickname, website, bio, and role
- **Password Change Logging** - Records when passwords are changed (without storing any password data)
- **Change Username** - Allows admins to change usernames directly from the user edit page (WordPress normally doesn't allow this)
- **Search by Previous Values** - Find users on the All Users page by their old email or username
- **See Who Made Changes** - Each log entry shows whether the user changed their own profile or if an admin made the change
- **Clear History** - Operators with the dedicated `manage_user_history` capability can clear a user's history log
- **User History Settings** - A User History admin menu (after Users) with retention, IP collection, and Clear All Logs
- **Lock Accounts** - Lock a user to sign them out and block logins; migrate existing Lock User Account flags once
- **Login and session monitoring** - Optional login/logout/failed-login history (off by default) and a Sessions tab with Log Out Everywhere
- **Dashboard Access** - Optional `/wp-admin` restriction (off by default). Enabling it requires `manage_user_history` and `manage_options`
- **Username Restrictions** - Optional registration username rules (off by default) with a Test Usernames tool
- **Activity Log** - Optional site-wide log of content, media, comments, users, logins, extensions, and settings (off by default)
- **Unique nicenames for new accounts** - New users get a URL-friendly nicename from display name or first+last; it is never the username and stays unique. Existing accounts are not rewritten
- **GitHub updates** - The Plugins screen shows updates from this repo’s public GitHub Releases (no WordPress.org listing and no GitHub token)
- **Privacy Export** - WordPress personal-data export includes decrypted account history; erasure keeps the audit trail unless an operator explicitly allows removal
- **Multisite Compatible** - Works with WordPress multisite installations
- **Members Plugin Compatible** - Works with the Members plugin for multiple role assignments

## Requirements

- WordPress 5.0+
- PHP 7.4+

## Installation

1. Download the plugin and upload to `/wp-content/plugins/user-history/`
2. Activate through the 'Plugins' menu in WordPress
3. Visit **User History → Settings** for retention, IP, and Activity Log options, or any user's edit page to see their Account History section

After a GitHub Release exists, **Plugins** shows an update when that Release tag is newer than the installed `Version:` header. Click **Check for updates** next to the plugin if you just published a Release and do not want to wait for the next automatic check (about 12 hours).

### Publishing a GitHub Release

WordPress only sees an update after a **Release** exists for the new `Version:`. Merging a version bump to `main` runs the **Release** GitHub Action, which creates a tag that matches `Version:` (for example `1.9.0`) and publishes that Release.

**One-time first Release:** this repo had no Releases when the updater shipped. The Action publishes a Release for the current `Version:` when that Release does not exist yet (a version bump on `main`, or **Actions → Release → Run workflow**). After a merge, wait a minute and open [Releases](https://github.com/technoogies/wp-user-history-log/releases). If `1.9.0` is missing, publish it once by hand:

1. Open the repository on GitHub.
2. Click **Releases** in the right column (or the tag icon).
3. Click **Create a new release** (or **Draft a new release**).
4. Click **Choose a tag**, type the plugin `Version:` exactly (example: `1.9.0`), then **Create new tag**. `v1.9.0` also works; the updater treats both as 1.9.0.
5. Set the target to **main**.
6. Set the release title to that same version.
7. Paste the changelog for that version if you want it shown on **View details**.
8. Leave **Set as a pre-release** unchecked (those are ignored).
9. Click **Publish release**.

Do this once for the current version if no Release exists. Later version bumps on `main` should publish themselves.

## Usage

### Viewing History

Go to **Users > All Users**, click on any user to edit their profile, and scroll down to the "Account History" section.

### Changing a Username

On the user edit page, click the "Change" link next to the username field. Enter the new username and click "Change" to save.

On WordPress multisite, usernames belong to the shared network users table. Username changes therefore require both the `manage_network_users` capability and super-administrator status, in addition to the existing `edit_users` and target-level `edit_user` checks. Single-site authorization is unchanged.

If the renamed account is a super administrator, the plugin prepares and verifies the `site_admins` mapping before committing identity changes. A failed mapping, user, nicename, display-name, or audit write leaves the previous username, nicename, display name, audit history, and super-administrator list unchanged.

Username changes and history clearing require InnoDB (or a table that can be converted to InnoDB). Activation and upgrade create the history table as InnoDB and convert an existing nontransactional history table when possible. If transactional storage is unavailable, those destructive actions are refused and no rows are changed. The plugin does not alter WordPress core tables such as `wp_users`.

### Searching by Previous Values

On the All Users page, use the search box to search for any previous email, username, or name. Users who previously had matching values will appear in the results.

Historical matches are added inside the existing WordPress user-search expression. Users that the original query already excluded — for example by `exclude`, site membership, role, or another plugin AND restriction — stay excluded.

Historical search indexing uses conservative resource limits:

- Searchable values up to 1,024 bytes are eligible for indexing.
- Each history entry stores at most 128 unique token hashes and 8,192 serialized token bytes.
- Search requests use at most five token hashes.

WordPress still saves a profile value that exceeds 1,024 bytes. To avoid copying or indexing oversized sensitive content, the history entry stores an encrypted fixed omission notice instead of that value. Normal usernames, email addresses, display names, and personal names remain well within the limit.

### Clearing History

On the user edit page, scroll down to the Account History section and click the "Clear Log" button. The button and AJAX action require the dedicated `manage_user_history` capability in addition to the existing `edit_users` / `edit_user` checks. Activation and upgrade grant that capability to the administrator role. An account editor who can view or search history but does not have `manage_user_history` cannot clear it.

Clearing deletes existing history and writes a maintenance event in one transaction; a failed maintenance insert or commit leaves the previous history unchanged.

### Settings

Open **User History → Settings** (also linked from the Plugins screen). The menu requires `manage_user_history`. An account that can edit users but does not have that capability cannot open it.

### Retention

Automatic retention pruning is off by default. The Settings field shows **0** (keep forever / cleanup off). Existing history and activity rows are kept until an operator types a positive day count in Settings or sets the `user_history_retention_days` option or filter. When enabled, the existing daily hook removes only rows older than that window from both the account-history table and the activity log, and writes a maintenance audit event. A failed delete, maintenance insert, or commit leaves the previous rows unchanged. Settings does not add a second cron.

### Clear All Logs

On **User History → Settings**, operators with `manage_user_history` can clear every history row on the site. The action asks for confirmation, runs in a real database transaction, deletes rows (it does not truncate the table), and writes a maintenance event on the operator's account history. If a transaction cannot start, nothing is changed. Clear All Logs does not empty the Activity Log; that has its own transactional Clear Activity Log button.

### Activity Log

Open **User History → Activity Log**. The page and the enable checkbox require `manage_user_history`. The log stays **off** after an update. When enabled, choose event groups (Content, Media, Comments, Users, Logins, Extensions, Settings). Descriptions are built at display time from a stored action key. IPs follow the same Settings / `USER_HISTORY_COLLECT_IP` rules as account history and use `REMOTE_ADDR` only. Clear Activity Log needs `manage_user_history`, uses a real transaction, deletes rows (it does not truncate), and writes a maintenance event.

### Personal Data and Uninstall

WordPress Tools → Export Personal Data includes decrypted account-history rows. The registered eraser keeps history as an audit record unless the `user_history_erase_personal_data` filter returns true. Uninstalling the plugin does not drop the history table or options unless `USER_HISTORY_DELETE_DATA_ON_UNINSTALL` is defined as true or the `user_history_delete_data_on_uninstall` option is set.

Operator IP addresses are still collected by default. Uncheck **Record IP addresses** on Settings to stop storing them, define `USER_HISTORY_COLLECT_IP` as false, or return false from the `user_history_collect_ip` filter. The constant wins when it is defined.

## Tracked Fields

| Field | Description |
|-------|-------------|
| Username | user_login |
| Email | user_email |
| Password | Change event only (no values stored) |
| Display Name | display_name |
| Nicename | user_nicename |
| Website URL | user_url |
| First Name | first_name meta |
| Last Name | last_name meta |
| Nickname | nickname meta |
| Biographical Info | description meta |
| Role | Capabilities (supports multiple roles) |

## Hooks

Sensitive history values are stored with versioned authenticated encryption (libsodium `secretbox` when available, otherwise OpenSSL AES-256-GCM). Each value is prefixed with a format and key version. Legacy AES-256-CBC rows remain readable and are re-encrypted on upgrade or when displayed. A failed decryption is shown as an explicit unavailable notice instead of a blank value.

Encryption protects stored history from casual reading of the database. It does not protect against a fully compromised WordPress host: the same process that encrypts values can also decrypt them, and key material is derived from WordPress salts or an optional `USER_HISTORY_ENCRYPTION_KEY` constant on that host.

The current key is derived from WordPress salts and a stored key-version option. Operators do not need a separate key store. To pin key material, add this optional constant to `wp-config.php` before activation or rotation:

```php
define('USER_HISTORY_ENCRYPTION_KEY', 'replace-with-a-long-random-secret');
```

Previous key versions are retained only for decryption. To rotate:

```php
do_action('user_history_rotate_encryption_key');
```

Optional governance constants and options:

```php
// Stop storing operator IP addresses. Collection remains on unless this is set.
// Settings can also store user_history_collect_ip as 0. The constant wins when defined.
define('USER_HISTORY_COLLECT_IP', false);

// Keep history forever by default (Settings shows 0). A positive value enables daily pruning of older rows.
update_option('user_history_retention_days', 365);

// Wipe the history table only when the operator explicitly uninstalls with this set.
define('USER_HISTORY_DELETE_DATA_ON_UNINSTALL', true);
```

### Actions

```php
// Fires after a username has been changed
do_action('user_history_username_changed', $user_id, $old_username, $new_username);

// Increments the stored key version and keeps previous versions for decryption
do_action('user_history_rotate_encryption_key');

// Daily hook used only when a positive retention window is configured
do_action('user_history_prune_history');
```

### Filters

```php
// Optional positive day count. Default 0 keeps all history.
add_filter('user_history_retention_days', function ($days) {
    return (int) $days;
});

// Allow Tools → Erase Personal Data to remove a user's history. Default false.
add_filter('user_history_erase_personal_data', '__return_true');

// Operator IP collection stays on unless this returns false.
add_filter('user_history_collect_ip', function ($collect) {
    return (bool) $collect;
});

// Filter an activity log entry before it is saved. Return false to skip.
add_filter('user_history_activity_log_entry', function ($entry) {
    return $entry;
});
```

## Screenshots

### Account History Section
The history log appears at the bottom of the user edit page, showing all tracked changes with timestamps and who made each change.

### Change Username
Click "Change" next to the username field to reveal an inline form for changing the username.

### Locking an account

On a user edit page, use **Lock Account**. That user is signed out immediately and cannot sign in until unlocked. You cannot lock yourself or a multisite super administrator. Lock and unlock require `edit_users` and `edit_user` on that account.

**Users** shows a Locked badge, Lock / Unlock row actions, bulk actions, and a Locked view. **User History → Lock Accounts** holds the custom login message and a short list of locked users.

Accounts already locked by the Lock User Account plugin (`baba_user_locked = yes`) are copied once on activation or upgrade. WP-CLI can still act as a locked user so they can be unlocked from the command line.

### Logins and sessions

**User History → Settings** has **Record logins** off by default. When you turn it on, Account History → **Logins** shows login, logout, and failed-login rows (failed attempts only when the typed username or email matches a real account). Passwords are never stored. The browser/OS label is parsed locally. IP follows the existing Record IP addresses setting.

The **Sessions** tab is always available to people who can edit that user. **Log Out Everywhere** requires `edit_users` and `edit_user`. Confirming it on your own account warns that you will be signed out too.

### Dashboard access

**User History → Dashboard Access** is off until an operator with `manage_user_history` and `manage_options` turns it on. Restricted users are redirected (homepage by default). Profile access stays available unless you uncheck it. AJAX stays unlocked by default. An allowlist can keep specific admin URLs reachable (`admin.php?page=example-*` matches those pages only).

If Remove Dashboard Access options exist (`rda_*`), they are copied once. The restriction stays off even when that plugin is still active.

### Username restrictions

**User History → Username Restrictions** is off until you turn it on. Rules apply to **new** registrations only. Existing accounts are never renamed and can still log in. Block exact names (`admin`) or fragments (`support` matches `mysupport`). Disallow spaces separately. Test Usernames uses the same reasons as registration.

Administrators bypass the rules on **Users → Add New** and **Change Username** unless **Also apply the rules to usernames chosen by administrators** is on. The `user_history_validate_username` filter can add a custom rule. Restrict Usernames settings (`c2c_restrict_usernames`) are imported once; the switch stays off.

### New account nicenames

New accounts only. The plugin slugs the nicename from display name, or from first+last when that is what **Users → Add New** provides. The value is never equal to the username. If that slug is already taken, it adds `-2`, `-3`, and so on. Existing `user_nicename` values stay as they are. You can still edit Nicename under Nickname on the user profile.

## Changelog

### 1.9.0
- Show plugin updates in wp-admin from this repo’s public GitHub Releases
- Vendored Plugin Update Checker so sites do not need Composer or a GitHub token
- Added a GitHub Action that publishes a Release when `Version:` is bumped on `main`

### 1.8.0
- Generated a unique nicename for new accounts from display name or first+last
- Kept the nicename different from the username and added a suffix when that slug was already taken
- Left existing accounts unchanged; the profile Nicename field stays editable under Nickname

### 1.7.0
- Added an optional site-wide Activity Log (default off) under User History → Activity Log
- Reused the existing daily retention hook to prune both account history and activity rows; no second cron and no TRUNCATE
- Clear Activity Log requires manage_user_history and a real transaction

### 1.6.0
- Added optional registration username rules under User History → Username Restrictions (default off)
- Added a Test Usernames tool and optional apply-to-admins checks for Add New and Change Username
- Imported Restrict Usernames settings once without auto-enabling the rules

### 1.5.0
- Added optional `/wp-admin` restriction under User History → Dashboard Access (default off)
- Imported Remove Dashboard Access settings once without auto-enabling the restriction

### 1.4.0
- Added optional login/logout/failed-login recording (default off) with encrypted, non-searchable user-agents
- Added Account History Logins and Sessions tabs, plus Log Out Everywhere

### 1.3.0
- Added account lock/unlock with session termination, login and application-password blocking, and a Locked view on All Users
- Added User History → Lock Accounts for a custom lock message
- Migrated Lock User Account plugin flags once (`baba_user_locked` → `user_history_locked`)

### 1.2.0
- Added a User History admin menu after Users, with Settings as the only page
- Exposed retention (default 0 / keep forever) and IP collection (default on) on Settings
- Added Clear All Logs behind `manage_user_history`, using a real transaction and a maintenance event
- Linked Settings from the Plugins screen

### 1.1.1
- Replaced hard-coded administrator role-name checks with `edit_users` / `edit_user` capability policy for nicename edits
- Built the empty-history notice with text nodes instead of a jQuery `.html()` string
- Omitted raw database and update error details from logs unless `WP_DEBUG` is enabled
- Documented that history encryption does not protect a fully compromised WordPress host

### 1.1.0
- Required the dedicated `manage_user_history` capability to clear history, granted to administrators on activation and upgrade
- Left viewing and historical search on the existing `edit_users` / `edit_user` checks
- Added optional retention pruning that stays off until a positive day count is configured
- Registered WordPress personal-data export and a conservative eraser that retains history by default
- Documented uninstall so history is kept unless the operator explicitly chooses deletion
- Made operator IP collection optional without changing the default

### 1.0.9
- Replaced unauthenticated AES-256-CBC history encryption with versioned authenticated encryption
- Kept legacy ciphertext readable during migration and showed decryption failures instead of blank values
- Added salt-derived key versioning and rotation without a separate key store

### 1.0.8
- Kept historical user-search matches inside the existing `WP_User_Query` search group
- Preserved exclude, site membership, and other query restrictions when a previous value matches

### 1.0.7
- Required and verified InnoDB for the history table during activation and upgrade
- Refused history clearing and username changes when transactional storage is unavailable
- Checked transaction begin, commit, and rollback results before treating destructive actions as complete

### 1.0.6
- Made username changes and the multisite super-administrator mapping verify-and-compensate on failure
- Added failure-injection coverage for mapping, identity, and audit writes

### 1.0.5
- Restricted multisite username changes to network super administrators with `manage_network_users`
- Added single-site and multisite authorization regression coverage

### 1.0.4
- Bounded historical search input, unique tokens, and serialized token storage
- Replaced oversized searchable audit values with an encrypted omission notice
- Cleared legacy search-token payloads that exceed the new storage budget

### 1.0.3
- Added Delete User button on user edit page for quick access
- Added Requires at least and Requires PHP headers to plugin file
- Code improvements for WordPress.org plugin directory compliance

### 1.0.2
- Added Clear Log button to delete history for a user
- Improved role change tracking for Members plugin compatibility
- Fixed false positive password change logging when saving without changes
- Fixed duplicate role change entries

### 1.0.1
- Added search functionality to find users by previous email/username
- Added database index for faster history searches
- Improved password change logging (no values stored)
- Added table existence check to prevent errors

### 1.0.0
- Initial release
- Track user profile changes
- Change username feature
- Account History display on user edit page

## License

GPL v2 or later - https://www.gnu.org/licenses/gpl-2.0.html

## Credits

Developed by [WPZOOM](https://www.wpzoom.com)

GitHub Release updates use [YahnisElsts Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) 5.7 (MIT), copied into `lib/plugin-update-checker`.
