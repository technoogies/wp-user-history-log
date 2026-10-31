=== User History ===
Contributors: wpzoom
Tags: user history, user log, audit log, change username, user tracking
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Track changes made to user accounts and allow admins to change usernames.

== Description ==

User History tracks all changes made to user profiles and displays a complete history log on the user edit page. This is especially useful when users change their email or username, making it easy to find them by their previous details.

**Features:**

* **Track Profile Changes** - Automatically logs changes to username, email, display name, first/last name, nickname, website, bio, and role
* **Password Change Logging** - Records when passwords are changed (without storing any password data)
* **Change Username** - Allows admins to change usernames directly from the user edit page (WordPress normally doesn't allow this)
* **Search by Previous Values** - Find users on the All Users page by their old email or username
* **See Who Made Changes** - Each log entry shows whether the user changed their own profile or if an admin made the change
* **Clear History** - Operators with the manage_user_history capability can clear the history log for a user
* **Privacy Export** - WordPress personal-data export includes account history; erasure keeps the audit trail unless explicitly allowed
* **Multisite Compatible** - Works with WordPress multisite installations
* **Members Plugin Compatible** - Works with the Members plugin for multiple role assignments

**Use Cases:**

* Find customers who changed their email after making a purchase
* Track when and who changed user roles
* Audit user profile modifications for security
* Allow username changes without database access

== Installation ==

1. Upload the `user-history` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Visit any user's edit page to see their Account History section

== Frequently Asked Questions ==

= Where can I see the user history? =

Go to Users > All Users, click on any user to edit their profile, and scroll down to the "Account History" section.

= How do I change a username? =

On the user edit page, click the "Change" link next to the username field. Enter the new username and click "Change" to save.

= Who can change usernames on multisite? =

Because usernames are shared across the network, multisite username changes require a network super administrator with the manage_network_users capability. Single-site permissions are unchanged. Super-administrator mapping is updated only after the intended list is prepared and verified; a failed write restores the previous identity, audit history, and mapping.

= How is history encrypted? =

Sensitive history values use versioned authenticated encryption. New writes prefer libsodium secretbox and fall back to AES-256-GCM. Existing AES-256-CBC rows stay readable and are re-encrypted during upgrade or when viewed. Decryption failures are shown as an unavailable notice, not a blank field. Keys are derived from WordPress salts and a stored version option; an optional USER_HISTORY_ENCRYPTION_KEY constant can pin the key material in wp-config.php.

Encryption protects stored history from casual database reading. It does not protect against a fully compromised WordPress host, because that host already has the salts or optional key used to decrypt the values.

= Does this plugin store passwords? =

No. The plugin only logs that a password was changed, along with the date and who changed it. No password values (hashed or otherwise) are ever stored.

= Can I search for users by their old email? =

Yes! On the All Users page, use the search box to search for any previous email, username, or name. Users who previously had matching values will appear in the results. Historical matches stay inside the original user query, so excluded users, non-members, and other query restrictions still apply.

= What user fields are tracked? =

* Username (user_login)
* Email (user_email)
* Password (change event only)
* Display Name
* Nicename
* Website URL
* First Name
* Last Name
* Nickname
* Biographical Info
* Role (including multiple roles with Members plugin)

= Is this plugin multisite compatible? =

Yes. The plugin works on multisite installations and properly handles super admin username changes.

= Does it work with the Members plugin? =

Yes. The plugin correctly tracks role changes when using the Members plugin, which allows assigning multiple roles to users.

= How do I clear a user's history? =

On the user edit page, scroll down to the Account History section and click the "Clear Log" button. Clearing requires the dedicated manage_user_history capability in addition to edit_users. Activation and upgrade grant that capability to administrators. An account editor who can view history but does not have manage_user_history cannot clear it. Clearing and username changes require InnoDB. If the history table is not transactional and cannot be converted, those actions are refused and no records are changed.

= Does this plugin automatically delete old history? =

No. Retention pruning stays off unless the user_history_retention_days option or filter is set to a positive number of days. When enabled, only older rows are removed and a maintenance audit event is written.

= What happens to history during a personal-data request or uninstall? =

Export Personal Data includes decrypted account-history rows. The eraser keeps history as an audit record unless the user_history_erase_personal_data filter allows removal. Uninstalling the plugin does not delete history unless USER_HISTORY_DELETE_DATA_ON_UNINSTALL is defined or the user_history_delete_data_on_uninstall option is set.

= Are operator IP addresses stored? =

Yes, by default. To stop collecting them without changing other behavior, define USER_HISTORY_COLLECT_IP as false or return false from the user_history_collect_ip filter.

== Screenshots ==

1. Account History section on the user edit page
2. Change username feature
3. Search results showing users found by previous email/username

== Changelog ==

= 1.1.1 =
* Replaced hard-coded administrator role-name checks with edit_users / edit_user capability policy for nicename edits
* Built the empty-history notice with text nodes instead of a jQuery .html() string
* Omitted raw database and update error details from logs unless WP_DEBUG is enabled
* Documented that history encryption does not protect a fully compromised WordPress host

= 1.1.0 =
* Required the dedicated manage_user_history capability to clear history, granted to administrators on activation and upgrade
* Left viewing and historical search on the existing edit_users / edit_user checks
* Added optional retention pruning that stays off until a positive day count is configured
* Registered WordPress personal-data export and a conservative eraser that retains history by default
* Documented uninstall so history is kept unless the operator explicitly chooses deletion
* Made operator IP collection optional without changing the default

= 1.0.9 =
* Replaced unauthenticated AES-256-CBC history encryption with versioned authenticated encryption
* Kept legacy ciphertext readable during migration and showed decryption failures instead of blank values
* Added salt-derived key versioning and rotation without a separate key store

= 1.0.8 =
* Kept historical user-search matches inside the existing WordPress user query
* Preserved exclude, site membership, and other query restrictions when a previous value matches

= 1.0.7 =
* Required and verified InnoDB for the history table during activation and upgrade
* Refused history clearing and username changes when transactional storage is unavailable
* Checked transaction begin, commit, and rollback results before treating destructive actions as complete

= 1.0.6 =
* Made username changes and the multisite super-administrator mapping verify-and-compensate on failure
* Added failure-injection coverage for mapping, identity, and audit writes

= 1.0.5 =
* Restricted multisite username changes to network super administrators with manage_network_users
* Added single-site and multisite authorization regression coverage

= 1.0.4 =
* Bounded historical search input, unique tokens, and serialized token storage
* Replaced oversized searchable audit values with an encrypted omission notice
* Cleared legacy search-token payloads that exceed the new storage budget

= 1.0.3 =
* Added Delete User button on user edit page for quick access
* Added Requires at least and Requires PHP headers to plugin file
* Code improvements for WordPress.org plugin directory compliance

= 1.0.2 =
* Added Clear Log button to delete history for a user
* Improved role change tracking for Members plugin compatibility
* Fixed false positive password change logging when saving without changes
* Fixed duplicate role change entries

= 1.0.1 =
* Added search functionality to find users by previous email/username
* Added database index for faster history searches
* Improved password change logging (no values stored)
* Added table existence check to prevent errors

= 1.0.0 =
* Initial release
* Track user profile changes
* Change username feature
* Account History display on user edit page

== Upgrade Notice ==

= 1.1.1 =
Uses capability checks for nicename edits and keeps raw database errors out of logs unless WP_DEBUG is on.

= 1.1.0 =
Adds a dedicated clear-history capability and optional retention/privacy controls. Existing history is kept unless an operator explicitly enables pruning, erasure, or uninstall deletion.

= 1.0.9 =
Stores sensitive history with authenticated encryption and migrates readable legacy rows.

= 1.0.8 =
Keeps historical user search inside existing All Users query restrictions.

= 1.0.7 =
Requires InnoDB for history clearing and username changes, and refuses those actions when a transaction cannot be guaranteed.

= 1.0.6 =
Makes username changes and super-administrator mapping failure-safe.

= 1.0.5 =
Restricts network-global username changes to appropriately authorized multisite administrators.

= 1.0.4 =
Limits historical search resource use and removes oversized legacy token payloads.

= 1.0.3 =
Adds Delete User button on user edit page. Code improvements for WordPress.org compliance.

= 1.0.2 =
Adds Clear Log button, fixes role tracking with Members plugin, and fixes false positive password logging.

= 1.0.1 =
Adds ability to search users by their previous email or username on the All Users page.
