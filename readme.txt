=== User History ===
Contributors: wpzoom
Tags: user history, user log, audit log, change username, user tracking
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.0.7
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
* **Clear History** - Admins can clear the history log for any user
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

= Does this plugin store passwords? =

No. The plugin only logs that a password was changed, along with the date and who changed it. No password values (hashed or otherwise) are ever stored.

= Can I search for users by their old email? =

Yes! On the All Users page, use the search box to search for any previous email, username, or name. Users who previously had matching values will appear in the results.

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

On the user edit page, scroll down to the Account History section and click the "Clear Log" button. Clearing and username changes require InnoDB. If the history table is not transactional and cannot be converted, those actions are refused and no records are changed.

== Screenshots ==

1. Account History section on the user edit page
2. Change username feature
3. Search results showing users found by previous email/username

== Changelog ==

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
