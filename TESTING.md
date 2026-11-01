# Automated tests

GitHub Actions runs the test suite automatically for every pull request and every push to `main`. No local Docker setup is required to contribute or review a pull request.

The CI matrix covers:

- PHP 7.4 with WordPress 6.0, the plugin's declared minimums.
- PHP 8.3 with the latest stable WordPress release.
- Single-site and multisite WordPress authorization.
- PHP and JavaScript syntax.
- Unit-level source security invariants.
- WordPress integration tests using a real temporary MySQL database.
- Locked Composer dependency auditing.

## What the first tests protect

The suite checks that:

- direct web access remains blocked;
- no unauthenticated WordPress AJAX hooks are introduced;
- first-party plugin code does not add outbound HTTP calls except the GitHub Release update check (vendored Plugin Update Checker; public repo; no token);
- plugin activation creates its history table;
- sensitive profile history is encrypted at rest and still renders correctly;
- password changes store an event but no password value or hash;
- history output escapes HTML and script payloads;
- users cannot count another user's history without permission;
- username changes reject insufficient permissions and invalid nonces;
- subsite administrators cannot change network-global usernames while network super administrators can;
- failed username, mapping, nicename, or audit writes leave identity, history, and site_admins consistent;
- simulated history-clear and username-change insert, update, and commit failures leave records unchanged;
- a nontransactional history or users table configuration is detected and refused;
- historical search input, unique token hashes, and serialized token storage remain within fixed budgets;
- a historically matching user remains excluded when `exclude`, site membership, or another query restriction excludes that ID;
- tampered history ciphertext is rejected visibly;
- legacy CBC rows remain readable and are re-encrypted;
- key rotation keeps previous versions readable;
- an unknown key version fails visibly;
- administrators receive `manage_user_history` on activation, and account editors without that capability cannot clear history;
- default retention does not prune records, while an enabled window removes only eligible rows and writes a maintenance event;
- personal-data export returns decrypted history and the eraser retains records unless explicitly allowed;
- operator IP collection stays on by default and can be disabled;
- Settings retention defaults to 0, IP collection honors the Settings option after the constant, and Clear All Logs requires manage_user_history and a real transaction;
- account lock requires edit_users and edit_user, refuses self-lock and multisite super-admin lock, blocks login and application passwords, and migrates baba_user_locked once;
- login recording stays off by default, logs only existing-account failures, never stores passwords, encrypts non-searchable user-agents, follows collect_ip, and Log Out Everywhere requires edit_users and edit_user;
- dashboard access stays off by default, does not auto-enable when Remove Dashboard Access is present, requires manage_user_history and manage_options to enable, keeps AJAX unlocked unless opted in, and matches allowlist wildcards without treating them as registered admin pages;
- username restrictions stay off by default, do not auto-enable from Restrict Usernames, never rename existing accounts, apply to Change Username only when apply-to-admins is on, and expose user_history_validate_username;
- activity log stays off by default, records only enabled event groups, reuses the daily prune hook for both tables, refuses TRUNCATE, and requires manage_user_history for the page and transactional Clear Activity Log;
- nicename edits use `edit_users` / `edit_user` instead of hard-coded administrator role slugs;
- new accounts get a unique nicename from display name or first+last that is never the username; existing nicenames stay unchanged;
- the empty-history notice is built with text nodes instead of a jQuery `.html()` string;
- plugin header Version matches the readme stable tag;
- GitHub Release tags 1.8.0 and v1.8.0 normalize to the same version;
- the updater points at this public repo and never sets a GitHub token;
- the Release workflow publishes a tag that matches Version: when main is bumped.

These are regression tests for behavior that is already safe. They deliberately do not encode the known insecure behavior as “correct.”

## Known gaps

The suite covers the shipped security controls and does not replace browser testing, load testing, a full privacy-program review, or testing against every third-party plugin.

Nontransactional engines are simulated with the `user_history_table_engine` filter so CI can refuse MyISAM-like configurations without converting WordPress core tables.

## Optional local execution

Local execution requires PHP 7.4 or newer, Composer, MySQL/MariaDB, `curl`, and the usual archive tools. Docker is not required.

```bash
composer install
bash bin/install-wp-tests.sh wordpress_test root root localhost latest
composer lint
composer test
composer test:multisite
node --check assets/js/admin.js
composer audit
```

Change the database user, password, and host arguments as needed. The installer writes WordPress and its test library under `/tmp` by default; set `WP_CORE_DIR` and `WP_TESTS_DIR` to use other locations.

Useful focused commands:

```bash
composer test:unit
composer test:integration
composer test:multisite
```
