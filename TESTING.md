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
- the plugin does not add outbound HTTP calls;
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
- an unknown key version fails visibly.

These are regression tests for behavior that is already safe. They deliberately do not encode the known insecure behavior as “correct.”

## Known gaps

The initial suite does not claim that the open security findings are fixed. Follow-up fixes need new tests for:

- audit retention and a dedicated audit-management capability.

Nontransactional engines are simulated with the `user_history_table_engine` filter so CI can refuse MyISAM-like configurations without converting WordPress core tables. The suite also does not replace browser testing, load testing, privacy review, or testing against every third-party plugin.

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
