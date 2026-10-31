<?php

final class HistoryEncryptionTest extends WP_UnitTestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        parent::setUp();

        if (is_multisite()) {
            $this->markTestSkipped('Single-site compatibility test.');
        }

        $this->plugin = User_History::get_instance();
        $this->plugin->activate();
        $this->clearHistoryTable();
    }

    protected function tearDown(): void
    {
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_new_sensitive_values_use_a_versioned_authenticated_envelope(): void
    {
        $ciphertext = $this->encrypt('Authenticated History');

        $this->assertStringStartsWith('uh1:', $ciphertext);
        $this->assertMatchesRegularExpression('/^uh1:(nacl|gcm):1:/', $ciphertext);
        $this->assertSame('Authenticated History', $this->decrypt($ciphertext));
        $this->assertStringNotContainsString('Authenticated History', $ciphertext);
    }

    public function test_tampered_ciphertext_is_rejected_visibly(): void
    {
        $ciphertext = $this->encrypt('Leave This Secret Intact');
        $parts = explode(':', $ciphertext, 4);
        $this->assertCount(4, $parts);

        $raw = base64_decode($parts[3], true);
        $this->assertNotFalse($raw);
        $this->assertNotSame('', $raw);
        $last = strlen($raw) - 1;
        $raw[$last] = $raw[$last] === "\0" ? "\x01" : "\0";
        $tampered = $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':' . base64_encode($raw);

        $entry = $this->historyEntry('first_name', $tampered);
        $rendered = $this->plugin->render_history_rows([$entry]);

        $this->assertStringContainsString('history unavailable: decryption failed', $rendered);
        $this->assertStringNotContainsString('Leave This Secret Intact', $rendered);
        $this->assertNotSame('', $this->decrypt($tampered));
    }

    public function test_legacy_cbc_records_remain_readable_and_are_reencrypted(): void
    {
        global $wpdb;

        $legacy = $this->encryptLegacyCbc('Legacy Readable Name');
        $this->assertStringStartsNotWith('uh1:', $legacy);

        $id = $this->insertHistoryRow('first_name', $legacy);
        $this->assertSame('Legacy Readable Name', $this->decrypt($legacy));

        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $this->historyTable() . ' WHERE id = %d', $id));
        $rendered = $this->plugin->render_history_rows([$row]);

        $this->assertStringContainsString('Legacy Readable Name', $rendered);

        $updated = $wpdb->get_var($wpdb->prepare('SELECT new_value FROM ' . $this->historyTable() . ' WHERE id = %d', $id));
        $this->assertStringStartsWith('uh1:', $updated);
        $this->assertSame('Legacy Readable Name', $this->decrypt($updated));
    }

    public function test_upgrade_migrates_legacy_ciphertext_in_a_batch(): void
    {
        global $wpdb;

        $legacy = $this->encryptLegacyCbc('Batch Migrated Name');
        $id = $this->insertHistoryRow('first_name', $legacy);
        delete_option('user_history_crypto_current');

        $method = new ReflectionMethod(User_History::class, 'maybe_migrate_encryption');
        $method->setAccessible(true);
        $method->invoke($this->plugin);

        $updated = $wpdb->get_var($wpdb->prepare('SELECT new_value FROM ' . $this->historyTable() . ' WHERE id = %d', $id));
        $this->assertStringStartsWith('uh1:', $updated);
        $this->assertSame('Batch Migrated Name', $this->decrypt($updated));
    }

    public function test_key_rotation_keeps_previous_versions_readable(): void
    {
        [$administrator, $subject] = $this->createActorAndSubject();
        wp_set_current_user($administrator);

        $first = wp_update_user(
            [
                'ID'         => $subject,
                'first_name' => 'Before Rotation',
            ]
        );
        $this->assertSame($subject, $first);

        $before = $this->latestValue($subject, 'first_name');
        $this->assertMatchesRegularExpression('/^uh1:(nacl|gcm):1:/', $before);

        $next_version = $this->plugin->rotate_encryption_key();
        $this->assertSame(2, $next_version);
        $this->assertSame('Before Rotation', $this->decrypt($before));

        $second = wp_update_user(
            [
                'ID'         => $subject,
                'first_name' => 'After Rotation',
            ]
        );
        $this->assertSame($subject, $second);

        $after = $this->latestValue($subject, 'first_name');
        $this->assertMatchesRegularExpression('/^uh1:(nacl|gcm):2:/', $after);
        $this->assertSame('After Rotation', $this->decrypt($after));

        $entry = (object) [
            'id'          => 0,
            'user_id'     => $subject,
            'changed_by'  => $administrator,
            'field_name'  => 'first_name',
            'field_label' => 'First Name',
            'old_value'   => $before,
            'new_value'   => $after,
            'change_type' => 'update',
            'created_at'  => current_time('mysql'),
        ];
        $rendered = $this->plugin->render_history_rows([$entry]);
        $this->assertStringContainsString('Before Rotation', $rendered);
        $this->assertStringContainsString('After Rotation', $rendered);
    }

    public function test_unknown_key_version_fails_visibly(): void
    {
        $ciphertext = $this->encrypt('Hidden From Unknown Keys');
        $unknown = preg_replace('/^uh1:(nacl|gcm):\d+:/', 'uh1:$1:99:', $ciphertext);
        $this->assertNotSame($ciphertext, $unknown);

        $entry = $this->historyEntry('first_name', $unknown);
        $rendered = $this->plugin->render_history_rows([$entry]);

        $this->assertStringContainsString('history unavailable: unknown key version', $rendered);
        $this->assertStringNotContainsString('Hidden From Unknown Keys', $rendered);
        $this->assertSame(
            '[history unavailable: unknown key version]',
            $this->decrypt($unknown)
        );
    }

    public function test_forced_gcm_backend_round_trips_when_available(): void
    {
        if (!$this->supportsGcm()) {
            $this->markTestSkipped('AES-256-GCM is not available.');
        }

        $filter = static function () {
            return 'gcm';
        };
        add_filter('user_history_encryption_backend', $filter);

        try {
            $ciphertext = $this->encrypt('GCM History Value');
        } finally {
            remove_filter('user_history_encryption_backend', $filter);
        }

        $this->assertStringStartsWith('uh1:gcm:1:', $ciphertext);
        $this->assertSame('GCM History Value', $this->decrypt($ciphertext));
    }

    private function encrypt($value): string
    {
        $method = new ReflectionMethod(User_History::class, 'encrypt_value');
        $method->setAccessible(true);

        return $method->invoke($this->plugin, $value);
    }

    private function decrypt($value): string
    {
        $method = new ReflectionMethod(User_History::class, 'decrypt_value');
        $method->setAccessible(true);

        return $method->invoke($this->plugin, $value);
    }

    private function encryptLegacyCbc($value): string
    {
        $method = new ReflectionMethod(User_History::class, 'get_legacy_derived_key');
        $method->setAccessible(true);
        $key = $method->invoke($this->plugin);
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($value, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        return base64_encode($iv . $encrypted);
    }

    private function insertHistoryRow($field_name, $new_value): int
    {
        global $wpdb;

        $wpdb->insert(
            $this->historyTable(),
            [
                'user_id'            => 1,
                'changed_by'         => 1,
                'field_name'         => $field_name,
                'field_label'        => 'First Name',
                'old_value'          => '',
                'new_value'          => $new_value,
                'search_tokens'      => '',
                'changed_by_details' => $this->encryptLegacyCbc('{"operator_id":1}'),
                'change_type'        => 'update',
                'created_at'         => current_time('mysql'),
            ]
        );

        return (int) $wpdb->insert_id;
    }

    private function historyEntry($field_name, $new_value): object
    {
        return (object) [
            'id'          => 0,
            'user_id'     => 1,
            'changed_by'  => 1,
            'field_name'  => $field_name,
            'field_label' => 'First Name',
            'old_value'   => '',
            'new_value'   => $new_value,
            'change_type' => 'update',
            'created_at'  => current_time('mysql'),
        ];
    }

    /**
     * @return array{0:int,1:int}
     */
    private function createActorAndSubject(): array
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        $subject = self::factory()->user->create(['role' => 'subscriber']);

        return [$administrator, $subject];
    }

    private function latestValue($user_id, $field_name): string
    {
        global $wpdb;

        return (string) $wpdb->get_var(
            $wpdb->prepare(
                'SELECT new_value FROM ' . $this->historyTable() . ' WHERE user_id = %d AND field_name = %s ORDER BY id DESC LIMIT 1',
                $user_id,
                $field_name
            )
        );
    }

    private function supportsGcm(): bool
    {
        $method = new ReflectionMethod(User_History::class, 'supports_aes_gcm');
        $method->setAccessible(true);

        return (bool) $method->invoke($this->plugin);
    }

    private function clearHistoryTable(): void
    {
        global $wpdb;

        $wpdb->query('DELETE FROM ' . $this->historyTable());
    }

    private function historyTable(): string
    {
        global $wpdb;

        return $wpdb->prefix . User_History::TABLE_NAME;
    }
}
