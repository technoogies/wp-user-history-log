<?php

final class MultisiteAuditGovernanceTest extends WP_Ajax_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (!is_multisite()) {
            $this->markTestSkipped('Requires the WordPress multisite test bootstrap.');
        }

        User_History::get_instance()->activate();
    }

    protected function tearDown(): void
    {
        while (ms_is_switched()) {
            restore_current_blog();
        }

        $_POST = [];
        $_GET = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_subsite_account_editor_without_manage_user_history_cannot_clear_history(): void
    {
        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $editor = self::factory()->user->create(['role' => 'editor']);
        $editor_user = get_userdata($editor);
        $editor_user->add_cap('edit_users');
        $editor_user->add_cap('list_users');
        $subject = self::factory()->user->create(['role' => 'subscriber']);
        add_user_to_blog($site_id, $editor, 'editor');
        add_user_to_blog($site_id, $subject, 'subscriber');

        wp_set_current_user($editor);
        $this->seedHistory($subject, 'ms-keep');
        $original = $this->historySnapshot($subject);

        $this->assertFalse(current_user_can(User_History::CLEAR_HISTORY_CAPABILITY));

        $response = $this->clearHistory($subject);

        $this->assertFalse($response['success']);
        $this->assertSame($original, $this->historySnapshot($subject));
    }

    public function test_subsite_administrator_receives_manage_user_history(): void
    {
        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $role = get_role('administrator');
        $this->assertNotNull($role);
        $this->assertTrue($role->has_cap(User_History::CLEAR_HISTORY_CAPABILITY));
    }

    private function seedHistory($user_id, $marker): void
    {
        global $wpdb;

        $wpdb->insert(
            $wpdb->prefix . User_History::TABLE_NAME,
            [
                'user_id'            => (int) $user_id,
                'changed_by'         => (int) $user_id,
                'field_name'         => 'first_name',
                'field_label'        => 'First Name',
                'old_value'          => $marker . '-old',
                'new_value'          => $marker . '-new',
                'search_tokens'      => '',
                'changed_by_details' => '',
                'change_type'        => 'update',
                'created_at'         => current_time('mysql'),
            ]
        );
    }

    private function clearHistory($user_id): array
    {
        $_POST = [
            'action'  => 'clear_user_history',
            'nonce'   => wp_create_nonce('user_history_clear'),
            'user_id' => (int) $user_id,
        ];

        try {
            $this->_handleAjax('clear_user_history');
        } catch (WPAjaxDieContinueException $exception) {
            // Expected: wp_send_json_* ends the AJAX request.
        }

        $response = json_decode($this->_last_response, true);
        $this->assertIsArray($response);

        return $response;
    }

    private function historySnapshot($user_id): array
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT id, field_name, old_value, new_value, change_type FROM ' . $wpdb->prefix . User_History::TABLE_NAME . ' WHERE user_id = %d ORDER BY id ASC',
                $user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }
}
