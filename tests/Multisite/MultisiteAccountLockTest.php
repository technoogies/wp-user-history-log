<?php

final class MultisiteAccountLockTest extends WP_Ajax_UnitTestCase
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

    public function test_super_admin_cannot_be_locked(): void
    {
        $site_id = self::factory()->blog->create();
        switch_to_blog($site_id);
        User_History::get_instance()->activate();

        $operator = self::factory()->user->create(['role' => 'administrator']);
        grant_super_admin($operator);
        $super = self::factory()->user->create(['role' => 'administrator']);
        grant_super_admin($super);
        add_user_to_blog($site_id, $operator, 'administrator');
        add_user_to_blog($site_id, $super, 'administrator');

        wp_set_current_user($operator);
        $lock = User_History_Lock::get_instance();

        $this->assertTrue(is_super_admin($super));
        $this->assertFalse($lock->current_operator_can_lock_user($super));

        $result = $lock->lock_user($super);
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('super_admin_lock', $result->get_error_code());
        $this->assertFalse($lock->is_user_locked($super));
    }
}
