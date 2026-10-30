<?php

use PHPUnit\Framework\TestCase;

final class SearchTokenBudgetTest extends TestCase
{
    private User_History $plugin;

    protected function setUp(): void
    {
        $this->plugin = User_History::get_instance();
    }

    public function test_documented_resource_limits_are_conservative_and_fixed(): void
    {
        $reflection = new ReflectionClass(User_History::class);

        $this->assertSame(1024, $reflection->getConstant('MAX_SEARCHABLE_VALUE_BYTES'));
        $this->assertSame(128, $reflection->getConstant('MAX_SEARCH_TOKEN_COUNT'));
        $this->assertSame(8192, $reflection->getConstant('MAX_SEARCH_TOKEN_BYTES'));
        $this->assertSame(5, $reflection->getConstant('MAX_SEARCH_QUERY_TOKENS'));
    }

    public function test_normal_searchable_value_produces_unique_bounded_hashes(): void
    {
        $serialized = $this->buildSearchTokens(
            'display_name',
            '',
            'Alexandra Security Example'
        );
        $hashes = explode('|', $serialized);

        $this->assertNotSame('', $serialized);
        $this->assertSame($hashes, array_values(array_unique($hashes)));
        $this->assertLessThanOrEqual(128, count($hashes));
        $this->assertLessThanOrEqual(8192, strlen($serialized));
    }

    public function test_high_diversity_value_stops_at_token_and_byte_budgets(): void
    {
        $value = $this->makeHighDiversityValue('v');

        $this->assertLessThanOrEqual(1024, strlen($value));

        $serialized = $this->buildSearchTokens('first_name', '', $value);
        $hashes = explode('|', $serialized);

        $this->assertGreaterThan(100, count($hashes));
        $this->assertLessThanOrEqual(128, count($hashes));
        $this->assertLessThanOrEqual(8192, strlen($serialized));
    }

    public function test_old_and_new_values_share_the_entry_budget(): void
    {
        $old_value = $this->makeHighDiversityValue('o');
        $new_value = $this->makeHighDiversityValue('n');

        $old_hashes = explode('|', $this->buildSearchTokens('first_name', '', $old_value));
        $new_hashes = explode('|', $this->buildSearchTokens('first_name', '', $new_value));
        $combined_hashes = explode('|', $this->buildSearchTokens('first_name', $old_value, $new_value));

        $this->assertContains($old_hashes[0], $combined_hashes);
        $this->assertContains($new_hashes[0], $combined_hashes);
        $this->assertLessThanOrEqual(128, count($combined_hashes));
        $this->assertLessThanOrEqual(8192, strlen(implode('|', $combined_hashes)));
    }

    public function test_oversized_value_is_not_tokenized_for_storage_or_search(): void
    {
        $oversized = str_repeat('sensitive-profile-value-', 100000);

        $this->assertGreaterThan(1024, strlen($oversized));
        $this->assertSame('', $this->buildSearchTokens('first_name', '', $oversized));
        $this->assertSame([], $this->hashSearchTerm($oversized));
    }

    public function test_search_query_hashing_stops_at_five_unique_tokens(): void
    {
        $hashes = $this->hashSearchTerm('alexandra security example');

        $this->assertNotEmpty($hashes);
        $this->assertLessThanOrEqual(5, count($hashes));
        $this->assertSame($hashes, array_values(array_unique($hashes)));
    }

    private function buildSearchTokens($field_name, $old_value, $new_value): string
    {
        $method = new ReflectionMethod(User_History::class, 'build_search_tokens');
        $method->setAccessible(true);

        return $method->invoke($this->plugin, $field_name, $old_value, $new_value);
    }

    private function hashSearchTerm($term): array
    {
        $method = new ReflectionMethod(User_History::class, 'hash_tokens_from_term');
        $method->setAccessible(true);

        return $method->invoke($this->plugin, $term);
    }

    private function makeHighDiversityValue($prefix): string
    {
        $words = [];
        for ($index = 0; $index < 100; $index++) {
            $words[] = sprintf('%s%03x%03x', $prefix, $index, $index * 17);
        }

        return implode(' ', $words);
    }
}
