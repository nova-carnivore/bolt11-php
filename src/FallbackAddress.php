<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

/**
 * Represents a fallback on-chain address in a BOLT 11 invoice.
 *
 * The version code maps to address types:
 * - 0-16: witness version (segwit, BIP-141)
 * - 17:   P2PKH
 * - 18:   P2SH
 *
 * Per BOLT 11, readers MUST skip `f` fields with any other version code.
 */
final readonly class FallbackAddress
{
    public function __construct(
        public int $code,
        public string $addressHash,
    ) {
    }
}
