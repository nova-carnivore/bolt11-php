<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

/**
 * Represents a fallback on-chain address in a BOLT 11 invoice.
 *
 * The version code maps to address types:
 * - 17: P2PKH
 * - 18: P2SH
 * - 0-16: Witness version (segwit)
 */
final readonly class FallbackAddress
{
    public function __construct(
        public int $code,
        public string $address,
        public string $addressHash,
    ) {
    }
}
