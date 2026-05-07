<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

/**
 * BOLT 11 amount multiplier suffixes.
 *
 * Each multiplier represents a fraction of 1 BTC.
 * 1 BTC = 100_000_000_000 millisatoshis.
 */
enum Multiplier: string
{
    case Milli = 'm'; // 0.001 BTC
    case Micro = 'u'; // 0.000001 BTC
    case Nano = 'n';  // 0.000000001 BTC
    case Pico = 'p';  // 0.000000000001 BTC

    /**
     * Convert an integer count of this multiplier's units to millisatoshis,
     * using integer arithmetic only (no float precision loss).
     *
     * Pico amounts must be multiples of 10 — the caller is responsible for
     * validating that before calling.
     */
    public function toMsat(int $units): int
    {
        return match ($this) {
            self::Milli => $units * 100_000_000,
            self::Micro => $units * 100_000,
            self::Nano => $units * 100,
            self::Pico => intdiv($units, 10),
        };
    }

    /**
     * Try to resolve a multiplier from its suffix character.
     */
    public static function fromSuffix(string $char): ?self
    {
        return self::tryFrom($char);
    }
}
