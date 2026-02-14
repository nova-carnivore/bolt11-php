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
     * Millisatoshis per unit for this multiplier.
     */
    public function msatPerUnit(): float
    {
        $msatPerBtc = 100_000_000_000; // 1e11

        return match ($this) {
            self::Milli => $msatPerBtc / 1_000,       // 1e8
            self::Micro => $msatPerBtc / 1_000_000,   // 1e5
            self::Nano => $msatPerBtc / 1_000_000_000, // 100
            self::Pico => $msatPerBtc / 1e12,          // 0.1
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
