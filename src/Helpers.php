<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;

/**
 * Static helper methods for BOLT 11 amount conversions.
 */
final class Helpers
{
    /**
     * Convert satoshis to an HRP amount string.
     *
     * Example: 250000 → "2500u"
     */
    public static function satToHrp(int $sat): string
    {
        return self::msatToHrpString($sat * 1000);
    }

    /**
     * Convert millisatoshis to an HRP amount string.
     *
     * Example: 250000000 → "2500u"
     */
    public static function millisatToHrp(string|int $msat): string
    {
        $m = is_string($msat) ? (int) $msat : $msat;

        return self::msatToHrpString($m);
    }

    /**
     * Convert an HRP amount string to satoshis.
     *
     * Example: "2500u" → 250000
     *
     * @throws InvalidAmountException if not a whole number of satoshis
     */
    public static function hrpToSat(string $hrp): int
    {
        $sat = Amount::fromHrp($hrp)->satoshis();
        if ($sat === null) {
            throw new InvalidAmountException(
                sprintf('Amount %s is not a whole number of satoshis', $hrp),
            );
        }

        return $sat;
    }

    /**
     * Convert an HRP amount string to millisatoshis.
     *
     * Example: "2500u" → 250000000
     */
    public static function hrpToMillisat(string $hrp): int
    {
        return Amount::fromHrp($hrp)->millisatoshis;
    }

    /**
     * Encode an amount in millisatoshis as an HRP amount string.
     * Chooses the shortest representation per spec.
     */
    public static function msatToHrpString(int $msat): string
    {
        // Use integer divisors where possible to avoid float precision issues
        // milli-bitcoin: 1e8 msat per unit
        if ($msat % 100_000_000 === 0 && $msat >= 100_000_000) {
            return (string) intdiv($msat, 100_000_000) . 'm';
        }

        // micro-bitcoin: 1e5 msat per unit
        if ($msat % 100_000 === 0 && $msat >= 100_000) {
            return (string) intdiv($msat, 100_000) . 'u';
        }

        // nano-bitcoin: 100 msat per unit
        if ($msat % 100 === 0 && $msat >= 100) {
            return (string) intdiv($msat, 100) . 'n';
        }

        // pico-bitcoin: 0.1 msat per unit (multiply by 10). Use GMP so a large
        // msat value cannot overflow to a float and emit scientific notation.
        $picoVal = gmp_strval(gmp_mul(gmp_init($msat), 10));

        return $picoVal . 'p';
    }
}
