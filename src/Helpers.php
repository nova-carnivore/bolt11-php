<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

use Nova\Bitcoin\Exception\InvalidAmountException;

/**
 * Static helper methods for BOLT 11 amount conversions.
 */
final class Helpers
{
    private const int MSAT_PER_BTC = 100_000_000_000; // 1e11

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
     * Example: "2500u" → "250000"
     *
     * @throws InvalidAmountException if not a whole number of satoshis
     */
    public static function hrpToSat(string $hrp): string
    {
        $msat = self::hrpToMillisatNum($hrp);
        if ($msat % 1000 !== 0) {
            throw new InvalidAmountException(
                sprintf('Amount %s is not a whole number of satoshis', $hrp),
            );
        }

        return (string) intdiv($msat, 1000);
    }

    /**
     * Convert an HRP amount string to millisatoshis.
     *
     * Example: "2500u" → "250000000"
     */
    public static function hrpToMillisat(string $hrp): string
    {
        return (string) self::hrpToMillisatNum($hrp);
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

        // pico-bitcoin: 0.1 msat per unit (multiply by 10 to stay in int)
        $picoVal = $msat * 10;

        return $picoVal . 'p';
    }

    /**
     * @throws InvalidAmountException
     */
    private static function hrpToMillisatNum(string $amountStr): int
    {
        if ($amountStr === '') {
            throw new InvalidAmountException('Invalid amount: ""');
        }

        $lastChar = $amountStr[strlen($amountStr) - 1];
        $multiplier = Multiplier::fromSuffix($lastChar);

        if ($multiplier !== null) {
            $numStr = substr($amountStr, 0, -1);
            $msatPerUnit = $multiplier->msatPerUnit();
        } else {
            $numStr = $amountStr;
            $msatPerUnit = (float) self::MSAT_PER_BTC;
        }

        if ($numStr === '' || !preg_match('/^\d+$/', $numStr) || (strlen($numStr) > 1 && $numStr[0] === '0')) {
            throw new InvalidAmountException(sprintf('Invalid amount: "%s"', $amountStr));
        }

        if ($multiplier === Multiplier::Pico && ((int) $numStr) % 10 !== 0) {
            throw new InvalidAmountException('pico-bitcoin amount must be a multiple of 10');
        }

        return (int) round((int) $numStr * $msatPerUnit);
    }
}
