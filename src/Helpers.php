<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;

/**
 * Static helper methods for BOLT 11 amount conversions.
 */
final class Helpers
{
    private const int MSAT_PER_BTC = 100_000_000_000; // 1e11

    /**
     * Upper bound on a representable amount: the 21M BTC supply cap, in msat.
     * No valid invoice can exceed this, and it keeps every parsed amount well
     * within PHP's signed-int range so downstream int arithmetic is safe.
     */
    private const int MAX_MSAT = 2_100_000_000_000_000_000; // 21e6 BTC * 1e11

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

        // pico-bitcoin: 0.1 msat per unit (multiply by 10). Use GMP so a large
        // msat value cannot overflow to a float and emit scientific notation.
        $picoVal = gmp_strval(gmp_mul(gmp_init($msat), 10));

        return $picoVal . 'p';
    }

    /**
     * Parse an HRP amount string to millisatoshis.
     *
     * All arithmetic runs through GMP so an oversized amount cannot overflow a
     * native int (which would raise a TypeError or store scientific notation).
     * The magnitude is capped at the 21M BTC supply; anything larger, or any
     * malformed amount, fails with InvalidAmountException. The result always
     * fits in a PHP int.
     *
     * @throws InvalidAmountException
     */
    private static function hrpToMillisatNum(string $amountStr): int
    {
        if ($amountStr === '') {
            throw new InvalidAmountException('Invalid amount: ""');
        }

        $lastChar = $amountStr[strlen($amountStr) - 1];
        $multiplier = Multiplier::fromSuffix($lastChar);
        $numStr = $multiplier !== null ? substr($amountStr, 0, -1) : $amountStr;

        if ($numStr === '' || !preg_match('/^\d+$/', $numStr) || (strlen($numStr) > 1 && $numStr[0] === '0')) {
            throw new InvalidAmountException(sprintf('Invalid amount: "%s"', $amountStr));
        }

        // Check the pico trailing-zero rule on the decimal string itself, not
        // on a lossy (int) cast; a saturated int would give the wrong digit.
        if ($multiplier === Multiplier::Pico && substr($numStr, -1) !== '0') {
            throw new InvalidAmountException('pico-bitcoin amount must be a multiple of 10');
        }

        $units = gmp_init($numStr, 10);
        $msat = $multiplier !== null
            ? $multiplier->toMsatGmp($units)
            : gmp_mul($units, self::MSAT_PER_BTC);

        if (gmp_cmp($msat, gmp_init(self::MAX_MSAT)) > 0) {
            throw new InvalidAmountException(
                sprintf('Amount exceeds the maximum of %d msat: "%s"', self::MAX_MSAT, $amountStr),
            );
        }

        return gmp_intval($msat);
    }
}
