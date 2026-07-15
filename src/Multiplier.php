<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use GMP;
use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;

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
     * Convert an integer count of this multiplier's units to millisatoshis.
     *
     * The multiplication is performed with GMP so it cannot overflow a native
     * int (which would silently promote to float and, under strict_types,
     * raise a TypeError from this `: int` return). If the result does not fit
     * in a PHP int an InvalidAmountException is thrown instead.
     *
     * Pico amounts must be multiples of 10; the caller is responsible for
     * validating that before calling.
     *
     * @throws InvalidAmountException
     */
    public function toMsat(int $units): int
    {
        $msat = $this->toMsatGmp(gmp_init($units));

        if (gmp_cmp($msat, gmp_init(PHP_INT_MAX)) > 0) {
            throw new InvalidAmountException('amount overflows integer range');
        }

        return gmp_intval($msat);
    }

    /**
     * Convert a GMP unit count to millisatoshis as a GMP value (no overflow).
     */
    public function toMsatGmp(GMP $units): GMP
    {
        return match ($this) {
            self::Milli => gmp_mul($units, 100_000_000),
            self::Micro => gmp_mul($units, 100_000),
            self::Nano => gmp_mul($units, 100),
            self::Pico => gmp_div_q($units, 10),
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
