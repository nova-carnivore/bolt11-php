<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;

/**
 * Represents a BOLT 11 payment amount.
 *
 * The amount is stored as an integer number of millisatoshis. A BOLT 11 amount
 * is always a whole number of millisatoshis (the pico multiplier is required to
 * be a multiple of 10) and is capped at the 21M BTC supply, so it always fits
 * in a 64-bit int. Sub-satoshi amounts are represented exactly; satoshis()
 * returns null when the amount is not a whole number of satoshis.
 *
 * For contexts that represent msat as a string (e.g. JSON APIs avoiding the
 * 53-bit precision limit of JavaScript numbers), use millisatoshisString().
 */
final readonly class Amount
{
    /** Maximum representable amount: the 21M BTC supply, in millisatoshis. */
    public const int MAX_MSAT = 2_100_000_000_000_000_000; // 21e6 BTC * 1e11

    private const int MSAT_PER_BTC = 100_000_000_000; // 1e11

    /**
     * @param int $millisatoshis Amount in millisatoshis (0..MAX_MSAT)
     * @throws InvalidAmountException
     */
    public function __construct(
        public int $millisatoshis,
    ) {
        if ($millisatoshis < 0) {
            throw new InvalidAmountException('millisatoshis must not be negative');
        }
        if ($millisatoshis > self::MAX_MSAT) {
            throw new InvalidAmountException(
                sprintf('millisatoshis exceeds the maximum of %d', self::MAX_MSAT),
            );
        }
    }

    /**
     * Get the amount in satoshis, or null if not a whole number of satoshis.
     */
    public function satoshis(): ?int
    {
        if ($this->millisatoshis % 1000 === 0) {
            return intdiv($this->millisatoshis, 1000);
        }

        return null;
    }

    /**
     * The millisatoshi amount as a decimal string, for JSON / interop contexts
     * that represent msat as a string.
     */
    public function millisatoshisString(): string
    {
        return (string) $this->millisatoshis;
    }

    /**
     * Create an Amount from a parsed HRP amount string (e.g. "2500u", "20m", "10n").
     *
     * @throws InvalidAmountException
     */
    public static function fromHrp(string $amountStr): self
    {
        if ($amountStr === '') {
            throw new InvalidAmountException('Empty amount string');
        }

        return new self(self::hrpAmountToMsat($amountStr));
    }

    /**
     * Parse an HRP amount token (e.g. "2500u", "20m", "9678785340p") to an
     * integer msat value. All arithmetic runs through GMP so an oversized
     * amount is rejected rather than overflowing a native int, and the value is
     * capped at the 21M BTC supply. The result always fits in a PHP int.
     *
     * @throws InvalidAmountException
     */
    private static function hrpAmountToMsat(string $amountStr): int
    {
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

    /**
     * Create an Amount from satoshis.
     *
     * @throws InvalidAmountException
     */
    public static function fromSatoshis(int $satoshis): self
    {
        if ($satoshis < 0) {
            throw new InvalidAmountException('satoshis must not be negative');
        }
        if ($satoshis > intdiv(self::MAX_MSAT, 1000)) {
            throw new InvalidAmountException(
                sprintf('satoshis exceeds the maximum of %d', intdiv(self::MAX_MSAT, 1000)),
            );
        }

        return new self($satoshis * 1000);
    }

    /**
     * Create an Amount from millisatoshis.
     *
     * Accepts an int or a decimal string. The string form is validated and
     * range-checked with GMP so an oversized or malformed value fails with
     * InvalidAmountException instead of a lossy (int) cast.
     *
     * @throws InvalidAmountException
     */
    public static function fromMillisatoshis(string|int $millisatoshis): self
    {
        if (is_string($millisatoshis)) {
            if (!preg_match('/^\d+$/', $millisatoshis)) {
                throw new InvalidAmountException(
                    sprintf('millisatoshis must be a non-negative integer string, got "%s"', $millisatoshis),
                );
            }
            $value = gmp_init($millisatoshis, 10);
            if (gmp_cmp($value, gmp_init(self::MAX_MSAT)) > 0) {
                throw new InvalidAmountException(
                    sprintf('millisatoshis exceeds the maximum of %d', self::MAX_MSAT),
                );
            }
            $millisatoshis = gmp_intval($value);
        }

        return new self($millisatoshis);
    }
}
