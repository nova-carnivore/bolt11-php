<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

use Nova\Bitcoin\Exception\InvalidAmountException;

/**
 * Represents a BOLT 11 payment amount.
 *
 * Internally stores millisatoshis as a string to handle sub-satoshi precision.
 */
final readonly class Amount
{
    /**
     * @param string $millisatoshis Amount in millisatoshis as string
     */
    public function __construct(
        public string $millisatoshis,
    ) {
    }

    /**
     * Get the amount in satoshis, or null if not a whole number of satoshis.
     */
    public function satoshis(): ?int
    {
        $msat = (int) $this->millisatoshis;
        if ($msat % 1000 === 0) {
            return intdiv($msat, 1000);
        }

        return null;
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

        $msatPerBtc = 100_000_000_000; // 1e11

        $lastChar = $amountStr[strlen($amountStr) - 1];
        $multiplier = Multiplier::fromSuffix($lastChar);

        if ($multiplier !== null) {
            $numStr = substr($amountStr, 0, -1);
            $msatPerUnit = $multiplier->msatPerUnit();
        } else {
            $numStr = $amountStr;
            $msatPerUnit = (float) $msatPerBtc;
        }

        if ($numStr === '' || !preg_match('/^\d+$/', $numStr) || (strlen($numStr) > 1 && $numStr[0] === '0')) {
            throw new InvalidAmountException(sprintf('Invalid amount: "%s"', $amountStr));
        }

        // Pico amounts must be multiples of 10
        if ($multiplier === Multiplier::Pico && ((int) $numStr) % 10 !== 0) {
            throw new InvalidAmountException('pico-bitcoin amount must be a multiple of 10');
        }

        $num = (int) $numStr;
        $msat = (int) round($num * $msatPerUnit);

        return new self((string) $msat);
    }

    /**
     * Create an Amount from satoshis.
     */
    public static function fromSatoshis(int $satoshis): self
    {
        return new self((string) ($satoshis * 1000));
    }

    /**
     * Create an Amount from millisatoshis.
     */
    public static function fromMillisatoshis(string|int $millisatoshis): self
    {
        return new self((string) $millisatoshis);
    }
}
