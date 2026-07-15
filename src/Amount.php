<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;

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
     * Delegates to the overflow-safe Helpers parser: the returned
     * millisatoshis is always a plain decimal-integer string (never a
     * float-formatted value), and an oversized or malformed amount fails with
     * InvalidAmountException rather than a TypeError.
     *
     * @throws InvalidAmountException
     */
    public static function fromHrp(string $amountStr): self
    {
        if ($amountStr === '') {
            throw new InvalidAmountException('Empty amount string');
        }

        return new self(Helpers::hrpToMillisat($amountStr));
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
