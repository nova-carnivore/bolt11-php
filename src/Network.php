<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

/**
 * Bitcoin network types supported by BOLT 11.
 */
enum Network: string
{
    case Bitcoin = 'bc';
    case Testnet = 'tb';
    case Signet = 'tbs';
    case Regtest = 'bcrt';

    /**
     * Get the network's P2PKH address version byte.
     */
    public function pubKeyHash(): int
    {
        return match ($this) {
            self::Bitcoin => 0x00,
            self::Testnet, self::Signet, self::Regtest => 0x6f,
        };
    }

    /**
     * Get the network's P2SH address version byte.
     */
    public function scriptHash(): int
    {
        return match ($this) {
            self::Bitcoin => 0x05,
            self::Testnet, self::Signet, self::Regtest => 0xc4,
        };
    }

    /**
     * Get supported witness versions for this network.
     *
     * @return list<int>
     */
    public function validWitnessVersions(): array
    {
        return [0, 1];
    }

    /**
     * Resolve a network from a bech32 prefix string.
     *
     * @throws Exception\UnsupportedNetworkException
     */
    public static function fromBech32(string $prefix): self
    {
        return self::tryFrom($prefix)
            ?? throw new Exception\UnsupportedNetworkException(
                sprintf('Unknown network prefix: "%s"', $prefix),
            );
    }

    /**
     * Resolve a network from an HRP prefix (e.g. 'lnbc', 'lntb', 'lntbs', 'lnbcrt').
     * Returns the network and remaining amount string.
     *
     * @return array{network: self, amount: string}
     * @throws Exception\UnsupportedNetworkException
     */
    public static function fromHrp(string $hrp): array
    {
        if (!str_starts_with($hrp, 'ln')) {
            throw new Exception\UnsupportedNetworkException(
                sprintf('Invalid prefix: must start with "ln", got "%s"', $hrp),
            );
        }

        // Try longest prefixes first (bcrt before bc)
        $cases = self::cases();
        usort($cases, static fn (self $a, self $b): int => strlen($b->value) <=> strlen($a->value));

        foreach ($cases as $network) {
            $prefix = 'ln' . $network->value;
            if (str_starts_with($hrp, $prefix)) {
                return [
                    'network' => $network,
                    'amount' => substr($hrp, strlen($prefix)),
                ];
            }
        }

        throw new Exception\UnsupportedNetworkException(
            sprintf('Unknown network in prefix "%s"', $hrp),
        );
    }
}
