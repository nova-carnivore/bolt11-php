<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

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
