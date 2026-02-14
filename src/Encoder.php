<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;

/**
 * BOLT 11 payment request encoder.
 *
 * Creates unsigned invoices that can then be signed with Signer::sign().
 */
final class Encoder
{
    /**
     * Encode an unsigned BOLT 11 payment request.
     *
     * @param list<Tag> $tags Required tags (must include payment_hash, payment_secret, and description or description_hash)
     * @param int|null $timestamp Unix timestamp (defaults to current time)
     */
    public static function encode(
        Network $network = Network::Bitcoin,
        ?int $satoshis = null,
        ?string $millisatoshis = null,
        array $tags = [],
        ?int $timestamp = null,
    ): Invoice {
        self::validateTags($tags);

        $timestamp ??= time();
        $hrp = self::buildHRP($network, $satoshis, $millisatoshis);
        $timestampWords = Bech32::intToWords($timestamp, 7);
        $tagWords = self::encodeAllTags($tags);
        $dataWords = [...$timestampWords, ...$tagWords];

        // Generate wordsTemp — the bech32-encoded string without signature
        $wordsTemp = Bech32::encode($hrp, $dataWords);

        $expiryTag = null;
        foreach ($tags as $tag) {
            if ($tag->tagName === 'expire_time' && is_int($tag->data)) {
                $expiryTag = $tag->data;
                break;
            }
        }
        $expireTime = $expiryTag ?? 3600;
        $timeExpireDate = $timestamp + $expireTime;

        $sat = $satoshis;
        $msat = $millisatoshis;
        if ($sat !== null && $msat === null) {
            $msat = (string) ($sat * 1000);
        }

        return new Invoice(
            complete: false,
            prefix: $hrp,
            wordsTemp: $wordsTemp,
            network: $network,
            satoshis: $sat,
            millisatoshis: $msat,
            timestamp: $timestamp,
            timestampString: gmdate('Y-m-d\TH:i:s\Z', $timestamp),
            timeExpireDate: $timeExpireDate,
            timeExpireDateString: gmdate('Y-m-d\TH:i:s\Z', $timeExpireDate),
            payeeNodeKey: null,
            signature: '',
            recoveryFlag: 0,
            tags: $tags,
        );
    }

    /**
     * Build the HRP string for a payment request.
     */
    public static function buildHRP(Network $network, ?int $satoshis = null, ?string $millisatoshis = null): string
    {
        $hrp = 'ln' . $network->value;

        if ($satoshis !== null) {
            $hrp .= Helpers::msatToHrpString($satoshis * 1000);
        } elseif ($millisatoshis !== null) {
            $msat = (int) $millisatoshis;
            $hrp .= Helpers::msatToHrpString($msat);
        }

        return $hrp;
    }

    /**
     * Encode all tags to 5-bit words.
     *
     * @param list<Tag> $tags
     * @return list<int>
     */
    public static function encodeAllTags(array $tags): array
    {
        $words = [];
        foreach ($tags as $tag) {
            foreach (self::encodeTag($tag) as $w) {
                $words[] = $w;
            }
        }

        return $words;
    }

    /**
     * Encode a single tag to 5-bit words.
     *
     * @return list<int>
     */
    private static function encodeTag(Tag $tag): array
    {
        $type = TagType::fromName($tag->tagName);
        if ($type === null) {
            throw new InvalidInvoiceException(sprintf('Unknown tag: %s', $tag->tagName));
        }

        $tagWords = self::encodeTagData($tag);
        $len = count($tagWords);

        // type (1 word) + length (2 words) + data
        return [$type->value, ($len >> 5) & 0x1f, $len & 0x1f, ...$tagWords];
    }

    /**
     * Encode tag data to 5-bit words.
     *
     * @return list<int>
     */
    private static function encodeTagData(Tag $tag): array
    {
        return match ($tag->tagName) {
            'payment_hash', 'payment_secret', 'purpose_commit_hash', 'payee', 'metadata' => self::encodeHexTag($tag),
            'description' => self::encodeDescriptionTag($tag),
            'expire_time', 'min_final_cltv_expiry' => self::encodeIntTag($tag),
            'fallback_address' => self::encodeFallbackTag($tag),
            'route_hint' => self::encodeRouteHintTag($tag),
            'feature_bits' => self::encodeFeatureBitsTag($tag),
            default => throw new InvalidInvoiceException(sprintf('Cannot encode tag: %s', $tag->tagName)),
        };
    }

    /**
     * @return list<int>
     */
    private static function encodeHexTag(Tag $tag): array
    {
        if (!is_string($tag->data)) {
            throw new InvalidInvoiceException(sprintf('Tag %s data must be a hex string', $tag->tagName));
        }

        return Bech32::eightToFive(Bech32::hexToBytes($tag->data));
    }

    /**
     * @return list<int>
     */
    private static function encodeDescriptionTag(Tag $tag): array
    {
        if (!is_string($tag->data)) {
            throw new InvalidInvoiceException('Description tag data must be a string');
        }

        return Bech32::eightToFive(Bech32::stringToBytes($tag->data));
    }

    /**
     * @return list<int>
     */
    private static function encodeIntTag(Tag $tag): array
    {
        if (!is_int($tag->data)) {
            throw new InvalidInvoiceException(sprintf('Tag %s data must be an integer', $tag->tagName));
        }

        return Bech32::intToMinWords($tag->data);
    }

    /**
     * @return list<int>
     */
    private static function encodeFallbackTag(Tag $tag): array
    {
        if (!$tag->data instanceof FallbackAddress) {
            throw new InvalidInvoiceException('Fallback address tag data must be a FallbackAddress');
        }

        return [$tag->data->code, ...Bech32::eightToFive(Bech32::hexToBytes($tag->data->addressHash))];
    }

    /**
     * @return list<int>
     */
    private static function encodeRouteHintTag(Tag $tag): array
    {
        if (!is_array($tag->data)) {
            throw new InvalidInvoiceException('Route hint tag data must be an array of RouteHint');
        }

        $hopBytes = [];
        /** @var RouteHint $hop */
        foreach ($tag->data as $hop) {
            foreach ($hop->toBytes() as $b) {
                $hopBytes[] = $b;
            }
        }

        return Bech32::eightToFive($hopBytes);
    }

    /**
     * @return list<int>
     */
    private static function encodeFeatureBitsTag(Tag $tag): array
    {
        if (!$tag->data instanceof FeatureBits) {
            throw new InvalidInvoiceException('Feature bits tag data must be a FeatureBits');
        }

        return $tag->data->toWords();
    }

    /**
     * Validate that required tags are present.
     *
     * @param list<Tag> $tags
     * @throws InvalidInvoiceException
     */
    private static function validateTags(array $tags): void
    {
        $hasPaymentHash = false;
        $hasPaymentSecret = false;
        $hasDescription = false;

        foreach ($tags as $tag) {
            match ($tag->tagName) {
                'payment_hash' => $hasPaymentHash = true,
                'payment_secret' => $hasPaymentSecret = true,
                'description', 'purpose_commit_hash' => $hasDescription = true,
                default => null,
            };
        }

        if (!$hasPaymentHash) {
            throw new InvalidInvoiceException('payment_hash tag is required');
        }
        if (!$hasPaymentSecret) {
            throw new InvalidInvoiceException('payment_secret tag is required');
        }
        if (!$hasDescription) {
            throw new InvalidInvoiceException('description or purpose_commit_hash tag is required');
        }
    }
}
