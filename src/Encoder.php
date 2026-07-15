<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;

/**
 * BOLT 11 payment request encoder.
 *
 * Creates unsigned invoices that can then be signed with Signer::sign().
 */
final class Encoder
{
    /** Maximum value of the 35-bit big-endian timestamp field (2^35 - 1). */
    private const int MAX_TIMESTAMP = 34359738367;

    /**
     * Encode an unsigned BOLT 11 payment request.
     *
     * @param list<Tag> $tags Required tags (must include payment_hash, payment_secret, and description or description_hash)
     * @param int|null $timestamp Unix timestamp (defaults to current time)
     */
    public static function encode(
        Network $network = Network::Bitcoin,
        ?int $satoshis = null,
        int|string|null $millisatoshis = null,
        array $tags = [],
        ?int $timestamp = null,
    ): Invoice {
        self::validateAmounts($satoshis, $millisatoshis);
        self::validateTags($tags);

        $timestamp ??= time();
        // Timestamp is a 35-bit big-endian field; a value outside that range
        // would be silently truncated/wrapped by Signer, producing a valid-
        // looking invoice with a wrong timestamp. Reject it instead.
        if ($timestamp < 0 || $timestamp > self::MAX_TIMESTAMP) {
            throw new InvalidInvoiceException(
                sprintf('timestamp must be within 0..%d (35-bit), got %d', self::MAX_TIMESTAMP, $timestamp),
            );
        }
        $hrp = self::buildHRP($network, $satoshis, $millisatoshis);

        $expiryTag = null;
        foreach ($tags as $tag) {
            if ($tag->tagName === 'expire_time' && is_int($tag->data)) {
                $expiryTag = $tag->data;
                break;
            }
        }
        $expireTime = $expiryTag ?? 3600;
        $timeExpireDate = $timestamp + $expireTime;

        $msat = match (true) {
            $millisatoshis !== null => Amount::fromMillisatoshis($millisatoshis)->millisatoshis,
            $satoshis !== null => Amount::fromSatoshis($satoshis)->millisatoshis,
            default => null,
        };

        return new Invoice(
            complete: false,
            prefix: $hrp,
            network: $network,
            satoshis: $satoshis,
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
    public static function buildHRP(Network $network, ?int $satoshis = null, int|string|null $millisatoshis = null): string
    {
        $hrp = 'ln' . $network->value;

        if ($satoshis !== null) {
            if ($satoshis === 0) {
                throw new InvalidAmountException('Amount must not be zero (use null for an any-amount invoice)');
            }

            $hrp .= Helpers::msatToHrpString(Amount::fromSatoshis($satoshis)->millisatoshis);
        } elseif ($millisatoshis !== null) {
            $msat = Amount::fromMillisatoshis($millisatoshis)->millisatoshis;
            if ($msat === 0) {
                throw new InvalidAmountException('Amount must not be zero (use null for an any-amount invoice)');
            }

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
            // Spec: when the feature vector has no non-zero bits the `9` field
            // MUST be omitted altogether.
            if (
                $tag->tagName === 'feature_bits'
                && $tag->data instanceof FeatureBits
                && self::minimalFeatureWords($tag->data) === []
            ) {
                continue;
            }
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

        $bytes = Bech32::hexToBytes($tag->data);

        // Fixed-length fields (spec: p/s/h = 32 bytes, n = 33 bytes) MUST have
        // the correct length, or every conformant reader rejects the invoice.
        // Fail at the writer boundary instead of emitting a wrong data_length.
        $expected = match ($tag->tagName) {
            'payment_hash', 'payment_secret', 'purpose_commit_hash' => 32,
            'payee' => 33,
            default => null,
        };
        if ($expected !== null && count($bytes) !== $expected) {
            throw new InvalidInvoiceException(sprintf(
                '%s must be %d bytes, got %d',
                $tag->tagName,
                $expected,
                count($bytes),
            ));
        }

        return Bech32::eightToFive($bytes);
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

        return self::minimalFeatureWords($tag->data);
    }

    /**
     * Feature-bits words with leading zero field-elements stripped. Spec: a
     * non-empty `9` field MUST use the minimum data_length possible (no leading
     * 0 field-elements). An all-zero vector yields an empty list, signalling to
     * encodeAllTags that the field must be omitted.
     *
     * @return list<int>
     */
    private static function minimalFeatureWords(FeatureBits $fb): array
    {
        $words = $fb->toWords();
        while ($words !== [] && $words[0] === 0) {
            array_shift($words);
        }

        return $words;
    }

    /**
     * Reject negative satoshis and non-numeric / negative millisatoshis at the
     * writer boundary. A string millisatoshis (accepted for interop) is
     * validated to be a plain non-negative decimal integer; `(int) "abc"`
     * would otherwise quietly become 0 and look like a valid amount.
     */
    private static function validateAmounts(?int $satoshis, int|string|null $millisatoshis): void
    {
        if ($satoshis !== null && $satoshis < 0) {
            throw new InvalidAmountException('satoshis must not be negative');
        }
        if (is_int($millisatoshis) && $millisatoshis < 0) {
            throw new InvalidAmountException('millisatoshis must not be negative');
        }
        if (is_string($millisatoshis) && !preg_match('/^\d+$/', $millisatoshis)) {
            throw new InvalidAmountException(
                sprintf('millisatoshis must be a non-negative integer string, got "%s"', $millisatoshis),
            );
        }
    }

    /**
     * Validate that required tags are present, no singleton tag is duplicated,
     * and description/description_hash are not both set.
     *
     * Per BOLT 11 spec, these tags MUST appear at most once. Tags allowing
     * multiple instances (route_hint, fallback_address) are excluded.
     *
     * @param list<Tag> $tags
     * @throws InvalidInvoiceException
     */
    private static function validateTags(array $tags): void
    {
        $singletons = [
            'payment_hash' => 0,
            'payment_secret' => 0,
            'description' => 0,
            'purpose_commit_hash' => 0,
            'payee' => 0,
            'expire_time' => 0,
            'min_final_cltv_expiry' => 0,
            'feature_bits' => 0,
            'metadata' => 0,
        ];

        foreach ($tags as $tag) {
            if (isset($singletons[$tag->tagName])) {
                $singletons[$tag->tagName]++;
            }
        }

        foreach ($singletons as $name => $count) {
            if ($count > 1) {
                throw new InvalidInvoiceException(
                    sprintf('Tag "%s" must appear at most once (got %d)', $name, $count),
                );
            }
        }

        if ($singletons['payment_hash'] === 0) {
            throw new InvalidInvoiceException('payment_hash tag is required');
        }
        if ($singletons['payment_secret'] === 0) {
            throw new InvalidInvoiceException('payment_secret tag is required');
        }
        if ($singletons['description'] === 0 && $singletons['purpose_commit_hash'] === 0) {
            throw new InvalidInvoiceException('description or purpose_commit_hash tag is required');
        }
        if ($singletons['description'] > 0 && $singletons['purpose_commit_hash'] > 0) {
            throw new InvalidInvoiceException('description and purpose_commit_hash are mutually exclusive');
        }
    }
}
