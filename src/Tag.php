<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

/**
 * Represents a single tagged field in a BOLT 11 invoice.
 */
final readonly class Tag
{
    /**
     * @param string $tagName Human-readable tag name
     * @param string|int|FallbackAddress|list<RouteHint>|FeatureBits $data Tag data
     */
    public function __construct(
        public string $tagName,
        public string|int|FallbackAddress|array|FeatureBits $data,
    ) {
    }

    /**
     * Create a payment_hash tag (256-bit hex).
     */
    public static function paymentHash(string $hex): self
    {
        return new self('payment_hash', $hex);
    }

    /**
     * Create a payment_secret tag (256-bit hex).
     */
    public static function paymentSecret(string $hex): self
    {
        return new self('payment_secret', $hex);
    }

    /**
     * Create a description tag (UTF-8 string).
     */
    public static function description(string $text): self
    {
        return new self('description', $text);
    }

    /**
     * Create a description_hash tag (SHA-256 hex).
     */
    public static function descriptionHash(string $hex): self
    {
        return new self('purpose_commit_hash', $hex);
    }

    /**
     * Create a payee node key tag (33-byte compressed pubkey hex).
     */
    public static function payeeNodeKey(string $hex): self
    {
        return new self('payee', $hex);
    }

    /**
     * Create an expiry tag (seconds).
     */
    public static function expiry(int $seconds): self
    {
        return new self('expire_time', $seconds);
    }

    /**
     * Create a min_final_cltv_expiry tag.
     */
    public static function minFinalCltvExpiry(int $blocks): self
    {
        return new self('min_final_cltv_expiry', $blocks);
    }

    /**
     * Create a fallback address tag.
     */
    public static function fallbackAddress(int $code, string $addressHash): self
    {
        return new self('fallback_address', new FallbackAddress(
            code: $code,
            address: '',
            addressHash: $addressHash,
        ));
    }

    /**
     * Create a route hint tag.
     *
     * @param list<RouteHint> $hops
     */
    public static function routeHint(array $hops): self
    {
        return new self('route_hint', $hops);
    }

    /**
     * Create a feature bits tag.
     */
    public static function featureBits(FeatureBits $bits): self
    {
        return new self('feature_bits', $bits);
    }

    /**
     * Create a metadata tag (hex string).
     */
    public static function metadata(string $hex): self
    {
        return new self('metadata', $hex);
    }
}
