<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

/**
 * Represents a decoded (or encoded) BOLT 11 payment request.
 */
final readonly class Invoice
{
    /**
     * @param bool $complete Whether the invoice is fully signed
     * @param string $prefix The full HRP prefix (e.g. 'lnbc2500u')
     * @param string $wordsTemp Temporary bech32 string (unsigned)
     * @param Network|null $network The Bitcoin network
     * @param int|null $satoshis Amount in satoshis (null if sub-sat or no amount)
     * @param string|null $millisatoshis Amount in millisatoshis as string
     * @param int $timestamp Unix timestamp
     * @param string $timestampString ISO 8601 timestamp string
     * @param int|null $timeExpireDate Unix timestamp of expiry
     * @param string|null $timeExpireDateString ISO 8601 expiry string
     * @param string|null $payeeNodeKey Compressed public key (hex)
     * @param string $signature 64-byte compact signature (hex)
     * @param int $recoveryFlag Signature recovery flag (0-3)
     * @param list<Tag> $tags All tagged fields
     * @param string|null $paymentRequest The full bech32-encoded payment request string
     */
    public function __construct(
        public bool $complete,
        public string $prefix,
        public string $wordsTemp,
        public ?Network $network,
        public ?int $satoshis,
        public ?string $millisatoshis,
        public int $timestamp,
        public string $timestampString,
        public ?int $timeExpireDate,
        public ?string $timeExpireDateString,
        public ?string $payeeNodeKey,
        public string $signature,
        public int $recoveryFlag,
        public array $tags,
        public ?string $paymentRequest = null,
    ) {
    }

    /**
     * Get the payment hash (hex).
     */
    public function getPaymentHash(): ?string
    {
        $data = $this->getTagData('payment_hash');

        return is_string($data) ? $data : null;
    }

    /**
     * Get the payment secret (hex).
     */
    public function getPaymentSecret(): ?string
    {
        $data = $this->getTagData('payment_secret');

        return is_string($data) ? $data : null;
    }

    /**
     * Get the description string.
     */
    public function getDescription(): ?string
    {
        $data = $this->getTagData('description');

        return is_string($data) ? $data : null;
    }

    /**
     * Get the description hash (hex).
     */
    public function getDescriptionHash(): ?string
    {
        $data = $this->getTagData('purpose_commit_hash');

        return is_string($data) ? $data : null;
    }

    /**
     * Get the metadata (hex).
     */
    public function getMetadata(): ?string
    {
        $data = $this->getTagData('metadata');

        return is_string($data) ? $data : null;
    }

    /**
     * Get the payee node key from the `n` tag.
     */
    public function getPayeeFromTag(): ?string
    {
        $data = $this->getTagData('payee');

        return is_string($data) ? $data : null;
    }

    /**
     * Get the expiry time in seconds (default 3600).
     */
    public function getExpiry(): int
    {
        $data = $this->getTagData('expire_time');

        return is_int($data) ? $data : 3600;
    }

    /**
     * Get the min_final_cltv_expiry (default 18).
     */
    public function getMinFinalCltvExpiry(): int
    {
        $data = $this->getTagData('min_final_cltv_expiry');

        return is_int($data) ? $data : 18;
    }

    /**
     * Get the fallback address.
     */
    public function getFallbackAddress(): ?FallbackAddress
    {
        $data = $this->getTagData('fallback_address');

        return $data instanceof FallbackAddress ? $data : null;
    }

    /**
     * Get route hints.
     *
     * @return list<RouteHint>|null
     */
    public function getRouteHints(): ?array
    {
        $data = $this->getTagData('route_hint');

        return is_array($data) ? $data : null;
    }

    /**
     * Get feature bits.
     */
    public function getFeatureBits(): ?FeatureBits
    {
        $data = $this->getTagData('feature_bits');

        return $data instanceof FeatureBits ? $data : null;
    }

    /**
     * Check if this invoice has expired.
     */
    public function isExpired(): bool
    {
        if ($this->timeExpireDate === null) {
            return false;
        }

        return time() > $this->timeExpireDate;
    }

    /**
     * Get a tag by name. Returns the first matching tag.
     */
    public function getTag(string $tagName): ?Tag
    {
        foreach ($this->tags as $tag) {
            if ($tag->tagName === $tagName) {
                return $tag;
            }
        }

        return null;
    }

    /**
     * Get tag data by name.
     *
     * @return string|int|FallbackAddress|list<RouteHint>|FeatureBits|null
     */
    private function getTagData(string $tagName): string|int|FallbackAddress|array|FeatureBits|null
    {
        $tag = $this->getTag($tagName);

        return $tag?->data;
    }

    /**
     * Create a new Invoice with updated fields (immutable clone).
     *
     * @param list<Tag>|null $tags
     */
    public function with(
        ?bool $complete = null,
        ?string $prefix = null,
        ?string $payeeNodeKey = null,
        ?string $signature = null,
        ?int $recoveryFlag = null,
        ?array $tags = null,
        ?string $paymentRequest = null,
    ): self {
        return new self(
            complete: $complete ?? $this->complete,
            prefix: $prefix ?? $this->prefix,
            wordsTemp: $this->wordsTemp,
            network: $this->network,
            satoshis: $this->satoshis,
            millisatoshis: $this->millisatoshis,
            timestamp: $this->timestamp,
            timestampString: $this->timestampString,
            timeExpireDate: $this->timeExpireDate,
            timeExpireDateString: $this->timeExpireDateString,
            payeeNodeKey: $payeeNodeKey ?? $this->payeeNodeKey,
            signature: $signature ?? $this->signature,
            recoveryFlag: $recoveryFlag ?? $this->recoveryFlag,
            tags: $tags ?? $this->tags,
            paymentRequest: $paymentRequest ?? $this->paymentRequest,
        );
    }
}
