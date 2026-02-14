<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

/**
 * BOLT 11 tag type codes.
 *
 * Maps the 5-bit tag type value to its semantic meaning.
 */
enum TagType: int
{
    case PaymentHash = 1;          // p
    case PaymentSecret = 16;       // s
    case Description = 13;         // d
    case Metadata = 27;            // m
    case PayeeNodeKey = 19;        // n
    case DescriptionHash = 23;     // h
    case Expiry = 6;               // x
    case MinFinalCltvExpiry = 24;  // c
    case FallbackAddress = 9;      // f
    case RouteHint = 3;            // r
    case FeatureBits = 5;          // 9

    /**
     * Get the human-readable tag name.
     */
    public function tagName(): string
    {
        return match ($this) {
            self::PaymentHash => 'payment_hash',
            self::PaymentSecret => 'payment_secret',
            self::Description => 'description',
            self::Metadata => 'metadata',
            self::PayeeNodeKey => 'payee',
            self::DescriptionHash => 'purpose_commit_hash',
            self::Expiry => 'expire_time',
            self::MinFinalCltvExpiry => 'min_final_cltv_expiry',
            self::FallbackAddress => 'fallback_address',
            self::RouteHint => 'route_hint',
            self::FeatureBits => 'feature_bits',
        };
    }

    /**
     * Resolve a TagType from its human-readable name.
     */
    public static function fromName(string $name): ?self
    {
        foreach (self::cases() as $case) {
            if ($case->tagName() === $name) {
                return $case;
            }
        }

        return null;
    }
}
