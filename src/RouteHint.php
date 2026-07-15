<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;

/**
 * Represents a single hop in a route hint.
 *
 * Each hop is 51 bytes: 33 (pubkey) + 8 (short_channel_id) + 4 (fee_base_msat) +
 * 4 (fee_proportional_millionths) + 2 (cltv_expiry_delta).
 */
final readonly class RouteHint
{
    public function __construct(
        public string $pubkey,
        public string $shortChannelId,
        public int $feeBaseMsat,
        public int $feeProportionalMillionths,
        public int $cltvExpiryDelta,
    ) {
        // The wire fields have fixed widths; reject out-of-range values up
        // front instead of silently truncating/wrapping them in toBytes().
        if ($feeBaseMsat < 0 || $feeBaseMsat > 0xFFFFFFFF) {
            throw new InvalidInvoiceException(
                sprintf('feeBaseMsat must fit in 32 bits (0..4294967295), got %d', $feeBaseMsat),
            );
        }
        if ($feeProportionalMillionths < 0 || $feeProportionalMillionths > 0xFFFFFFFF) {
            throw new InvalidInvoiceException(
                sprintf('feeProportionalMillionths must fit in 32 bits (0..4294967295), got %d', $feeProportionalMillionths),
            );
        }
        if ($cltvExpiryDelta < 0 || $cltvExpiryDelta > 0xFFFF) {
            throw new InvalidInvoiceException(
                sprintf('cltvExpiryDelta must fit in 16 bits (0..65535), got %d', $cltvExpiryDelta),
            );
        }
    }

    /**
     * Serialize this hop to bytes (51 bytes).
     *
     * @return list<int>
     */
    public function toBytes(): array
    {
        $bytes = [];

        // pubkey: 33 bytes
        $pubkeyBytes = Bech32::hexToBytes($this->pubkey);
        foreach ($pubkeyBytes as $b) {
            $bytes[] = $b;
        }

        // short_channel_id: 8 bytes
        $scidBytes = Bech32::hexToBytes($this->shortChannelId);
        foreach ($scidBytes as $b) {
            $bytes[] = $b;
        }

        // fee_base_msat: 4 bytes big-endian
        $bytes[] = ($this->feeBaseMsat >> 24) & 0xff;
        $bytes[] = ($this->feeBaseMsat >> 16) & 0xff;
        $bytes[] = ($this->feeBaseMsat >> 8) & 0xff;
        $bytes[] = $this->feeBaseMsat & 0xff;

        // fee_proportional_millionths: 4 bytes big-endian
        $bytes[] = ($this->feeProportionalMillionths >> 24) & 0xff;
        $bytes[] = ($this->feeProportionalMillionths >> 16) & 0xff;
        $bytes[] = ($this->feeProportionalMillionths >> 8) & 0xff;
        $bytes[] = $this->feeProportionalMillionths & 0xff;

        // cltv_expiry_delta: 2 bytes big-endian
        $bytes[] = ($this->cltvExpiryDelta >> 8) & 0xff;
        $bytes[] = $this->cltvExpiryDelta & 0xff;

        return $bytes;
    }
}
