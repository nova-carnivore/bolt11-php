<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

/**
 * Represents feature bits from a BOLT 11 invoice.
 *
 * Feature bits are encoded in 5-bit words (big-endian). For each pair, the
 * even bit indicates "required", the odd bit indicates "optional/supported".
 *
 * The known set is **deliberately scoped to BOLT 9 invoice-context features
 * only** (those whose Context column contains `9`). Channel- and init-only
 * features (`option_data_loss_protect`, `option_upfront_shutdown_script`,
 * etc.) are NOT tracked here: per BOLT 11, a reader MUST fail the payment
 * if the `9` field contains unknown even bits, and "unknown" in invoice
 * context means anything not standardised for invoices.
 */
final readonly class FeatureBits
{
    /**
     * Map of even bit index → property name. Each entry covers a feature pair
     * (`even` = required, `even + 1` = optional). A bit is "known" iff its
     * even-numbered partner is a key here.
     *
     * Source: BOLT 9, "Context" column containing `9`. Bits 8/9 and 14/15 are
     * marked "ASSUMED" in BOLT 9 but BOLT 11 spec test vector 7 sets them, so
     * they are tracked here as valid invoice-context bits.
     */
    private const array KNOWN_FEATURES = [
        8 => 'varOnionOptin',
        14 => 'paymentSecret',
        16 => 'basicMpp',
        24 => 'optionRouteBlinding',
        36 => 'optionAttributionData',
        48 => 'optionPaymentMetadata',
    ];

    /**
     * @param int $wordLength Number of 5-bit words used
     * @param array{required: bool, supported: bool}|null $varOnionOptin Feature bits 8/9
     * @param array{required: bool, supported: bool}|null $paymentSecret Feature bits 14/15
     * @param array{required: bool, supported: bool}|null $basicMpp Feature bits 16/17
     * @param array{required: bool, supported: bool}|null $optionRouteBlinding Feature bits 24/25
     * @param array{required: bool, supported: bool}|null $optionAttributionData Feature bits 36/37
     * @param array{required: bool, supported: bool}|null $optionPaymentMetadata Feature bits 48/49
     * @param array{bits: list<int>, has_required: bool}|null $extraBits Bits set outside the known set
     * @param list<int>|null $rawWords The exact 5-bit words this was parsed from, if any.
     *        When present, toWords() replays them verbatim so a decode→encode
     *        round-trip is bit-identical (the required/supported view is lossy
     *        and cannot, by itself, distinguish "required only" from "both bits").
     */
    public function __construct(
        public int $wordLength,
        public ?array $varOnionOptin = null,
        public ?array $paymentSecret = null,
        public ?array $basicMpp = null,
        public ?array $optionRouteBlinding = null,
        public ?array $optionAttributionData = null,
        public ?array $optionPaymentMetadata = null,
        public ?array $extraBits = null,
        private ?array $rawWords = null,
    ) {
    }

    /**
     * Parse feature bits from 5-bit words.
     *
     * @param list<int> $words
     */
    public static function fromWords(array $words): self
    {
        $totalBits = count($words) * 5;
        $bits = array_fill(0, $totalBits, false);

        for ($w = 0; $w < count($words); $w++) {
            for ($b = 0; $b < 5; $b++) {
                $bitIndex = $totalBits - 1 - ($w * 5 + (4 - $b));
                $bits[$bitIndex] = (($words[$w] >> $b) & 1) === 1;
            }
        }

        $getBit = static fn (int $i): bool => $i >= 0 && $i < count($bits) && $bits[$i];

        /**
         * @return array{required: bool, supported: bool}|null
         */
        $feature = static function (int $even) use ($getBit): ?array {
            $req = $getBit($even);
            $sup = $getBit($even + 1);
            if (!$req && !$sup) {
                return null;
            }

            return ['required' => $req, 'supported' => $req ? true : $sup];
        };

        // Build the set of bit positions that fall under a tracked feature.
        $knownPositions = [];
        foreach (self::KNOWN_FEATURES as $even => $_propertyName) {
            $knownPositions[$even] = true;
            $knownPositions[$even + 1] = true;
        }

        $extraBitsArr = [];
        $hasRequired = false;
        for ($i = 0; $i < count($bits); $i++) {
            if ($bits[$i] && !isset($knownPositions[$i])) {
                $extraBitsArr[] = $i;
                if ($i % 2 === 0) {
                    $hasRequired = true;
                }
            }
        }

        return new self(
            wordLength: count($words),
            varOnionOptin: $feature(8),
            paymentSecret: $feature(14),
            basicMpp: $feature(16),
            optionRouteBlinding: $feature(24),
            optionAttributionData: $feature(36),
            optionPaymentMetadata: $feature(48),
            extraBits: $extraBitsArr === [] ? null : [
                'bits' => $extraBitsArr,
                'has_required' => $hasRequired,
            ],
            rawWords: $words,
        );
    }

    /**
     * Encode this feature bits back to 5-bit words.
     *
     * @return list<int>
     */
    public function toWords(): array
    {
        // Faithful round-trip: if this instance was parsed from the wire, emit
        // the exact same words. The required/supported model is a lossy view
        // (a required-only bit and a required+optional pair both read as
        // required=true, supported=true), so re-deriving would corrupt the
        // signed feature vector.
        if ($this->rawWords !== null) {
            return $this->rawWords;
        }

        $totalBits = $this->wordLength * 5;
        $bits = array_fill(0, $totalBits, false);

        $setBit = static function (int $i) use (&$bits, $totalBits): void {
            if ($i >= 0 && $i < $totalBits) {
                $bits[$i] = true;
            }
        };

        $setFeature = static function (int $even, ?array $f) use ($setBit): void {
            if ($f === null) {
                return;
            }
            if ($f['required']) {
                $setBit($even);
            }
            if ($f['supported']) {
                $setBit($even + 1);
            }
        };

        $setFeature(8, $this->varOnionOptin);
        $setFeature(14, $this->paymentSecret);
        $setFeature(16, $this->basicMpp);
        $setFeature(24, $this->optionRouteBlinding);
        $setFeature(36, $this->optionAttributionData);
        $setFeature(48, $this->optionPaymentMetadata);

        if ($this->extraBits !== null) {
            foreach ($this->extraBits['bits'] as $b) {
                $setBit($b);
            }
        }

        $words = [];
        for ($w = 0; $w < $this->wordLength; $w++) {
            $val = 0;
            for ($b = 0; $b < 5; $b++) {
                $bitIdx = $totalBits - 1 - ($w * 5 + (4 - $b));
                if ($bitIdx >= 0 && $bits[$bitIdx]) {
                    $val |= 1 << $b;
                }
            }
            $words[] = $val;
        }

        return $words;
    }
}
