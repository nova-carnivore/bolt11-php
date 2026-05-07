<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

/**
 * Represents feature bits from a BOLT 11 invoice.
 *
 * Feature bits are encoded in 5-bit words (big-endian). For each pair, the
 * even bit indicates "required", the odd bit indicates "optional/supported".
 *
 * The set of *known* (tracked) feature pairs covers the BOLT 9 features that
 * appear in invoice context. Anything else that is set lands in `extraBits`.
 */
final readonly class FeatureBits
{
    /**
     * Map of even bit index → property name. Each entry covers a feature pair
     * (`even` = required, `even + 1` = optional). A bit is "known" iff its
     * even-numbered partner is a key here.
     */
    private const array KNOWN_FEATURES = [
        0 => 'optionDataLossProtect',
        2 => 'initialRoutingSync',
        4 => 'optionUpfrontShutdownScript',
        6 => 'gossipQueries',
        8 => 'varOnionOptin',
        10 => 'gossipQueriesEx',
        12 => 'optionStaticRemotekey',
        14 => 'paymentSecret',
        16 => 'basicMpp',
        18 => 'optionSupportLargeChannel',
        24 => 'optionRouteBlinding',
        48 => 'optionPaymentMetadata',
    ];

    /**
     * @param int $wordLength Number of 5-bit words used
     * @param array{required: bool, supported: bool}|null $optionDataLossProtect Feature bits 0/1
     * @param array{required: bool, supported: bool}|null $initialRoutingSync Feature bits 2/3
     * @param array{required: bool, supported: bool}|null $optionUpfrontShutdownScript Feature bits 4/5
     * @param array{required: bool, supported: bool}|null $gossipQueries Feature bits 6/7
     * @param array{required: bool, supported: bool}|null $varOnionOptin Feature bits 8/9
     * @param array{required: bool, supported: bool}|null $gossipQueriesEx Feature bits 10/11
     * @param array{required: bool, supported: bool}|null $optionStaticRemotekey Feature bits 12/13
     * @param array{required: bool, supported: bool}|null $paymentSecret Feature bits 14/15
     * @param array{required: bool, supported: bool}|null $basicMpp Feature bits 16/17
     * @param array{required: bool, supported: bool}|null $optionSupportLargeChannel Feature bits 18/19
     * @param array{required: bool, supported: bool}|null $optionRouteBlinding Feature bits 24/25
     * @param array{required: bool, supported: bool}|null $optionPaymentMetadata Feature bits 48/49
     * @param array{bits: list<int>, has_required: bool}|null $extraBits Bits set outside the known set
     */
    public function __construct(
        public int $wordLength,
        public ?array $optionDataLossProtect = null,
        public ?array $initialRoutingSync = null,
        public ?array $optionUpfrontShutdownScript = null,
        public ?array $gossipQueries = null,
        public ?array $varOnionOptin = null,
        public ?array $gossipQueriesEx = null,
        public ?array $optionStaticRemotekey = null,
        public ?array $paymentSecret = null,
        public ?array $basicMpp = null,
        public ?array $optionSupportLargeChannel = null,
        public ?array $optionRouteBlinding = null,
        public ?array $optionPaymentMetadata = null,
        public ?array $extraBits = null,
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
            optionDataLossProtect: $feature(0),
            initialRoutingSync: $feature(2),
            optionUpfrontShutdownScript: $feature(4),
            gossipQueries: $feature(6),
            varOnionOptin: $feature(8),
            gossipQueriesEx: $feature(10),
            optionStaticRemotekey: $feature(12),
            paymentSecret: $feature(14),
            basicMpp: $feature(16),
            optionSupportLargeChannel: $feature(18),
            optionRouteBlinding: $feature(24),
            optionPaymentMetadata: $feature(48),
            extraBits: $extraBitsArr === [] ? null : [
                'bits' => $extraBitsArr,
                'has_required' => $hasRequired,
            ],
        );
    }

    /**
     * Encode this feature bits back to 5-bit words.
     *
     * @return list<int>
     */
    public function toWords(): array
    {
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

        $setFeature(0, $this->optionDataLossProtect);
        $setFeature(2, $this->initialRoutingSync);
        $setFeature(4, $this->optionUpfrontShutdownScript);
        $setFeature(6, $this->gossipQueries);
        $setFeature(8, $this->varOnionOptin);
        $setFeature(10, $this->gossipQueriesEx);
        $setFeature(12, $this->optionStaticRemotekey);
        $setFeature(14, $this->paymentSecret);
        $setFeature(16, $this->basicMpp);
        $setFeature(18, $this->optionSupportLargeChannel);
        $setFeature(24, $this->optionRouteBlinding);
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
