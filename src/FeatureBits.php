<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

/**
 * Represents feature bits from a BOLT 11 invoice.
 *
 * Feature bits are encoded in 5-bit words (big-endian). Even bits indicate
 * "required", odd bits indicate "optional/supported".
 */
final readonly class FeatureBits
{
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
     * @param array{start_bit: int, bits: list<int>, has_required: bool}|null $extraBits Extra feature bits beyond the known set
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

        $getBit = static fn (int $i): bool => $i < count($bits) && $bits[$i];

        /**
         * @return array{required: bool, supported: bool}|null
         */
        $feature = static function (int $even) use ($getBit): ?array {
            $req = $getBit($even);
            $sup = $getBit($even + 1);
            if (!$req && !$sup) {
                return null;
            }

            // "supported" is true when either bit is set
            $supported = $req ? true : $sup;

            return ['required' => $req, 'supported' => $supported];
        };

        $knownEnd = 20;
        $extraBitsArr = [];
        $hasRequired = false;

        for ($i = $knownEnd; $i < count($bits); $i++) {
            if ($bits[$i]) {
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
            extraBits: [
                'start_bit' => $knownEnd,
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
            if ($i < $totalBits) {
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

        if ($this->extraBits !== null) {
            foreach ($this->extraBits['bits'] as $b) {
                $setBit($b);
            }
        }

        // Convert bit array to 5-bit words (big-endian)
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
