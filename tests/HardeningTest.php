<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Mdanter\Ecc\EccFactory;
use Nova\Bitcoin\Bolt11\Amount;
use Nova\Bitcoin\Bolt11\Bech32;
use Nova\Bitcoin\Bolt11\Decoder;
use Nova\Bitcoin\Bolt11\Encoder;
use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;
use Nova\Bitcoin\Bolt11\FeatureBits;
use Nova\Bitcoin\Bolt11\Helpers;
use Nova\Bitcoin\Bolt11\Network;
use Nova\Bitcoin\Bolt11\RouteHint;
use Nova\Bitcoin\Bolt11\Secp256k1Recovery;
use Nova\Bitcoin\Bolt11\Signer;
use Nova\Bitcoin\Bolt11\Tag;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the spec-compliance and security hardening fixes
 * (findings A–N of the July 2026 review). Each test pins down a specific
 * malformed/hostile input and asserts the library fails cleanly with a domain
 * exception (or behaves correctly), never a raw TypeError/Error or a silently
 * corrupt value.
 */
final class HardeningTest extends TestCase
{
    private const string PRIVATE_KEY = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734';

    /** @param list<int> $tagWords */
    private function craftFromTagWords(array $tagWords, string $hrp = 'lnbc'): string
    {
        $words = [
            ...Bech32::intToWords(1700000000, 7),
            ...$tagWords,
            ...array_fill(0, 104, 0),
        ];

        return Bech32::encode($hrp, $words);
    }

    /**
     * @param list<int> $data
     * @return list<int>
     */
    private static function tagWords(int $type, array $data): array
    {
        $len = count($data);

        return [$type, ($len >> 5) & 0x1f, $len & 0x1f, ...$data];
    }

    /** @return list<int> */
    private function requiredTagWords(): array
    {
        return [
            ...self::tagWords(1, Bech32::eightToFive(Bech32::hexToBytes(
                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            ))),
            ...self::tagWords(16, Bech32::eightToFive(Bech32::hexToBytes(
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            ))),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('hardening'))),
        ];
    }

    // ── A: amount overflow → domain exception, not TypeError / float string ──

    public function testDecodeOversizedAmountWithMultiplierThrowsDomainException(): void
    {
        // Valid-checksum invoice whose HRP amount overflows a native int.
        // Before the fix this threw a raw TypeError from Multiplier::toMsat.
        $invoice = $this->craftFromTagWords($this->requiredTagWords(), 'lnbc99999999999999999999m');

        $this->expectException(InvalidAmountException::class);
        Decoder::decode($invoice);
    }

    public function testDecodeOversizedAmountNoMultiplierThrowsDomainException(): void
    {
        $invoice = $this->craftFromTagWords($this->requiredTagWords(), 'lnbc99999999999999999999');

        $this->expectException(InvalidAmountException::class);
        Decoder::decode($invoice);
    }

    public function testAmountFromHrpNeverReturnsFloatString(): void
    {
        // Just under the 21M BTC cap stays a plain decimal string.
        $amount = Amount::fromHrp('20999999m');
        self::assertMatchesRegularExpression('/^\d+$/', $amount->millisatoshis);
    }

    public function testAmountAboveSupplyCapRejected(): void
    {
        $this->expectException(InvalidAmountException::class);
        // 22M BTC in milli-bitcoin units exceeds the 21M supply cap.
        Amount::fromHrp('22000000000m');
    }

    public function testHelpersOversizedAmountThrows(): void
    {
        $this->expectException(InvalidAmountException::class);
        Helpers::hrpToMillisat('99999999999999999999u');
    }

    // ── G: pico trailing-zero rule uses the decimal string, not a cast ──

    public function testPicoTrailingZeroCheckUsesString(): void
    {
        // Within range, a non-trailing-zero pico is rejected for the right reason.
        $this->expectException(InvalidAmountException::class);
        $this->expectExceptionMessage('pico-bitcoin');
        Helpers::hrpToMillisat('9678785341p');
    }

    // ── #16: msatToHrpString pico branch is overflow-safe ──

    public function testMsatToHrpStringLargePicoNoScientificNotation(): void
    {
        // A large sub-satoshi msat value must not overflow to "…E+…p".
        $hrp = Helpers::millisatToHrp('999999999999999999');
        self::assertStringNotContainsString('E', $hrp);
        self::assertMatchesRegularExpression('/^\d+p$/', $hrp);
    }

    // ── C: oversized x/c field → domain exception, not TypeError ──

    public function testDecodeOversizedExpiryFieldThrowsDomainException(): void
    {
        // x (type 6) with 20 max-value words overflows a native int.
        $tagWords = [
            ...$this->requiredTagWords(),
            ...self::tagWords(6, array_fill(0, 20, 31)),
        ];
        $invoice = $this->craftFromTagWords($tagWords);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('out of range');
        Decoder::decode($invoice);
    }

    // ── B: FeatureBits decode→encode round-trip is bit-identical ──

    public function testFeatureBitsRoundTripIsIdentity(): void
    {
        foreach ([[16, 8, 0], [16, 24, 0], [1, 0, 0, 0, 0], [8, 0, 0, 0, 0, 0, 0, 0, 0, 0]] as $words) {
            self::assertSame($words, FeatureBits::fromWords($words)->toWords());
        }
    }

    // ── D: recovery rejects the point at infinity ──

    public function testRecoveryRejectsPointAtInfinity(): void
    {
        $gen = EccFactory::getSecgCurves()->generator256k1();
        $adapter = EccFactory::getAdapter();
        $n = $gen->getOrder();

        // Craft (r,s) so that s*R = z*G, i.e. Q = infinity: s=1, k=z mod n.
        $z = gmp_init('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 16);
        $k = gmp_mod($z, $n);
        $r = $gen->mul($k);
        $flag = gmp_cmp(gmp_mod($r->getY(), gmp_init(2)), gmp_init(0)) === 0 ? 0 : 1;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('infinity');
        Secp256k1Recovery::recoverPublicKey($gen, $adapter, $z, $r->getX(), gmp_init(1), $flag);
    }

    // ── E: RouteHint rejects out-of-range wire fields ──

    public function testRouteHintRejectsOversizedFeeBase(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        new RouteHint('02' . str_repeat('00', 32), str_repeat('00', 8), 0x1_0000_0000, 20, 3);
    }

    public function testRouteHintRejectsOversizedCltv(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        new RouteHint('02' . str_repeat('00', 32), str_repeat('00', 8), 1, 20, 0x1_0000);
    }

    public function testRouteHintRejectsNegativeFee(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        new RouteHint('02' . str_repeat('00', 32), str_repeat('00', 8), -1, 20, 3);
    }

    // ── F: writer emits a minimal `9` field (no leading zero words) ──

    public function testEncoderStripsLeadingZeroFeatureWords(): void
    {
        // A feature vector with a leading zero word (bit 9 = var_onion optional)
        // must re-encode minimally, so the library's own decoder accepts it.
        $fb = FeatureBits::fromWords([0, 16, 0]);
        $unsigned = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 1000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('minimal features'),
                Tag::featureBits($fb),
            ],
        );
        $signed = Signer::sign($unsigned, self::PRIVATE_KEY);
        self::assertNotNull($signed->paymentRequest);

        // Decoder enforces minimal encoding; a non-minimal `9` would throw here.
        $decoded = Decoder::decode($signed->paymentRequest);
        self::assertNotNull($decoded->getFeatureBits());
    }

    // ── K: an all-zero feature vector is omitted entirely ──

    public function testEncoderOmitsAllZeroFeatureField(): void
    {
        $fb = FeatureBits::fromWords([0]);
        $unsigned = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 1000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('no features'),
                Tag::featureBits($fb),
            ],
        );
        $signed = Signer::sign($unsigned, self::PRIVATE_KEY);
        self::assertNotNull($signed->paymentRequest);

        $decoded = Decoder::decode($signed->paymentRequest);
        self::assertNull($decoded->getFeatureBits());
    }

    // ── H: writer rejects fixed-length p/s/h/n with the wrong byte length ──

    public function testSignerRejectsWrongLengthPaymentHash(): void
    {
        $unsigned = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 1000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash(str_repeat('aa', 16)), // 16 bytes, must be 32
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('short hash'),
            ],
        );

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('must be 32 bytes');
        Signer::sign($unsigned, self::PRIVATE_KEY);
    }

    // ── I: transitive feature dependencies (payment_metadata → var_onion) ──

    public function testPaymentMetadataWithoutVarOnionRejected(): void
    {
        // option_payment_metadata (bit 48) required, var_onion_optin (bit 8) absent.
        $fbWords = (new FeatureBits(
            wordLength: 10,
            optionPaymentMetadata: ['required' => true, 'supported' => false],
        ))->toWords();

        $tagWords = [
            ...$this->requiredTagWords(),
            ...self::tagWords(5, $fbWords),
        ];
        $invoice = $this->craftFromTagWords($tagWords);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('var_onion_optin');
        Decoder::decode($invoice);
    }

    // ── J: writer rejects an out-of-range 35-bit timestamp ──

    public function testEncoderRejectsTooLargeTimestamp(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        Encoder::encode(
            satoshis: 1000,
            timestamp: 34359738368, // 2^35, one past the field
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('bad ts'),
            ],
        );
    }

    public function testEncoderRejectsNegativeTimestamp(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        Encoder::encode(
            satoshis: 1000,
            timestamp: -1,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('bad ts'),
            ],
        );
    }

    // ── L: decode path rejects absurdly long input ──

    public function testDecodeRejectsOverlongInput(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('maximum length');
        Bech32::decode('lnbc1' . str_repeat('q', 25000));
    }

    // ── M: bech32 rejects HRP characters outside [33,126] ──

    public function testBech32RejectsOutOfRangeHrpCharacter(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('range');
        Bech32::decode("\x7f1qqqqqq");
    }
}
