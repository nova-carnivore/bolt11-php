<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Decoder;
use Nova\Bitcoin\Bolt11\Encoder;
use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;
use Nova\Bitcoin\Bolt11\Exception\InvalidSignatureException;
use Nova\Bitcoin\Bolt11\Invoice;
use Nova\Bitcoin\Bolt11\Network;
use Nova\Bitcoin\Bolt11\Signer;
use Nova\Bitcoin\Bolt11\Tag;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the Encoder and Signer.
 */
final class EncoderTest extends TestCase
{
    private const string PRIVATE_KEY = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734';
    private const string SPEC_PUBKEY = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';

    /**
     * @return list<Tag>
     */
    private function makeBasicTags(): array
    {
        return [
            Tag::paymentHash('0001020304050607080900010203040506070809000102030405060708090102'),
            Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
            Tag::description('test'),
        ];
    }

    public function testCreatesUnsignedInvoice(): void
    {
        $pr = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 250000,
            timestamp: 1496314658,
            tags: [
                Tag::paymentHash('0001020304050607080900010203040506070809000102030405060708090102'),
                Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
                Tag::description('1 cup coffee'),
            ],
        );

        self::assertFalse($pr->complete);
        self::assertSame(250000, $pr->satoshis);
        self::assertSame(1496314658, $pr->timestamp);
        self::assertSame(
            '0001020304050607080900010203040506070809000102030405060708090102',
            $pr->getPaymentHash(),
        );
        self::assertSame('1 cup coffee', $pr->getDescription());
    }

    public function testHrpGenerationForVariousAmounts(): void
    {
        $makeEncode = fn (?int $sat = null, ?string $msat = null): Invoice => Encoder::encode(
            network: Network::Bitcoin,
            satoshis: $sat,
            millisatoshis: $msat,
            tags: $this->makeBasicTags(),
        );

        self::assertSame('lnbc10u', $makeEncode(1000)->prefix);
        self::assertSame('lnbc2500u', $makeEncode(250000)->prefix);
        self::assertSame('lnbc20m', $makeEncode(2000000)->prefix);
        self::assertSame('lnbc25m', $makeEncode(2500000)->prefix);
        self::assertSame('lnbc', $makeEncode()->prefix);
        self::assertSame('lnbc9678785340p', $makeEncode(null, '967878534')->prefix);
    }

    public function testMissingPaymentHashThrows(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('payment_hash');

        Encoder::encode(
            tags: [
                Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
                Tag::description('test'),
            ],
        );
    }

    public function testMissingPaymentSecretThrows(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('payment_secret');

        Encoder::encode(
            tags: [
                Tag::paymentHash('0001020304050607080900010203040506070809000102030405060708090102'),
                Tag::description('test'),
            ],
        );
    }

    public function testMissingDescriptionThrows(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('description');

        Encoder::encode(
            tags: [
                Tag::paymentHash('0001020304050607080900010203040506070809000102030405060708090102'),
                Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
            ],
        );
    }

    public function testSignProducesValidInvoice(): void
    {
        $pr = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 250000,
            timestamp: 1496314658,
            tags: [
                Tag::paymentHash('0001020304050607080900010203040506070809000102030405060708090102'),
                Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
                Tag::description('1 cup coffee'),
                Tag::expiry(60),
            ],
        );

        $signed = Signer::sign($pr, self::PRIVATE_KEY);

        self::assertTrue($signed->complete);
        self::assertNotNull($signed->paymentRequest);
        self::assertStringStartsWith('lnbc', $signed->paymentRequest);
        self::assertSame(self::SPEC_PUBKEY, $signed->payeeNodeKey);
        self::assertSame(128, strlen($signed->signature)); // 64 bytes hex
        self::assertContains($signed->recoveryFlag, [0, 1]);
    }

    public function testTestnetInvoice(): void
    {
        $pr = Encoder::encode(
            network: Network::Testnet,
            satoshis: 2000000,
            timestamp: 1496314658,
            tags: [
                Tag::paymentHash('0001020304050607080900010203040506070809000102030405060708090102'),
                Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
                Tag::description('test payment'),
            ],
        );

        $signed = Signer::sign($pr, self::PRIVATE_KEY);

        self::assertNotNull($signed->paymentRequest);
        self::assertStringStartsWith('lntb', $signed->paymentRequest);
    }

    public function testSignetInvoice(): void
    {
        $pr = Encoder::encode(
            network: Network::Signet,
            satoshis: 1000,
            timestamp: 1496314658,
            tags: $this->makeBasicTags(),
        );

        $signed = Signer::sign($pr, self::PRIVATE_KEY);

        self::assertNotNull($signed->paymentRequest);
        self::assertStringStartsWith('lntbs', $signed->paymentRequest);
    }

    /**
     * Spec: "MUST NOT include an amount of 0 millisatoshis."
     * Without the fix, satoshis=0 falls through to msatToHrpString(0) and emits "0p",
     * producing a malformed prefix "lnbc0p" that no conformant reader will parse.
     */
    public function testZeroSatoshisRejected(): void
    {
        $this->expectException(InvalidAmountException::class);

        Encoder::encode(
            satoshis: 0,
            tags: $this->makeBasicTags(),
        );
    }

    public function testNegativeSatoshisRejected(): void
    {
        $this->expectException(InvalidAmountException::class);

        Encoder::encode(
            satoshis: -1,
            tags: $this->makeBasicTags(),
        );
    }

    public function testNonNumericMillisatoshisRejected(): void
    {
        $this->expectException(InvalidAmountException::class);

        Encoder::encode(
            millisatoshis: 'abc',
            tags: $this->makeBasicTags(),
        );
    }

    public function testNegativeMillisatoshisRejected(): void
    {
        $this->expectException(InvalidAmountException::class);

        Encoder::encode(
            millisatoshis: '-100',
            tags: $this->makeBasicTags(),
        );
    }

    public function testInvalidUtf8DescriptionRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('UTF-8');

        Tag::description("\xff\xfe invalid utf-8");
    }

    public function testNegativeExpiryRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);

        Tag::expiry(-1);
    }

    public function testNegativeMinFinalCltvExpiryRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);

        Tag::minFinalCltvExpiry(-1);
    }

    public function testFallbackAddressWrongLengthForP2pkhRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('Invalid fallback');

        // P2PKH (code 17) requires a 20-byte hash; we pass 19 bytes.
        Tag::fallbackAddress(17, str_repeat('aa', 19));
    }

    public function testFallbackAddressWrongLengthForP2trRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);

        // P2TR (segwit v1) requires a 32-byte hash; we pass 20 bytes.
        Tag::fallbackAddress(1, str_repeat('aa', 20));
    }

    public function testFallbackAddressUnknownVersionRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);

        Tag::fallbackAddress(20, str_repeat('aa', 20));
    }

    public function testFallbackAddressNonHexRejected(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('hex');

        Tag::fallbackAddress(17, 'zz' . str_repeat('aa', 19));
    }

    public function testZeroMillisatoshisRejected(): void
    {
        $this->expectException(InvalidAmountException::class);

        Encoder::encode(
            millisatoshis: '0',
            tags: $this->makeBasicTags(),
        );
    }

    /**
     * Per BOLT 11, "MUST set `n` to the public key used to create the
     * `signature`." If a writer constructs an unsigned invoice with an `n`
     * tag claiming a different pubkey than the signing key, the Signer must
     * fail-fast — otherwise the writer would emit an invoice that no
     * compliant reader will accept.
     */
    public function testSignerRejectsMismatchedPayeeNodeKey(): void
    {
        $unsigned = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 1000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('mismatched n tag'),
                Tag::payeeNodeKey('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'),
            ],
        );

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('does not match the public key derived from the signing private key');

        Signer::sign($unsigned, self::PRIVATE_KEY);
    }

    /**
     * The matching case: when an `n` tag is present and equals the recovered
     * key, decode succeeds and surfaces the tagged value.
     */
    public function testMatchingPayeeNodeKeyTagAccepted(): void
    {
        $unsigned = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 1000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('matching n tag'),
                Tag::payeeNodeKey(self::SPEC_PUBKEY),
            ],
        );

        $signed = Signer::sign($unsigned, self::PRIVATE_KEY);
        self::assertNotNull($signed->paymentRequest);

        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertSame(self::SPEC_PUBKEY, $decoded->payeeNodeKey);
    }

    public function testRegtestInvoice(): void
    {
        $pr = Encoder::encode(
            network: Network::Regtest,
            satoshis: 1000,
            timestamp: 1496314658,
            tags: $this->makeBasicTags(),
        );

        $signed = Signer::sign($pr, self::PRIVATE_KEY);

        self::assertNotNull($signed->paymentRequest);
        self::assertStringStartsWith('lnbcrt', $signed->paymentRequest);
    }
}
