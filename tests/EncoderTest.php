<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Encoder;
use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;
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

    public function testUnsignedInvoiceHasWordsTemp(): void
    {
        $pr = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 1000,
            timestamp: 1496314658,
            tags: $this->makeBasicTags(),
        );

        self::assertNotEmpty($pr->wordsTemp);
        self::assertStringStartsWith('lnbc', $pr->wordsTemp);
    }

    public function testHrpGenerationForVariousAmounts(): void
    {
        $makeEncode = fn (?int $sat = null, ?string $msat = null) => Encoder::encode(
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

        self::assertStringStartsWith('lntbs', $signed->paymentRequest);
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

        self::assertStringStartsWith('lnbcrt', $signed->paymentRequest);
    }
}
