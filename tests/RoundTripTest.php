<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Tests;

use Nova\Bitcoin\Decoder;
use Nova\Bitcoin\Encoder;
use Nova\Bitcoin\Network;
use Nova\Bitcoin\RouteHint;
use Nova\Bitcoin\Signer;
use Nova\Bitcoin\Tag;
use PHPUnit\Framework\TestCase;

/**
 * Round-trip tests: encode → sign → decode.
 */
final class RoundTripTest extends TestCase
{
    private const string PRIVATE_KEY = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734';
    private const string SPEC_PUBKEY = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';

    public function testBasicRoundTrip(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 100000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('Round trip test'),
                Tag::expiry(3600),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertSame(100000, $decoded->satoshis);
        self::assertSame(1700000000, $decoded->timestamp);
        self::assertSame(
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            $decoded->getPaymentHash(),
        );
        self::assertSame(
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            $decoded->getPaymentSecret(),
        );
        self::assertSame('Round trip test', $decoded->getDescription());
        self::assertSame(3600, $decoded->getTag('expire_time')?->data);
        self::assertSame(self::SPEC_PUBKEY, $decoded->payeeNodeKey);
    }

    public function testNoAmountRoundTrip(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'),
                Tag::paymentSecret('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
                Tag::description('Donation'),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertNull($decoded->satoshis);
        self::assertNull($decoded->millisatoshis);
        self::assertSame('Donation', $decoded->getDescription());
    }

    public function testMillisatoshisRoundTrip(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            millisatoshis: '967878534',
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'),
                Tag::paymentSecret('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
                Tag::description('Fractional satoshis'),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertSame('967878534', $decoded->millisatoshis);
        self::assertNull($decoded->satoshis);
    }

    public function testRoundTripWithRouteHints(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 100000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('Route hint test'),
                Tag::routeHint([
                    new RouteHint(
                        pubkey: '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
                        shortChannelId: '0102030405060708',
                        feeBaseMsat: 1,
                        feeProportionalMillionths: 20,
                        cltvExpiryDelta: 3,
                    ),
                ]),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        $routes = $decoded->getRouteHints();
        self::assertNotNull($routes);
        self::assertCount(1, $routes);
        self::assertSame(
            '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
            $routes[0]->pubkey,
        );
        self::assertSame('0102030405060708', $routes[0]->shortChannelId);
        self::assertSame(1, $routes[0]->feeBaseMsat);
        self::assertSame(20, $routes[0]->feeProportionalMillionths);
        self::assertSame(3, $routes[0]->cltvExpiryDelta);
    }

    public function testRoundTripWithFallbackAddress(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 100000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('Fallback test'),
                Tag::fallbackAddress(17, '3172b5654f6683c8fb146959d347ce303cae4ca7'),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertNotNull($decoded->getFallbackAddress());
        self::assertSame(17, $decoded->getFallbackAddress()->code);
        self::assertSame(
            '3172b5654f6683c8fb146959d347ce303cae4ca7',
            $decoded->getFallbackAddress()->addressHash,
        );
    }

    public function testRoundTripWithDescriptionHash(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 2000000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::descriptionHash('3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1'),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertSame(
            '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1',
            $decoded->getDescriptionHash(),
        );
        self::assertNull($decoded->getDescription());
    }

    public function testRoundTripWithCltvExpiry(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 100000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('CLTV test'),
                Tag::minFinalCltvExpiry(144),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertSame(144, $decoded->getTag('min_final_cltv_expiry')?->data);
    }

    public function testRoundTripWithUtf8Description(): void
    {
        $original = Encoder::encode(
            network: Network::Bitcoin,
            satoshis: 250000,
            timestamp: 1700000000,
            tags: [
                Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                Tag::description('ナンセンス 1杯 ☕'),
            ],
        );

        $signed = Signer::sign($original, self::PRIVATE_KEY);
        $decoded = Decoder::decode($signed->paymentRequest);

        self::assertSame('ナンセンス 1杯 ☕', $decoded->getDescription());
        self::assertSame(250000, $decoded->satoshis);
    }

    public function testRoundTripOnAllNetworks(): void
    {
        foreach (Network::cases() as $network) {
            $original = Encoder::encode(
                network: $network,
                satoshis: 1000,
                timestamp: 1700000000,
                tags: [
                    Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
                    Tag::paymentSecret('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
                    Tag::description("Test on {$network->name}"),
                ],
            );

            $signed = Signer::sign($original, self::PRIVATE_KEY);
            self::assertStringStartsWith(
                'ln' . $network->value,
                $signed->paymentRequest,
                "Invoice for {$network->name} should start with ln{$network->value}",
            );

            $decoded = Decoder::decode($signed->paymentRequest);
            self::assertSame($network->value, $decoded->network?->value);
            self::assertSame(1000, $decoded->satoshis);
            self::assertSame("Test on {$network->name}", $decoded->getDescription());
        }
    }
}
