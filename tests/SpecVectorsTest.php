<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Decoder;
use PHPUnit\Framework\TestCase;

/**
 * BOLT 11 Specification Test Vectors.
 *
 * Source: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
 */
final class SpecVectorsTest extends TestCase
{
    private const string SPEC_PUBKEY = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';
    private const string SPEC_PAYMENT_HASH = '0001020304050607080900010203040506070809000102030405060708090102';
    private const string SPEC_PAYMENT_SECRET = '1111111111111111111111111111111111111111111111111111111111111111';

    public function testVector1DonationAnyAmount(): void
    {
        $d = Decoder::decode(
            'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql',
        );

        self::assertTrue($d->complete);
        self::assertSame('lnbc', $d->prefix);
        self::assertSame('bc', $d->network?->value);
        self::assertNull($d->satoshis);
        self::assertNull($d->millisatoshis);
        self::assertSame(1496314658, $d->timestamp);
        self::assertSame(self::SPEC_PAYMENT_HASH, $d->getPaymentHash());
        self::assertSame(self::SPEC_PAYMENT_SECRET, $d->getPaymentSecret());
        self::assertSame('Please consider supporting this project', $d->getDescription());
        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
        self::assertSame(
            '8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d81127425e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1',
            $d->signature,
        );
        self::assertSame(1, $d->recoveryFlag);
    }

    public function testVector2CoffeeWithExpiry(): void
    {
        $d = Decoder::decode(
            'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh',
        );

        self::assertSame('bc', $d->network?->value);
        self::assertSame(250000, $d->satoshis);
        self::assertSame('250000000', $d->millisatoshis);
        self::assertSame(self::SPEC_PAYMENT_HASH, $d->getPaymentHash());
        self::assertSame(self::SPEC_PAYMENT_SECRET, $d->getPaymentSecret());
        self::assertSame('1 cup coffee', $d->getDescription());
        self::assertSame(60, $d->getTag('expire_time')?->data);
        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
        self::assertSame(
            'e59e3ffbd3945e4334879158d31e89b076dff54f3fa7979ae79df2db9dcaf5896cbfe1a478b8d2307e92c88139464cb7e6ef26e414c4abe33337961ddc5e8ab1',
            $d->signature,
        );
        self::assertSame(1, $d->recoveryFlag);
    }

    public function testVector3Utf8Description(): void
    {
        $d = Decoder::decode(
            'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr',
        );

        self::assertSame(250000, $d->satoshis);
        self::assertSame('250000000', $d->millisatoshis);
        self::assertSame('ナンセンス 1杯', $d->getDescription());
        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
    }

    public function testVector4HashedDescription(): void
    {
        $d = Decoder::decode(
            'lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44',
        );

        self::assertSame(2000000, $d->satoshis);
        self::assertSame('2000000000', $d->millisatoshis);
        self::assertSame(
            '3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1',
            $d->getDescriptionHash(),
        );
        self::assertNull($d->getDescription());
        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
    }

    public function testVector5TestnetWithP2pkhFallback(): void
    {
        $d = Decoder::decode(
            'lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8',
        );

        self::assertSame('tb', $d->network?->value);
        self::assertSame(2000000, $d->satoshis);
        self::assertNotNull($d->getFallbackAddress());
        self::assertSame(17, $d->getFallbackAddress()->code); // P2PKH
        self::assertSame(
            '3172b5654f6683c8fb146959d347ce303cae4ca7',
            $d->getFallbackAddress()->addressHash,
        );
        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
    }

    public function testVector6MainnetWithFallbackAndRouteHints(): void
    {
        $d = Decoder::decode(
            'lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0',
        );

        self::assertSame('bc', $d->network?->value);
        self::assertSame(2000000, $d->satoshis);

        // Fallback: P2PKH
        self::assertNotNull($d->getFallbackAddress());
        self::assertSame(17, $d->getFallbackAddress()->code);

        // Route hints: 2 hops
        $routes = $d->getRouteHints();
        self::assertNotNull($routes);
        self::assertCount(2, $routes);

        // First hop
        self::assertSame(
            '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
            $routes[0]->pubkey,
        );
        self::assertSame('0102030405060708', $routes[0]->shortChannelId);
        self::assertSame(1, $routes[0]->feeBaseMsat);
        self::assertSame(20, $routes[0]->feeProportionalMillionths);
        self::assertSame(3, $routes[0]->cltvExpiryDelta);

        // Second hop
        self::assertSame(
            '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255',
            $routes[1]->pubkey,
        );
        self::assertSame('030405060708090a', $routes[1]->shortChannelId);
        self::assertSame(2, $routes[1]->feeBaseMsat);
        self::assertSame(30, $routes[1]->feeProportionalMillionths);
        self::assertSame(4, $routes[1]->cltvExpiryDelta);
    }

    public function testVector7FeatureBits(): void
    {
        $d = Decoder::decode(
            'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa',
        );

        self::assertSame(2500000, $d->satoshis);
        self::assertSame('coffee beans', $d->getDescription());

        $fb = $d->getFeatureBits();
        self::assertNotNull($fb);

        // Feature bit 8 = var_onion_optin
        self::assertNotNull($fb->varOnionOptin);
        self::assertTrue($fb->varOnionOptin['supported']);

        // Feature bit 14 = payment_secret
        self::assertNotNull($fb->paymentSecret);
        self::assertTrue($fb->paymentSecret['supported']);

        // Feature bit 99 = unknown extra feature
        self::assertNotNull($fb->extraBits);
        self::assertContains(99, $fb->extraBits['bits']);
    }

    public function testVector8UppercaseInvoice(): void
    {
        $d = Decoder::decode(
            'LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3SGPZ3UAPA',
        );

        self::assertSame(2500000, $d->satoshis);
        self::assertSame('coffee beans', $d->getDescription());
        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
    }

    public function testVector9Metadata(): void
    {
        $d = Decoder::decode(
            'lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc',
        );

        self::assertSame(1000000, $d->satoshis);
        self::assertSame('payment metadata inside', $d->getDescription());
        self::assertSame('01fafaf0', $d->getMetadata());
    }

    public function testVector10PicoBtcAmount(): void
    {
        $d = Decoder::decode(
            'lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz',
        );

        self::assertSame('967878534', $d->millisatoshis);
        self::assertNull($d->satoshis);
        self::assertSame(
            '462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f',
            $d->getPaymentHash(),
        );
        self::assertSame(10, $d->getTag('min_final_cltv_expiry')?->data);
        self::assertNotNull($d->getRouteHints());
        self::assertCount(1, $d->getRouteHints());
    }

    public function testVector11HighSSignatureRecovery(): void
    {
        $d = Decoder::decode(
            'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap2r09nt4ndd0unm3z9u5t48y6ucv4r5sg7lk98c77ctvjczkspk5qprc90gx',
        );

        self::assertSame(self::SPEC_PUBKEY, $d->payeeNodeKey);
    }

    public function testVector12UnknownTagsSilentlyIgnored(): void
    {
        $d = Decoder::decode(
            'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x',
        );

        self::assertSame('coffee beans', $d->getDescription());
        self::assertSame(self::SPEC_PAYMENT_HASH, $d->getPaymentHash());
        self::assertSame(self::SPEC_PAYMENT_SECRET, $d->getPaymentSecret());
    }
}
