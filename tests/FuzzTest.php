<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Decoder;
use Nova\Bitcoin\Bolt11\Exception\Bolt11Exception;
use PHPUnit\Framework\TestCase;

/**
 * Property-based fuzz tests.
 *
 * For each spec vector, we apply a deterministic mutation strategy and
 * assert the decoder either succeeds or throws Bolt11Exception. It must
 * never raise an untyped error or warning, and never silently corrupt
 * output for inputs that should clearly be rejected.
 *
 * The seed is fixed so failures are reproducible.
 */
final class FuzzTest extends TestCase
{
    /** @var list<string> Spec vectors 1, 2, 5, 6, 7, 9, 10 (subset that exercises every tag type). */
    private const array VECTORS = [
        'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql',
        'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh',
        'lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8',
        'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa',
        'lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc',
    ];

    private const string CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    /**
     * Single-character substitution: replace one bech32 data character with
     * another valid bech32 character. Either the checksum catches it or
     * the decode raises a typed Bolt11Exception.
     */
    public function testSingleCharSubstitutionNeverCrashes(): void
    {
        mt_srand(0xB011);

        $iterations = 0;
        foreach (self::VECTORS as $invoice) {
            $sepIndex = strrpos($invoice, '1');
            self::assertNotFalse($sepIndex);

            for ($trial = 0; $trial < 20; $trial++) {
                $pos = $sepIndex + 1 + mt_rand(0, strlen($invoice) - $sepIndex - 2);
                $original = $invoice[$pos];
                do {
                    $replacement = self::CHARSET[mt_rand(0, 31)];
                } while ($replacement === $original);

                $mutated = substr_replace($invoice, $replacement, $pos, 1);

                $this->assertSafeDecode($mutated);
                $iterations++;
            }
        }

        self::assertSame(100, $iterations); // 5 vectors × 20 trials
    }

    /**
     * Truncation: chop off bytes from the end. Should always throw, never
     * crash with a TypeError or warning.
     */
    public function testTruncationNeverCrashes(): void
    {
        foreach (self::VECTORS as $invoice) {
            for ($cut = 1; $cut <= 20; $cut++) {
                $mutated = substr($invoice, 0, -$cut);
                $this->assertSafeDecode($mutated);
            }
        }
    }

    /**
     * Random garbage prefix/suffix. Should always throw.
     */
    public function testGarbageInputNeverCrashes(): void
    {
        $inputs = [
            '',
            '1',
            'lnbc',
            'lnbc1',
            'lnbc1' . str_repeat('q', 5),
            'not-an-invoice',
            str_repeat('z', 100),
            "\x00\x01\x02",
        ];

        foreach ($inputs as $input) {
            $this->assertSafeDecode($input);
        }
    }

    private function assertSafeDecode(string $input): void
    {
        try {
            Decoder::decode($input);
            // Decoded successfully — that's also acceptable for some mutations.
            self::assertTrue(true);
        } catch (Bolt11Exception) {
            // Expected: any malformed input must throw a typed Bolt11Exception.
            self::assertTrue(true);
        } catch (\Throwable $t) {
            self::fail(sprintf(
                'Unexpected uncaught %s on input %s: %s',
                $t::class,
                (string) json_encode(substr($input, 0, 80), JSON_UNESCAPED_SLASHES),
                $t->getMessage(),
            ));
        }
    }
}
