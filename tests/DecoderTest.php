<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Bech32;
use Nova\Bitcoin\Bolt11\Decoder;
use Nova\Bitcoin\Bolt11\Encoder;
use Nova\Bitcoin\Bolt11\Exception\InvalidChecksumException;
use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;
use Nova\Bitcoin\Bolt11\Exception\InvalidSignatureException;
use Nova\Bitcoin\Bolt11\Tag;
use PHPUnit\Framework\TestCase;

/**
 * Tests for error handling in the Decoder.
 */
final class DecoderTest extends TestCase
{
    public function testInvalidChecksum(): void
    {
        $this->expectException(InvalidChecksumException::class);

        Decoder::decode(
            'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpxxxxxx',
        );
    }

    public function testMixedCaseRejected(): void
    {
        // Same body as testInvalidChecksum but with mixed case at the tail.
        // Mixed case must fail with a typed exception, not crash.
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('Mixed-case');

        Decoder::decode(
            'lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpXXXXXX',
        );
    }

    public function testNoSeparator(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('No separator');

        Decoder::decode('lnbcinvalid');
    }

    public function testTooShort(): void
    {
        $this->expectException(\Throwable::class);

        Decoder::decode('lnbc1qqqqqq');
    }

    public function testCompleteFlag(): void
    {
        $d = Decoder::decode(
            'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh',
        );

        self::assertTrue($d->complete);
    }

    public function testTimestampParsing(): void
    {
        $d = Decoder::decode(
            'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql',
        );

        self::assertSame(1496314658, $d->timestamp);
    }

    public function testPaymentRequestIsPreserved(): void
    {
        $invoice = 'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh';
        $d = Decoder::decode($invoice);

        self::assertSame($invoice, $d->paymentRequest);
    }

    /**
     * Spec: the recovery id appended after the 64-byte compact signature MUST be 0–3.
     * Higher 5-bit-word values (4–31) silently aliased onto valid flags before the fix,
     * breaking decode→encode round-trips and accepting malformed invoices.
     */
    public function testInvalidRecoveryFlagRejected(): void
    {
        // Spec vector 1 (recovery flag = 1)
        $original = 'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql';
        $decoded = Bech32::decode($original);
        $words = $decoded['data'];
        $words[count($words) - 1] = 5; // invalid: must be 0–3
        $tampered = Bech32::encode($decoded['hrp'], array_values($words));

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('recovery flag');

        Decoder::decode($tampered);
    }

    /**
     * Build a syntactically valid bech32 invoice from a list of tags and a
     * dummy (all-zero) signature. The invoice is well-formed at the bech32
     * layer but won't pass signature validation; tests use it to exercise
     * checks that run *before* signature recovery.
     *
     * @param list<Tag> $tags
     */
    private function craftInvoice(array $tags, string $hrp = 'lnbc'): string
    {
        $words = [
            ...Bech32::intToWords(1700000000, 7),
            ...Encoder::encodeAllTags($tags),
            ...array_fill(0, 104, 0),
        ];

        return Bech32::encode($hrp, $words);
    }

    /**
     * Build a tag header (type, len_high, len_low) followed by the data words.
     * Bypasses Encoder, so it can produce malformed payloads for testing.
     *
     * @param list<int> $data
     * @return list<int>
     */
    private static function tagWords(int $type, array $data): array
    {
        $len = count($data);

        return [$type, ($len >> 5) & 0x1f, $len & 0x1f, ...$data];
    }

    /**
     * Like craftInvoice() but takes raw tag words (already including
     * type/length headers).
     *
     * @param list<int> $tagWords
     */
    private function craftFromTagWords(array $tagWords, string $hrp = 'lnbc'): string
    {
        $words = [
            ...Bech32::intToWords(1700000000, 7),
            ...$tagWords,
            ...array_fill(0, 104, 0),
        ];

        return Bech32::encode($hrp, $words);
    }

    public function testMissingPaymentHashRejected(): void
    {
        $invoice = $this->craftInvoice([
            Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
            Tag::description('no p tag'),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('payment_hash');

        Decoder::decode($invoice);
    }

    public function testMissingPaymentSecretRejected(): void
    {
        $invoice = $this->craftInvoice([
            Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            Tag::description('no s tag'),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('payment_secret');

        Decoder::decode($invoice);
    }

    public function testMissingDescriptionAndHashRejected(): void
    {
        $invoice = $this->craftInvoice([
            Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('description');

        Decoder::decode($invoice);
    }

    public function testNonMinimalExpireTimeRejected(): void
    {
        // Expire-time encoded as [0, 1, 0] (= value 32 with a leading zero word).
        // Build a tag manually: type 6, length 3, data [0, 1, 0].
        $invoice = $this->craftFromTagWords([
            // valid p
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            // valid s
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            // valid d
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            // x with non-minimal encoding
            ...self::tagWords(6, [0, 1, 0]),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('non-minimal');

        Decoder::decode($invoice);
    }

    public function testNonZeroPaddingBitsInPaymentHashRejected(): void
    {
        // Take a valid p tag (52 words) and flip a padding bit in the last word.
        // Lower 4 bits of word 51 are padding and MUST be zero.
        $hashWords = Bech32::eightToFive(Bech32::hexToBytes(
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ));
        $hashWords[51] = $hashWords[51] | 0x01; // set a padding bit

        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, array_values($hashWords)),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('non-zero padding');

        Decoder::decode($invoice);
    }

    public function testNonZeroPaddingBitInPayeeNodeKeyRejected(): void
    {
        // Construct a 53-word `n` tag whose final word has the lowest bit set.
        $payeeWords = Bech32::eightToFive(Bech32::hexToBytes(
            '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad',
        ));
        // 33 bytes -> ceil(264/5) = 53 words; lowest bit of word 52 is padding.
        $payeeWords[52] = $payeeWords[52] | 0x01;

        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            ...self::tagWords(19, array_values($payeeWords)),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('non-zero padding');

        Decoder::decode($invoice);
    }

    public function testNonZeroPaddingBitsInSignatureRejected(): void
    {
        // Vector 1's bech32, but flip padding bits in the signature data word.
        $original = 'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql';
        $decoded = Bech32::decode($original);
        $words = $decoded['data'];
        // Word 102 is at $words[count - 2] (last 104 are signature: 0..102 sig, 103 flag).
        $idx = count($words) - 2;
        \assert($idx >= 0);
        $words[$idx] = $words[$idx] | 0x01; // flip a padding bit
        $tampered = Bech32::encode($decoded['hrp'], $words);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('padding bits');

        Decoder::decode($tampered);
    }

    public function testBasicMppWithoutPaymentSecretRejected(): void
    {
        // basic_mpp = bit 16. Minimum encoding requires 4 words (20 bits).
        // bit 16 sits at MSB-position 3 → word 0, bit 1 → word 0 = 1<<1 = 2.
        $featureWords = [2, 0, 0, 0];

        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            ...self::tagWords(5, $featureWords),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('basic_mpp requires payment_secret');

        Decoder::decode($invoice);
    }

    public function testPaymentSecretFeatureBitWithoutVarOnionOptinRejected(): void
    {
        // Set bit 14 (payment_secret feature) without bit 8 (var_onion_optin).
        // 3 words = 15 bits. Bit 14 sits at MSB-position 0 → word 0, bit 4
        // → word 0 = 1 << 4 = 16.
        $featureWords = [16, 0, 0];

        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            ...self::tagWords(5, $featureWords),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('payment_secret requires var_onion_optin');

        Decoder::decode($invoice);
    }

    public function testNonInvoiceContextFeatureBitRejected(): void
    {
        // Bit 0 = option_data_loss_protect — channel feature (Context: ASSUMED,
        // not invoice-context). When set required in an invoice, decode must
        // reject it as unknown-in-invoice-context.
        // 1 word = 5 bits. Bit 0 = LSB-most = bit 0 of word 0 = word 0 = 1.
        $featureWords = [1];

        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            ...self::tagWords(5, $featureWords),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('unknown feature');

        Decoder::decode($invoice);
    }

    public function testUnknownRequiredFeatureBitRejected(): void
    {
        // Set bit 22 (option_anchors_zero_fee_htlc_tx — not in our known
        // invoice-context map) and required. 22 % 2 == 0 → has_required.
        // Need enough words to encode bit 22; 5 words = 25 bits.
        // bit 22 within 25-bit total: index 22 from the LSB.
        // Per FeatureBits encoding (big-endian within words), bit 22 at index 22
        // sits in word 0, bit position 4 - ((22 - 0) % 5)... easier to just try
        // a known-bad encoding: 5 words [1, 0, 0, 0, 0] sets bit 22.
        $featureWords = [1, 0, 0, 0, 0];

        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            ...self::tagWords(5, $featureWords),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('unknown feature');

        Decoder::decode($invoice);
    }

    public function testRouteHintWithLeftoverBytesRejected(): void
    {
        // Construct a route hint whose decoded byte length is 51+5=56 (one full
        // hop + 5 stray bytes). Spec says route hint must be a positive
        // multiple of 51 bytes.
        $oneHop = array_fill(0, 51, 0);
        $stray = array_fill(0, 5, 0);
        $invoice = $this->craftFromTagWords([
            ...self::tagWords(1, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                )),
            ]),
            ...self::tagWords(16, [
                ...Bech32::eightToFive(Bech32::hexToBytes(
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                )),
            ]),
            ...self::tagWords(13, Bech32::eightToFive(Bech32::stringToBytes('test'))),
            ...self::tagWords(3, Bech32::eightToFive([...$oneHop, ...$stray])),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('multiple of 51');

        Decoder::decode($invoice);
    }

    public function testBothDescriptionAndHashRejected(): void
    {
        $invoice = $this->craftInvoice([
            Tag::paymentHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
            Tag::paymentSecret('1111111111111111111111111111111111111111111111111111111111111111'),
            Tag::description('cannot have both'),
            Tag::descriptionHash('3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1'),
        ]);

        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('both');

        Decoder::decode($invoice);
    }

    /**
     * Per BOLT 11, readers MUST check the signature is valid: when no `n` tag
     * is provided, public-key recovery MUST succeed. A signature that cannot
     * be recovered must cause decode to fail, not return a partial invoice.
     */
    public function testFailedSignatureRecoveryThrows(): void
    {
        // Zero out all 103 signature words (keep the recovery flag).
        // r=0 makes ECDSA recovery fail (inverseMod(0, n) is undefined).
        $original = 'lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql';
        $decoded = Bech32::decode($original);
        $words = $decoded['data'];
        $count = count($words);
        for ($i = $count - 104; $i < $count - 1; $i++) {
            $words[$i] = 0;
        }
        $tampered = Bech32::encode($decoded['hrp'], array_values($words));

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('recover');

        Decoder::decode($tampered);
    }
}
