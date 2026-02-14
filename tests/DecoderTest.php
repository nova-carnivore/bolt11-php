<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Tests;

use Nova\Bitcoin\Decoder;
use Nova\Bitcoin\Exception\InvalidChecksumException;
use Nova\Bitcoin\Exception\InvalidInvoiceException;
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
}
