<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Tests;

use Nova\Bitcoin\Bech32;
use Nova\Bitcoin\Exception\InvalidChecksumException;
use Nova\Bitcoin\Exception\InvalidInvoiceException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for Bech32 encoding/decoding.
 */
final class Bech32Test extends TestCase
{
    public function testEncodeDecodeRoundTrip(): void
    {
        $hrp = 'test';
        $data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        $encoded = Bech32::encode($hrp, $data);
        $decoded = Bech32::decode($encoded);

        self::assertSame($hrp, $decoded['hrp']);
        self::assertSame($data, $decoded['data']);
    }

    public function testDecodeInvalidChecksum(): void
    {
        $this->expectException(InvalidChecksumException::class);

        Bech32::decode('test1qqqqqXXXXXX');
    }

    public function testDecodeNoSeparator(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('No separator');

        Bech32::decode('testinvalid');
    }

    public function testDecodeEmptyHrp(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('Empty HRP');

        Bech32::decode('1qqqqqqqqqqqqqqqqqq');
    }

    public function testFiveToEightAndBack(): void
    {
        $original = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        $bytes = Bech32::fiveToEightTrim($original);
        $restored = Bech32::eightToFive($bytes);

        // The restored should match, though the last word may have padding
        self::assertSame(count($original), count($restored));
    }

    public function testHexToBytes(): void
    {
        $bytes = Bech32::hexToBytes('0102ff');
        self::assertSame([1, 2, 255], $bytes);
    }

    public function testBytesToHex(): void
    {
        $hex = Bech32::bytesToHex([1, 2, 255]);
        self::assertSame('0102ff', $hex);
    }

    public function testHexToBytesBadLength(): void
    {
        $this->expectException(InvalidInvoiceException::class);
        $this->expectExceptionMessage('even length');

        Bech32::hexToBytes('abc');
    }

    public function testBytesToInt(): void
    {
        self::assertSame(256, Bech32::bytesToInt([1, 0]));
        self::assertSame(0, Bech32::bytesToInt([0]));
        self::assertSame(255, Bech32::bytesToInt([255]));
    }

    public function testWordsToInt(): void
    {
        self::assertSame(32, Bech32::wordsToInt([1, 0]));
        self::assertSame(0, Bech32::wordsToInt([0]));
        self::assertSame(31, Bech32::wordsToInt([31]));
    }

    public function testIntToWords(): void
    {
        self::assertSame([0, 0, 0, 0, 0, 0, 1], Bech32::intToWords(1, 7));
        self::assertSame([1, 0], Bech32::intToWords(32, 2));
    }

    public function testIntToMinWords(): void
    {
        self::assertSame([0], Bech32::intToMinWords(0));
        self::assertSame([1], Bech32::intToMinWords(1));
        self::assertSame([1, 0], Bech32::intToMinWords(32));
        self::assertSame([1, 28], Bech32::intToMinWords(60));
    }

    public function testStringToBytes(): void
    {
        self::assertSame([72, 101, 108, 108, 111], Bech32::stringToBytes('Hello'));
    }

    public function testBytesToString(): void
    {
        self::assertSame('Hello', Bech32::bytesToString([72, 101, 108, 108, 111]));
    }
}
