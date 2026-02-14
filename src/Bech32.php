<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

use Nova\Bitcoin\Exception\InvalidChecksumException;
use Nova\Bitcoin\Exception\InvalidInvoiceException;

/**
 * Bech32 encoding/decoding for BOLT 11 payment requests.
 *
 * Based on BIP-173. BOLT 11 reuses bech32 encoding but may exceed
 * the 90-character limit.
 */
final class Bech32
{
    private const string CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    /** @var list<int> */
    private const array GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    /**
     * Decode a bech32 string into HRP and 5-bit data words (without checksum).
     *
     * @return array{hrp: string, data: list<int>}
     * @throws InvalidInvoiceException
     * @throws InvalidChecksumException
     */
    public static function decode(string $str): array
    {
        $input = strtolower($str);
        $sepIndex = strrpos($input, '1');

        if ($sepIndex === false) {
            throw new InvalidInvoiceException('No separator character found');
        }
        if ($sepIndex === 0) {
            throw new InvalidInvoiceException('Empty HRP');
        }
        if ($sepIndex + 7 > strlen($input)) {
            throw new InvalidChecksumException('Checksum too short');
        }

        $hrp = substr($input, 0, $sepIndex);
        $dataStr = substr($input, $sepIndex + 1);
        $data = [];

        for ($i = 0; $i < strlen($dataStr); $i++) {
            $idx = strpos(self::CHARSET, $dataStr[$i]);
            if ($idx === false) {
                throw new InvalidInvoiceException(
                    sprintf('Invalid bech32 character: %s', $dataStr[$i]),
                );
            }
            $data[] = $idx;
        }

        if (!self::verifyChecksum($hrp, $data)) {
            throw new InvalidChecksumException('Invalid checksum');
        }

        return [
            'hrp' => $hrp,
            'data' => array_slice($data, 0, -6),
        ];
    }

    /**
     * Encode HRP + 5-bit data words to a bech32 string.
     *
     * @param list<int> $data
     */
    public static function encode(string $hrp, array $data): string
    {
        $checksum = self::createChecksum($hrp, $data);
        $result = $hrp . '1';

        foreach ([...$data, ...$checksum] as $v) {
            $result .= self::CHARSET[$v];
        }

        return $result;
    }

    /**
     * Convert 5-bit words to bytes with padding (for signing data).
     *
     * @param list<int> $words
     * @return list<int>
     */
    public static function fiveToEight(array $words, bool $pad = true): array
    {
        $acc = 0;
        $bits = 0;
        $out = [];

        foreach ($words as $w) {
            $acc = ($acc << 5) | $w;
            $bits += 5;
            while ($bits >= 8) {
                $bits -= 8;
                $out[] = ($acc >> $bits) & 0xff;
            }
        }

        if ($pad && $bits > 0) {
            $out[] = ($acc << (8 - $bits)) & 0xff;
        }

        return $out;
    }

    /**
     * Convert 5-bit words to bytes, trimming trailing padding bits.
     *
     * @param list<int> $words
     * @return list<int>
     */
    public static function fiveToEightTrim(array $words): array
    {
        $acc = 0;
        $bits = 0;
        $out = [];

        foreach ($words as $w) {
            $acc = ($acc << 5) | $w;
            $bits += 5;
            while ($bits >= 8) {
                $bits -= 8;
                $out[] = ($acc >> $bits) & 0xff;
            }
        }

        return $out;
    }

    /**
     * Convert bytes to 5-bit words (with zero-padding to fill last word).
     *
     * @param list<int> $bytes
     * @return list<int>
     */
    public static function eightToFive(array $bytes): array
    {
        $acc = 0;
        $bits = 0;
        $out = [];

        foreach ($bytes as $b) {
            $acc = ($acc << 8) | $b;
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out[] = ($acc >> $bits) & 0x1f;
            }
        }

        if ($bits > 0) {
            $out[] = ($acc << (5 - $bits)) & 0x1f;
        }

        return $out;
    }

    /**
     * Convert a hex string to a byte array.
     *
     * @return list<int>
     */
    public static function hexToBytes(string $hex): array
    {
        if (strlen($hex) % 2 !== 0) {
            throw new InvalidInvoiceException('Hex string must have even length');
        }

        $bytes = [];
        for ($i = 0; $i < strlen($hex); $i += 2) {
            $bytes[] = (int) hexdec(substr($hex, $i, 2));
        }

        return $bytes;
    }

    /**
     * Convert a byte array to a hex string.
     *
     * @param list<int>|array<int, int> $bytes
     */
    public static function bytesToHex(array $bytes): string
    {
        $hex = '';
        foreach ($bytes as $b) {
            $hex .= str_pad(dechex($b), 2, '0', STR_PAD_LEFT);
        }

        return $hex;
    }

    /**
     * Convert big-endian bytes to integer.
     *
     * @param list<int> $bytes
     */
    public static function bytesToInt(array $bytes): int
    {
        $result = 0;
        foreach ($bytes as $byte) {
            $result = $result * 256 + $byte;
        }

        return $result;
    }

    /**
     * Convert 5-bit words to integer (big-endian).
     *
     * @param list<int> $words
     */
    public static function wordsToInt(array $words): int
    {
        $result = 0;
        foreach ($words as $word) {
            $result = $result * 32 + $word;
        }

        return $result;
    }

    /**
     * Convert integer to 5-bit words (big-endian) with fixed length.
     *
     * @return list<int>
     */
    public static function intToWords(int $num, int $length): array
    {
        $words = [];
        for ($i = 0; $i < $length; $i++) {
            array_unshift($words, $num & 31);
            $num >>= 5;
        }

        return $words;
    }

    /**
     * Convert integer to minimum number of 5-bit words.
     *
     * @return list<int>
     */
    public static function intToMinWords(int $num): array
    {
        if ($num === 0) {
            return [0];
        }

        $words = [];
        $n = $num;
        while ($n > 0) {
            array_unshift($words, $n & 0x1f);
            $n >>= 5;
        }

        return $words;
    }

    /**
     * Convert a UTF-8 string to a byte array.
     *
     * @return list<int>
     */
    public static function stringToBytes(string $str): array
    {
        $bytes = [];
        for ($i = 0; $i < strlen($str); $i++) {
            $bytes[] = ord($str[$i]);
        }

        return $bytes;
    }

    /**
     * Convert a byte array to a UTF-8 string.
     *
     * @param list<int> $bytes
     */
    public static function bytesToString(array $bytes): string
    {
        $str = '';
        foreach ($bytes as $b) {
            $str .= chr($b);
        }

        return $str;
    }

    /**
     * @param list<int> $values
     */
    private static function polymod(array $values): int
    {
        $chk = 1;
        foreach ($values as $v) {
            $top = $chk >> 25;
            $chk = (($chk & 0x1ffffff) << 5) ^ $v;
            for ($i = 0; $i < 5; $i++) {
                if (($top >> $i) & 1) {
                    $chk ^= self::GENERATOR[$i];
                }
            }
        }

        return $chk;
    }

    /**
     * @return list<int>
     */
    private static function hrpExpand(string $hrp): array
    {
        $r = [];
        for ($i = 0; $i < strlen($hrp); $i++) {
            $r[] = ord($hrp[$i]) >> 5;
        }
        $r[] = 0;
        for ($i = 0; $i < strlen($hrp); $i++) {
            $r[] = ord($hrp[$i]) & 31;
        }

        return $r;
    }

    /**
     * @param list<int> $data
     */
    private static function verifyChecksum(string $hrp, array $data): bool
    {
        return self::polymod([...self::hrpExpand($hrp), ...$data]) === 1;
    }

    /**
     * @param list<int> $data
     * @return list<int>
     */
    private static function createChecksum(string $hrp, array $data): array
    {
        $values = [...self::hrpExpand($hrp), ...$data, 0, 0, 0, 0, 0, 0];
        $mod = self::polymod($values) ^ 1;

        $result = [];
        for ($i = 0; $i < 6; $i++) {
            $result[] = ($mod >> (5 * (5 - $i))) & 31;
        }

        return $result;
    }
}
