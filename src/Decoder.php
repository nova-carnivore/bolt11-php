<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use Mdanter\Ecc\EccFactory;
use Nova\Bitcoin\Bolt11\Exception\InvalidInvoiceException;
use Nova\Bitcoin\Bolt11\Exception\InvalidSignatureException;

/**
 * BOLT 11 payment request decoder.
 *
 * Spec: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
 */
final class Decoder
{
    /** @var array<int, string> Tag type code → tag name */
    private const array TAG_CODE_TO_NAME = [
        1 => 'payment_hash',
        16 => 'payment_secret',
        13 => 'description',
        27 => 'metadata',
        19 => 'payee',
        23 => 'purpose_commit_hash',
        6 => 'expire_time',
        24 => 'min_final_cltv_expiry',
        9 => 'fallback_address',
        3 => 'route_hint',
        5 => 'feature_bits',
    ];

    /**
     * Decode a BOLT 11 payment request string into an Invoice object.
     *
     * @throws InvalidInvoiceException
     * @throws Exception\InvalidChecksumException
     * @throws InvalidSignatureException
     */
    public static function decode(string $paymentRequest): Invoice
    {
        $decoded = Bech32::decode($paymentRequest);
        $hrp = $decoded['hrp'];
        $data = $decoded['data'];

        // Parse HRP
        $hrpParsed = Network::fromHrp($hrp);
        $network = $hrpParsed['network'];
        $amountStr = $hrpParsed['amount'];
        $amount = $amountStr !== '' ? Amount::fromHrp($amountStr) : null;

        // Timestamp: first 7 × 5-bit words
        if (count($data) < 7 + 104) {
            throw new InvalidInvoiceException('Payment request too short');
        }

        $timestamp = Bech32::wordsToInt(array_slice($data, 0, 7));

        // Signature: last 104 words (65 bytes = 64 R‖S + 1 recovery)
        $signatureStart = count($data) - 104;
        $tagWords = array_slice($data, 7, $signatureStart - 7);
        $signatureWords = array_slice($data, $signatureStart);

        // Parse tags
        $tags = self::parseTags($tagWords);

        // Extract signature
        $sigBytes = Bech32::fiveToEightTrim(array_slice($signatureWords, 0, 103));
        $recoveryFlag = $signatureWords[103];
        $signature = Bech32::bytesToHex($sigBytes);

        // Signing data: hrp UTF-8 || data-words→bytes
        $preSignatureWords = array_slice($data, 0, $signatureStart);
        $hrpBytes = Bech32::stringToBytes($hrp);
        $dataBytes = Bech32::fiveToEight($preSignatureWords, true);
        $signingData = [...$hrpBytes, ...$dataBytes];
        $sigHash = self::sha256Bytes($signingData);

        // Recover / verify payee node key
        $payeeNodeKey = self::resolvePayeeKey($sigHash, $sigBytes, $recoveryFlag, $tags);

        // Build expiry
        $expiryTag = null;
        foreach ($tags as $tag) {
            if ($tag->tagName === 'expire_time') {
                $expiryTag = $tag->data;
                break;
            }
        }
        $expireTime = is_int($expiryTag) ? $expiryTag : 3600;
        $timeExpireDate = $timestamp + $expireTime;

        return new Invoice(
            complete: true,
            prefix: $hrp,
            wordsTemp: '',
            network: $network,
            satoshis: $amount?->satoshis(),
            millisatoshis: $amount?->millisatoshis,
            timestamp: $timestamp,
            timestampString: gmdate('Y-m-d\TH:i:s\Z', $timestamp),
            timeExpireDate: $timeExpireDate,
            timeExpireDateString: gmdate('Y-m-d\TH:i:s\Z', $timeExpireDate),
            payeeNodeKey: $payeeNodeKey,
            signature: $signature,
            recoveryFlag: $recoveryFlag,
            tags: $tags,
            paymentRequest: $paymentRequest,
        );
    }

    /**
     * Parse tags from 5-bit words.
     *
     * @param list<int> $words
     * @return list<Tag>
     */
    private static function parseTags(array $words): array
    {
        $tags = [];
        $pos = 0;
        $wordCount = count($words);

        while ($pos < $wordCount) {
            if ($pos + 3 > $wordCount) {
                break; // Malformed trailing data
            }

            $type = $words[$pos];
            $dataLen = $words[$pos + 1] * 32 + $words[$pos + 2];
            $tagEnd = $pos + 3 + $dataLen;

            if ($tagEnd > $wordCount) {
                throw new InvalidInvoiceException('Tag data extends beyond data part');
            }

            $tagWords = array_slice($words, $pos + 3, $dataLen);
            $name = self::TAG_CODE_TO_NAME[$type] ?? null;

            if ($name !== null) {
                $parsed = self::parseTagData($name, $tagWords, $dataLen);
                if ($parsed !== null) {
                    $tags[] = $parsed;
                }
            }
            // Unknown tags are silently skipped (spec: extensibility)

            $pos = $tagEnd;
        }

        return $tags;
    }

    /**
     * @param list<int> $words
     */
    private static function parseTagData(string $name, array $words, int $dataLen): ?Tag
    {
        return match ($name) {
            'payment_hash', 'payment_secret', 'purpose_commit_hash' => self::parseHashTag($name, $words, $dataLen),
            'payee' => self::parsePayeeTag($words, $dataLen),
            'description' => new Tag('description', Bech32::bytesToString(Bech32::fiveToEightTrim($words))),
            'metadata' => new Tag('metadata', Bech32::bytesToHex(Bech32::fiveToEightTrim($words))),
            'expire_time' => new Tag('expire_time', Bech32::wordsToInt($words)),
            'min_final_cltv_expiry' => new Tag('min_final_cltv_expiry', Bech32::wordsToInt($words)),
            'fallback_address' => new Tag('fallback_address', self::parseFallbackAddress($words)),
            'route_hint' => new Tag('route_hint', self::parseRouteHint($words)),
            'feature_bits' => new Tag('feature_bits', FeatureBits::fromWords($words)),
            default => null,
        };
    }

    /**
     * @param list<int> $words
     */
    private static function parseHashTag(string $name, array $words, int $dataLen): ?Tag
    {
        if ($dataLen !== 52) {
            return null;
        }

        return new Tag($name, Bech32::bytesToHex(Bech32::fiveToEightTrim($words)));
    }

    /**
     * @param list<int> $words
     */
    private static function parsePayeeTag(array $words, int $dataLen): ?Tag
    {
        if ($dataLen !== 53) {
            return null;
        }

        return new Tag('payee', Bech32::bytesToHex(Bech32::fiveToEightTrim($words)));
    }

    /**
     * @param list<int> $words
     */
    private static function parseFallbackAddress(array $words): FallbackAddress
    {
        if ($words === []) {
            throw new InvalidInvoiceException('Empty fallback address');
        }

        $version = $words[0];
        $addrBytes = Bech32::fiveToEightTrim(array_slice($words, 1));

        return new FallbackAddress(
            code: $version,
            address: '',
            addressHash: Bech32::bytesToHex($addrBytes),
        );
    }

    /**
     * @param list<int> $words
     * @return list<RouteHint>
     */
    private static function parseRouteHint(array $words): array
    {
        $bytes = Bech32::fiveToEightTrim($words);
        $routes = [];
        $hop = 51; // 33+8+4+4+2

        for ($i = 0; $i + $hop <= count($bytes); $i += $hop) {
            $routes[] = new RouteHint(
                pubkey: Bech32::bytesToHex(array_slice($bytes, $i, 33)),
                shortChannelId: Bech32::bytesToHex(array_slice($bytes, $i + 33, 8)),
                feeBaseMsat: Bech32::bytesToInt(array_slice($bytes, $i + 41, 4)),
                feeProportionalMillionths: Bech32::bytesToInt(array_slice($bytes, $i + 45, 4)),
                cltvExpiryDelta: Bech32::bytesToInt(array_slice($bytes, $i + 49, 2)),
            );
        }

        return $routes;
    }

    /**
     * Recover or verify the payee's public key from the signature.
     *
     * @param list<int> $sigHash SHA-256 hash bytes
     * @param list<int> $sigBytes 64-byte compact signature
     * @param int $recoveryFlag Recovery flag (0-3)
     * @param list<Tag> $tags Parsed tags
     */
    private static function resolvePayeeKey(array $sigHash, array $sigBytes, int $recoveryFlag, array $tags): ?string
    {
        // Check for explicit payee tag first
        foreach ($tags as $tag) {
            if ($tag->tagName === 'payee' && is_string($tag->data)) {
                return $tag->data;
            }
        }

        return self::recoverPublicKey($sigHash, $sigBytes, $recoveryFlag);
    }

    /**
     * Recover compressed public key from compact signature using paragonie/ecc.
     *
     * Handles both low-S and high-S signatures.
     *
     * @param list<int> $msgHash 32-byte hash
     * @param list<int> $signature 64-byte R||S
     * @param int $recoveryFlag Recovery id (0-3)
     */
    private static function recoverPublicKey(array $msgHash, array $signature, int $recoveryFlag): ?string
    {
        $generator = EccFactory::getSecgCurves()->generator256k1();
        $adapter = EccFactory::getAdapter();

        $hashHex = Bech32::bytesToHex($msgHash);
        $rHex = Bech32::bytesToHex(array_slice($signature, 0, 32));
        $sHex = Bech32::bytesToHex(array_slice($signature, 32, 32));

        $hashGmp = gmp_init($hashHex, 16);
        $r = gmp_init($rHex, 16);
        $s = gmp_init($sHex, 16);

        // secp256k1 curve order
        $n = $generator->getOrder();
        $halfN = gmp_div_q($n, 2);

        $isHighS = gmp_cmp($s, $halfN) > 0;

        if (!$isHighS) {
            // Standard low-S: use flag as-is
            try {
                return Secp256k1Recovery::recoverPublicKey($generator, $adapter, $hashGmp, $r, $s, $recoveryFlag);
            } catch (\Throwable) {
                // Fall through
            }
        } else {
            // High-S: try with inverted flag first
            try {
                return Secp256k1Recovery::recoverPublicKey($generator, $adapter, $hashGmp, $r, $s, $recoveryFlag ^ 1);
            } catch (\Throwable) {
                // Fall through
            }

            // Try with normalized S
            try {
                $sNorm = gmp_sub($n, $s);

                return Secp256k1Recovery::recoverPublicKey($generator, $adapter, $hashGmp, $r, $sNorm, $recoveryFlag);
            } catch (\Throwable) {
                // Fall through
            }
        }

        return null;
    }

    /**
     * SHA-256 hash of a byte array.
     *
     * @param list<int> $bytes
     * @return list<int>
     */
    private static function sha256Bytes(array $bytes): array
    {
        $binary = '';
        foreach ($bytes as $b) {
            $binary .= chr($b);
        }

        $hash = hash('sha256', $binary, true);
        $result = [];
        for ($i = 0; $i < strlen($hash); $i++) {
            $result[] = ord($hash[$i]);
        }

        return $result;
    }
}
