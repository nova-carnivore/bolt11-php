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
        self::validateRequiredTagPresence($tags);
        self::validateFeatureBits($tags);

        // Extract signature. The 103 sig-data words encode 64 bytes (512 bits)
        // with 3 trailing padding bits in the lowest 3 bits of word 102; per
        // canonical encoding those MUST be zero.
        if (($signatureWords[102] & 0x07) !== 0) {
            throw new InvalidSignatureException(
                'Signature has non-zero padding bits in word 102',
            );
        }
        $sigBytes = Bech32::fiveToEightTrim(array_slice($signatureWords, 0, 103));
        $recoveryFlag = $signatureWords[103];
        if ($recoveryFlag > 3) {
            throw new InvalidSignatureException(
                sprintf('Invalid recovery flag: %d (must be 0–3)', $recoveryFlag),
            );
        }
        $signature = Bech32::bytesToHex($sigBytes);

        // Signing data: hrp UTF-8 || data-words→bytes
        $preSignatureWords = array_slice($data, 0, $signatureStart);
        $hrpBytes = Bech32::stringToBytes($hrp);
        $dataBytes = Bech32::fiveToEight($preSignatureWords, true);
        $signingData = [...$hrpBytes, ...$dataBytes];
        $sigHash = self::sha256Bytes($signingData);

        // Recover / verify payee node key. Per BOLT 11, readers MUST check the
        // signature is valid: when there is no `n` tag, public-key recovery
        // MUST succeed. A malformed/tampered signature must fail decode, not
        // produce a partially-decoded invoice.
        $payeeNodeKey = self::resolvePayeeKey($sigHash, $sigBytes, $recoveryFlag, $tags);
        if ($payeeNodeKey === null) {
            throw new InvalidSignatureException('Could not recover payee public key from signature');
        }

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
     * Spec-required reader checks on the parsed tag set:
     *
     *   - At least one valid `p` (payment_hash) tag MUST be present. If the
     *     invoice contained only wrong-length `p` candidates, parseTags will
     *     have skipped them all and we fail here. (Same applies to `s`, `n`.)
     *   - A reader MUST fail the payment if a valid `s` tag is not provided.
     *   - A reader MUST fail the payment if neither `d` nor `h` is present,
     *     or if both are present.
     *
     * @param list<Tag> $tags
     */
    private static function validateRequiredTagPresence(array $tags): void
    {
        $hasPaymentHash = false;
        $hasPaymentSecret = false;
        $hasDescription = false;
        $hasDescriptionHash = false;
        foreach ($tags as $tag) {
            match ($tag->tagName) {
                'payment_hash' => $hasPaymentHash = true,
                'payment_secret' => $hasPaymentSecret = true,
                'description' => $hasDescription = true,
                'purpose_commit_hash' => $hasDescriptionHash = true,
                default => null,
            };
        }

        if (!$hasPaymentHash) {
            throw new InvalidInvoiceException('Invoice must contain a payment_hash (p) tag');
        }
        if (!$hasPaymentSecret) {
            throw new InvalidInvoiceException('Invoice must contain a payment_secret (s) tag');
        }
        if (!$hasDescription && !$hasDescriptionHash) {
            throw new InvalidInvoiceException(
                'Invoice must contain a description (d) or description_hash (h) tag',
            );
        }
        if ($hasDescription && $hasDescriptionHash) {
            throw new InvalidInvoiceException(
                'Invoice must not contain both description (d) and description_hash (h) tags',
            );
        }
    }

    /**
     * Spec: a reader MUST fail the payment if the `9` field contains unknown
     * even feature bits that are non-zero. Unknown odd bits MUST be ignored.
     * Additionally, BOLT 9 says "if the feature vector does not set all
     * known, transitive feature dependencies: MUST NOT attempt the payment."
     *
     * "Unknown" is relative to this implementation's known-feature map (see
     * FeatureBits::KNOWN_FEATURES). Bits not in that map land in
     * `extraBits.bits`; if any of them is even, decode fails here.
     *
     * @param list<Tag> $tags
     */
    private static function validateFeatureBits(array $tags): void
    {
        foreach ($tags as $tag) {
            if (!($tag->tagName === 'feature_bits' && $tag->data instanceof FeatureBits)) {
                continue;
            }
            $fb = $tag->data;

            if ($fb->extraBits !== null && $fb->extraBits['has_required']) {
                throw new InvalidInvoiceException(
                    'Invoice requires unknown feature bits (unknown even bit set in `9` field)',
                );
            }

            self::validateFeatureBitDependencies($fb);
        }
    }

    /**
     * Enforce the BOLT 9 transitive-dependency chain that's relevant for
     * invoice context:
     *   basic_mpp (16/17) → payment_secret (14/15) → var_onion_optin (8/9)
     *
     * If a feature is set (required OR supported), all its dependencies must
     * be set too (in either flavour). The spec phrases this as a payer-side
     * rule, but the only sensible point to enforce it for an invoice library
     * is at decode.
     */
    private static function validateFeatureBitDependencies(FeatureBits $fb): void
    {
        $isSet = static fn (?array $f): bool => $f !== null && ($f['required'] || $f['supported']);

        if ($isSet($fb->paymentSecret) && !$isSet($fb->varOnionOptin)) {
            throw new InvalidInvoiceException(
                'BOLT 9 dependency violation: payment_secret requires var_onion_optin',
            );
        }
        if ($isSet($fb->basicMpp) && !$isSet($fb->paymentSecret)) {
            throw new InvalidInvoiceException(
                'BOLT 9 dependency violation: basic_mpp requires payment_secret',
            );
        }
    }

    /**
     * Spec: a reader SHOULD treat `c`, `x`, and `9` fields as invalid if they
     * begin with zero field elements (non-minimal encoding). This catches
     * malicious or malformed writers; honest writers always emit the shortest
     * representation. Single-zero `[0]` is canonical for the value 0 and is
     * NOT flagged.
     *
     * @param list<int> $words
     */
    private static function ensureMinimalEncoding(string $name, array $words): void
    {
        if (count($words) > 1 && $words[0] === 0) {
            throw new InvalidInvoiceException(
                sprintf('%s tag has non-minimal encoding (leading zero word)', $name),
            );
        }
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
        $wordCount = count($words);
        $pos = 0;

        while ($pos + 3 <= $wordCount) {
            \assert($pos >= 0);
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
            'description' => self::parseDescriptionTag($words),
            'metadata' => new Tag('metadata', Bech32::bytesToHex(Bech32::fiveToEightTrim($words))),
            'expire_time', 'min_final_cltv_expiry' => self::parseIntTag($name, $words),
            'fallback_address' => self::parseFallbackTag($words),
            'route_hint' => new Tag('route_hint', self::parseRouteHint($words)),
            'feature_bits' => self::parseFeatureBitsTag($words),
            default => null,
        };
    }

    /**
     * Decode the `d` (description) tag and validate UTF-8.
     *
     * @param list<int> $words
     */
    private static function parseDescriptionTag(array $words): Tag
    {
        $str = Bech32::bytesToString(Bech32::fiveToEightTrim($words));
        if ($str !== '' && !mb_check_encoding($str, 'UTF-8')) {
            throw new InvalidInvoiceException('description (d) tag is not valid UTF-8');
        }

        return new Tag('description', $str);
    }

    /**
     * Decode an integer-valued variable-length tag (`x`, `c`), rejecting
     * non-minimal encodings.
     *
     * @param list<int> $words
     */
    private static function parseIntTag(string $name, array $words): Tag
    {
        self::ensureMinimalEncoding($name, $words);

        return new Tag($name, Bech32::wordsToInt($words));
    }

    /**
     * Decode the `9` (feature_bits) tag, rejecting non-minimal encodings.
     *
     * @param list<int> $words
     */
    private static function parseFeatureBitsTag(array $words): Tag
    {
        self::ensureMinimalEncoding('feature_bits', $words);

        return new Tag('feature_bits', FeatureBits::fromWords($words));
    }

    /**
     * Per spec test vector 12, a `p`/`h`/`s` tag with the wrong data_length is
     * silently skipped (not a hard failure). The required-presence check
     * after parseTags catches the case where every candidate is wrong-length.
     *
     * 52 5-bit words encode 260 bits; the payload is 256 bits (32 bytes), so
     * the lower 4 bits of the last word are padding and MUST be zero per
     * canonical encoding.
     *
     * @param list<int> $words
     */
    private static function parseHashTag(string $name, array $words, int $dataLen): ?Tag
    {
        if ($dataLen !== 52) {
            return null;
        }
        if (($words[51] & 0x0F) !== 0) {
            throw new InvalidInvoiceException(
                sprintf('%s tag has non-zero padding bits', $name),
            );
        }

        return new Tag($name, Bech32::bytesToHex(Bech32::fiveToEightTrim($words)));
    }

    /**
     * Same wrong-length-skip rule as parseHashTag, but for the 53-word `n` tag.
     * 53 5-bit words encode 265 bits; the payload is 264 bits (33 bytes), so
     * the lowest bit of the last word is padding and MUST be zero.
     *
     * @param list<int> $words
     */
    private static function parsePayeeTag(array $words, int $dataLen): ?Tag
    {
        if ($dataLen !== 53) {
            return null;
        }
        if (($words[52] & 0x01) !== 0) {
            throw new InvalidInvoiceException('payee node key tag has non-zero padding bit');
        }

        return new Tag('payee', Bech32::bytesToHex(Bech32::fiveToEightTrim($words)));
    }

    /**
     * @param list<int> $words
     */
    private static function parseFallbackTag(array $words): ?Tag
    {
        if ($words === []) {
            return null;
        }

        $version = $words[0];
        // Per spec, valid version codes are 0–16 (segwit) plus 17 (P2PKH) and 18 (P2SH).
        // Readers MUST skip `f` fields with any other version.
        if ($version > 18) {
            return null;
        }

        $addrBytes = Bech32::fiveToEightTrim(array_slice($words, 1));
        $len = count($addrBytes);

        // Validate the witness/script length for known address types.
        // Skip (return null) on length mismatch — same lenience as wrong-length
        // p/h/s/n; the address is malformed but the rest of the invoice is
        // still parseable.
        $valid = match (true) {
            $version === 17 || $version === 18 => $len === 20,        // P2PKH / P2SH
            $version === 0 => $len === 20 || $len === 32,             // P2WPKH or P2WSH
            $version === 1 => $len === 32,                            // P2TR
            default => $len >= 2 && $len <= 40,                       // BIP-141 segwit v2-16
        };
        if (!$valid) {
            return null;
        }

        return new Tag('fallback_address', new FallbackAddress(
            code: $version,
            addressHash: Bech32::bytesToHex($addrBytes),
        ));
    }

    /**
     * @param list<int> $words
     * @return list<RouteHint>
     */
    private static function parseRouteHint(array $words): array
    {
        $bytes = Bech32::fiveToEightTrim($words);
        $byteCount = count($bytes);
        $hop = 51; // 33 (pubkey) + 8 (scid) + 4 (fee_base) + 4 (fee_prop) + 2 (cltv)

        // Per spec, an `r` field contains "one or more entries"; each entry is
        // exactly 51 bytes. Reject empty hint vectors and any trailing
        // partial-hop bytes instead of silently truncating.
        if ($byteCount === 0 || $byteCount % $hop !== 0) {
            throw new InvalidInvoiceException(
                sprintf('Route hint must be a positive multiple of %d bytes, got %d', $hop, $byteCount),
            );
        }

        $routes = [];
        for ($i = 0; $i < $byteCount; $i += $hop) {
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
     * Resolve the payee's public key from the signature, honouring BOLT 11's
     * branching reader requirements:
     *
     *   - if a valid `n` tag is provided: the tag MUST be used to validate the
     *     signature, AND the signature MUST be low-S. (We implement the
     *     "validate" step as recover-and-compare, which is functionally
     *     equivalent to ECDSA verification when the signature is low-S.)
     *   - otherwise: perform ECDSA public-key recovery, accepting both
     *     high-S and low-S signatures.
     *
     * Spec: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
     *
     * @param list<int> $sigHash SHA-256 hash bytes
     * @param list<int> $sigBytes 64-byte compact signature
     * @param int $recoveryFlag Recovery flag (0-3)
     * @param list<Tag> $tags Parsed tags
     */
    private static function resolvePayeeKey(array $sigHash, array $sigBytes, int $recoveryFlag, array $tags): ?string
    {
        $explicit = null;
        foreach ($tags as $tag) {
            if ($tag->tagName === 'payee' && is_string($tag->data)) {
                $explicit = $tag->data;
                break;
            }
        }

        if ($explicit !== null) {
            if (self::isHighS($sigBytes)) {
                throw new InvalidSignatureException(
                    'high-S signature is not valid when payee node key (n) tag is present',
                );
            }

            $recovered = self::recoverPublicKey($sigHash, $sigBytes, $recoveryFlag);
            if ($recovered === null || strtolower($recovered) !== strtolower($explicit)) {
                throw new InvalidSignatureException(
                    'payee node key tag does not match the key recovered from the signature',
                );
            }

            return $explicit;
        }

        return self::recoverPublicKey($sigHash, $sigBytes, $recoveryFlag);
    }

    /**
     * Detect whether a compact ECDSA signature uses a high-S value (S > n/2).
     *
     * @param list<int> $sigBytes 64-byte compact R||S signature
     */
    private static function isHighS(array $sigBytes): bool
    {
        $sHex = Bech32::bytesToHex(array_slice($sigBytes, 32, 32));
        $s = gmp_init($sHex, 16);
        $halfN = gmp_div_q(EccFactory::getSecgCurves()->generator256k1()->getOrder(), 2);

        return gmp_cmp($s, $halfN) > 0;
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
        $hash = hash('sha256', pack('C*', ...$bytes), true);

        return array_map(ord(...), str_split($hash));
    }
}
