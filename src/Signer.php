<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use GMP;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\Signer as EccSigner;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Nova\Bitcoin\Bolt11\Exception\InvalidSignatureException;

/**
 * Signs BOLT 11 payment requests using secp256k1.
 */
final class Signer
{
    /**
     * Sign an unsigned invoice with a private key.
     *
     * @param Invoice $invoice The unsigned invoice (from Encoder::encode())
     * @param string $privateKeyHex The private key as a hex string
     * @return Invoice A completed, signed invoice with paymentRequest
     * @throws InvalidSignatureException
     */
    public static function sign(Invoice $invoice, string $privateKeyHex): Invoice
    {
        $generator = EccFactory::getSecgCurves()->generator256k1();
        $adapter = EccFactory::getAdapter();

        $network = $invoice->network ?? Network::Bitcoin;
        $hrp = Encoder::buildHRP($network, $invoice->satoshis, $invoice->millisatoshis);
        $timestampWords = Bech32::intToWords($invoice->timestamp, 7);
        $tagWords = Encoder::encodeAllTags($invoice->tags);
        $dataWords = [...$timestampWords, ...$tagWords];

        // Signing data = hrp (UTF-8) || data-words→bytes (with 0-pad to byte boundary)
        $hrpBytes = Bech32::stringToBytes($hrp);
        $dataBytes = Bech32::fiveToEight($dataWords, true);
        $signingData = [...$hrpBytes, ...$dataBytes];

        $binary = '';
        foreach ($signingData as $b) {
            $binary .= chr($b);
        }
        $sigHash = hash('sha256', $binary, true);

        // Create private key
        $privateKeyGmp = gmp_init($privateKeyHex, 16);
        $key = $generator->getPrivateKeyFrom($privateKeyGmp);

        // Create hash as GMP for signing
        $hashGmp = gmp_init(bin2hex($sigHash), 16);
        $hashGmp = self::truncateHash($hashGmp, $generator);

        // Sign with deterministic k (RFC 6979)
        $random = RandomGeneratorFactory::getHmacRandomGenerator($key, $hashGmp, 'sha256');
        $randomK = $random->generate($generator->getOrder());

        $signer = new EccSigner($adapter);
        $sig = $signer->sign($key, $hashGmp, $randomK);

        // Enforce low-S
        $n = $generator->getOrder();
        $halfN = gmp_div_q($n, 2);
        $s = $sig->getS();
        $r = $sig->getR();
        if (gmp_cmp($s, $halfN) > 0) {
            $s = gmp_sub($n, $s);
            $sig = new Signature($r, $s);
        }

        $rHex = str_pad(gmp_strval($r, 16), 64, '0', STR_PAD_LEFT);
        $sHex = str_pad(gmp_strval($s, 16), 64, '0', STR_PAD_LEFT);
        $signature = Bech32::hexToBytes($rHex . $sHex);

        // Determine recovery flag
        $recoveryFlag = self::findRecoveryFlag($generator, $adapter, $sigHash, $r, $s, $key);

        // Signature → 5-bit words: 64 bytes → 103 words, then recovery flag as 104th word
        $sigWords = Bech32::eightToFive($signature);
        // Ensure exactly 103 words
        while (count($sigWords) < 103) {
            $sigWords[] = 0;
        }
        $sigWords[] = $recoveryFlag;

        $allWords = [...$dataWords, ...$sigWords];
        $paymentRequest = Bech32::encode($hrp, $allWords);

        // Get public key
        $pubPoint = $key->getPublicKey()->getPoint();
        $x = gmp_strval($pubPoint->getX(), 16);
        $x = str_pad($x, 64, '0', STR_PAD_LEFT);
        $prefix = gmp_cmp(gmp_mod($pubPoint->getY(), gmp_init(2)), gmp_init(0)) === 0 ? '02' : '03';
        $pubKeyHex = $prefix . $x;

        return $invoice->with(
            complete: true,
            prefix: $hrp,
            payeeNodeKey: $pubKeyHex,
            signature: $rHex . $sHex,
            recoveryFlag: $recoveryFlag,
            paymentRequest: $paymentRequest,
        );
    }

    /**
     * Truncate hash to the bit length of the curve order (per ECDSA spec).
     */
    private static function truncateHash(GMP $hash, GeneratorPoint $generator): GMP
    {
        $order = $generator->getOrder();
        $orderBitLen = self::gmpBitLength($order);
        $hashBitLen = self::gmpBitLength($hash);

        if ($hashBitLen > $orderBitLen) {
            $hash = gmp_div_q($hash, gmp_pow(gmp_init(2), $hashBitLen - $orderBitLen));
        }

        return $hash;
    }

    /**
     * Get the bit length of a GMP number.
     */
    private static function gmpBitLength(GMP $n): int
    {
        if (gmp_cmp($n, 0) === 0) {
            return 0;
        }

        $hex = gmp_strval($n, 16);

        return strlen($hex) * 4;
    }

    /**
     * Find the correct recovery flag by trying each possibility.
     *
     * @param GeneratorPoint $generator
     * @param \Mdanter\Ecc\Math\GmpMathInterface $adapter
     * @param string $sigHash Raw binary hash
     * @param GMP $r
     * @param GMP $s
     * @param PrivateKeyInterface $key
     * @return int
     * @throws InvalidSignatureException
     */
    private static function findRecoveryFlag(
        GeneratorPoint $generator,
        \Mdanter\Ecc\Math\GmpMathInterface $adapter,
        string $sigHash,
        GMP $r,
        GMP $s,
        PrivateKeyInterface $key,
    ): int {
        $expectedPoint = $key->getPublicKey()->getPoint();
        $expectedX = str_pad(gmp_strval($expectedPoint->getX(), 16), 64, '0', STR_PAD_LEFT);
        $expectedPrefix = gmp_cmp(gmp_mod($expectedPoint->getY(), gmp_init(2)), gmp_init(0)) === 0 ? '02' : '03';
        $expectedPubHex = $expectedPrefix . $expectedX;

        $hashGmp = gmp_init(bin2hex($sigHash), 16);

        for ($flag = 0; $flag <= 3; $flag++) {
            try {
                $recovered = Secp256k1Recovery::recoverPublicKey($generator, $adapter, $hashGmp, $r, $s, $flag);
                if ($recovered === $expectedPubHex) {
                    return $flag;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        throw new InvalidSignatureException('Could not determine recovery flag');
    }
}
