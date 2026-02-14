<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11;

use GMP;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Primitives\PointInterface;

/**
 * ECDSA public key recovery for secp256k1.
 *
 * Implements the recovery algorithm from SEC 1 v2, section 4.1.6:
 * Given a message hash, signature (r, s), and recovery flag (0-3),
 * recover the public key that produced the signature.
 */
final class Secp256k1Recovery
{
    /**
     * Recover a compressed public key (hex) from an ECDSA signature.
     *
     * @param GeneratorPoint $generator The secp256k1 generator point
     * @param GmpMathInterface $adapter Math adapter
     * @param GMP $hash Message hash as GMP integer
     * @param GMP $r Signature r component
     * @param GMP $s Signature s component
     * @param int $recoveryFlag Recovery flag (0-3)
     * @return string Compressed public key as hex string (66 chars)
     * @throws \RuntimeException If recovery fails
     */
    public static function recoverPublicKey(
        GeneratorPoint $generator,
        GmpMathInterface $adapter,
        GMP $hash,
        GMP $r,
        GMP $s,
        int $recoveryFlag,
    ): string {
        $n = $generator->getOrder();
        $curve = $generator->getCurve();
        $p = $curve->getPrime();

        // Recovery flag encodes:
        // - bit 0: y parity (0 = even, 1 = odd)
        // - bit 1: whether r > n (add n to x)
        $isOddY = ($recoveryFlag & 1) === 1;
        $isSecondKey = ($recoveryFlag & 2) === 2;

        // Step 1: Compute x coordinate of R
        $x = $isSecondKey ? $adapter->add($r, $n) : $r;

        // x must be less than p
        if ($adapter->cmp($x, $p) >= 0) {
            throw new \RuntimeException('Recovery failed: x >= p');
        }

        // Step 2: Recover the point R from x
        $rPoint = self::decompressPoint($curve, $adapter, $x, $isOddY);

        // Step 3: Compute the public key
        // Q = r^-1 * (s*R - hash*G)
        $rInv = $adapter->inverseMod($r, $n);

        // s*R
        $sR = $rPoint->mul($s);

        // hash*G — we need to negate: -hash * G
        $negHash = $adapter->mod($adapter->sub($n, $hash), $n);
        $negHashG = $generator->mul($negHash);

        // Q = r^-1 * (sR + (-hash*G))
        $sum = $sR->add($negHashG);
        $q = $sum->mul($rInv);

        return self::compressPoint($q);
    }

    /**
     * Decompress a point from its x coordinate and y parity.
     *
     * For secp256k1: y² = x³ + 7 (mod p)
     *
     * @param \Mdanter\Ecc\Primitives\CurveFpInterface $curve
     * @param GmpMathInterface $adapter
     * @param GMP $x
     * @param bool $isOddY
     * @return PointInterface
     */
    private static function decompressPoint(
        \Mdanter\Ecc\Primitives\CurveFpInterface $curve,
        GmpMathInterface $adapter,
        GMP $x,
        bool $isOddY,
    ): PointInterface {
        $p = $curve->getPrime();
        $a = $curve->getA();
        $b = $curve->getB();

        // y² = x³ + ax + b (mod p)
        $x3 = $adapter->mod($adapter->mul($x, $adapter->mul($x, $x)), $p);
        $ax = $adapter->mod($adapter->mul($a, $x), $p);
        $rhs = $adapter->mod($adapter->add($adapter->add($x3, $ax), $b), $p);

        // Compute square root: y = rhs^((p+1)/4) mod p (works when p ≡ 3 mod 4, which is true for secp256k1)
        $exp = $adapter->div($adapter->add($p, gmp_init(1)), gmp_init(4));
        $y = gmp_powm($rhs, $exp, $p);

        // Verify
        if (gmp_cmp($adapter->mod($adapter->mul($y, $y), $p), $rhs) !== 0) {
            throw new \RuntimeException('Recovery failed: no valid y for x');
        }

        // Adjust parity
        $yIsOdd = gmp_cmp($adapter->mod($y, gmp_init(2)), gmp_init(0)) !== 0;
        if ($yIsOdd !== $isOddY) {
            $y = $adapter->sub($p, $y);
        }

        return $curve->getPoint($x, $y);
    }

    /**
     * Compress a point to its 33-byte hex representation.
     */
    private static function compressPoint(PointInterface $point): string
    {
        $x = str_pad(gmp_strval($point->getX(), 16), 64, '0', STR_PAD_LEFT);
        $prefix = gmp_cmp(gmp_mod($point->getY(), gmp_init(2)), gmp_init(0)) === 0 ? '02' : '03';

        return $prefix . $x;
    }
}
