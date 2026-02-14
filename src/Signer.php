<?php

declare(strict_types=1);

namespace Nova\Bitcoin;

use Elliptic\EC;
use Nova\Bitcoin\Exception\InvalidSignatureException;

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
        $ec = new EC('secp256k1');

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

        // Sign with secp256k1
        $key = $ec->keyFromPrivate($privateKeyHex, 'hex');
        $sig = $key->sign(bin2hex($sigHash), ['canonical' => true]);

        $rHex = str_pad($sig->r->toString(16), 64, '0', STR_PAD_LEFT);
        $sHex = str_pad($sig->s->toString(16), 64, '0', STR_PAD_LEFT);
        $signature = Bech32::hexToBytes($rHex . $sHex);

        // Determine recovery flag
        $recoveryFlag = self::findRecoveryFlag($ec, $sigHash, $rHex, $sHex, $privateKeyHex);

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
        $pubPoint = $key->getPublic();
        $pubKeyHex = $pubPoint->encode('hex', true);

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
     * Find the correct recovery flag by trying each possibility.
     */
    private static function findRecoveryFlag(
        EC $ec,
        string $sigHash,
        string $rHex,
        string $sHex,
        string $privateKeyHex,
    ): int {
        $key = $ec->keyFromPrivate($privateKeyHex, 'hex');
        $expectedPubHex = $key->getPublic()->encode('hex', true);
        $hashHex = bin2hex($sigHash);
        $sigObj = ['r' => $rHex, 's' => $sHex];

        for ($flag = 0; $flag <= 3; $flag++) {
            try {
                $point = $ec->recoverPubKey($hashHex, $sigObj, $flag);
                $recoveredKey = $ec->keyFromPublic($point);
                $recoveredHex = $recoveredKey->getPublic(true, 'hex');

                if ($recoveredHex === $expectedPubHex) {
                    return $flag;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        throw new InvalidSignatureException('Could not determine recovery flag');
    }
}
