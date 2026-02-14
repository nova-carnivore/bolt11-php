# bolt11-php

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.3-8892BF.svg)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/nova-carnivore/bolt11-php/actions/workflows/ci.yml/badge.svg)](https://github.com/nova-carnivore/bolt11-php/actions/workflows/ci.yml)
[![PHPStan Level](https://img.shields.io/badge/phpstan-level%209-brightgreen.svg)](https://phpstan.org)
[![Latest Version](https://img.shields.io/packagist/v/nova-carnivore/bolt11-php.svg)](https://packagist.org/packages/nova-carnivore/bolt11-php)

Modern PHP 8.3+ BOLT 11 Lightning Network invoice encoder/decoder. Full spec compliance, production-ready.

## Features

- ⚡ **Full BOLT 11 spec compliance** — All 12 spec test vectors pass
- 🔐 **Encode, sign & decode** — Complete lifecycle support
- 🏗️ **Modern PHP 8.3+** — Enums, readonly classes, named arguments, match expressions
- 🔍 **PHPStan level 9** — Maximum static analysis strictness
- 🌐 **All networks** — Bitcoin, Testnet, Signet, Regtest
- 🏷️ **All tag types** — payment_hash, description, route hints, feature bits, metadata, and more
- 🔄 **Round-trip safe** — Encode → sign → decode preserves all data
- 📏 **PSR-12 code style** — Enforced with PHP-CS-Fixer

## Installation

```bash
composer require nova-carnivore/bolt11-php
```

### Requirements

- PHP 8.3 or higher
- ext-gmp (required by elliptic-php dependency)

## Quick Start

### Decode an Invoice

```php
use Nova\Bitcoin\Decoder;

$invoice = Decoder::decode('lnbc2500u1pvjluez...');

$invoice->satoshis;          // 250000
$invoice->millisatoshis;     // '250000000'
$invoice->network;           // Network::Bitcoin
$invoice->timestamp;         // 1496314658
$invoice->payeeNodeKey;      // '03e7156ae33b...'

// Access tags
$invoice->getPaymentHash();   // hex string
$invoice->getDescription();   // 'string'
$invoice->getPaymentSecret(); // hex string
$invoice->isExpired();        // bool
$invoice->getTag('payment_hash'); // Tag object
```

### Encode an Invoice

```php
use Nova\Bitcoin\Encoder;
use Nova\Bitcoin\Network;
use Nova\Bitcoin\Tag;

$unsigned = Encoder::encode(
    network: Network::Bitcoin,
    satoshis: 1000,
    tags: [
        Tag::paymentHash('0001020304050607...'),
        Tag::paymentSecret('1111111111111111...'),
        Tag::description('test payment'),
        Tag::expiry(3600),
    ],
);
```

### Sign an Invoice

```php
use Nova\Bitcoin\Signer;

$signed = Signer::sign($unsigned, $privateKeyHex);

$signed->paymentRequest; // 'lnbc10u1...'
$signed->complete;       // true
$signed->payeeNodeKey;   // compressed public key
```

### Amount Helpers

```php
use Nova\Bitcoin\Helpers;

Helpers::satToHrp(250000);       // '2500u'
Helpers::hrpToSat('2500u');      // '250000'
Helpers::millisatToHrp('1000');  // '10n'
Helpers::hrpToMillisat('10n');   // '1000'
```

## API Reference

### `Decoder::decode(string $paymentRequest): Invoice`

Decodes a BOLT 11 payment request string into an `Invoice` object. Handles both lowercase and UPPERCASE invoices.

### `Encoder::encode(...): Invoice`

Creates an unsigned invoice. Parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `network` | `Network` | `Network::Bitcoin` | Target network |
| `satoshis` | `?int` | `null` | Amount in satoshis |
| `millisatoshis` | `?string` | `null` | Amount in millisatoshis |
| `tags` | `array<Tag>` | `[]` | Tagged fields |
| `timestamp` | `?int` | `null` | Unix timestamp (defaults to now) |

### `Signer::sign(Invoice $invoice, string $privateKeyHex): Invoice`

Signs an unsigned invoice with a secp256k1 private key.

### `Invoice` (Value Object)

| Property | Type | Description |
|----------|------|-------------|
| `complete` | `bool` | Whether the invoice is fully signed |
| `prefix` | `string` | Full HRP (e.g. `lnbc2500u`) |
| `network` | `?Network` | Bitcoin network enum |
| `satoshis` | `?int` | Amount in satoshis |
| `millisatoshis` | `?string` | Amount in millisatoshis |
| `timestamp` | `int` | Unix timestamp |
| `payeeNodeKey` | `?string` | Compressed public key (hex) |
| `signature` | `string` | 64-byte compact signature (hex) |
| `recoveryFlag` | `int` | Signature recovery flag (0-3) |
| `tags` | `array<Tag>` | All tagged fields |
| `paymentRequest` | `?string` | Full bech32-encoded string |

### Tag Factory Methods

```php
Tag::paymentHash(string $hex): Tag
Tag::paymentSecret(string $hex): Tag
Tag::description(string $text): Tag
Tag::descriptionHash(string $hex): Tag
Tag::payeeNodeKey(string $hex): Tag
Tag::expiry(int $seconds): Tag
Tag::minFinalCltvExpiry(int $blocks): Tag
Tag::fallbackAddress(int $code, string $addressHash): Tag
Tag::routeHint(array $hops): Tag
Tag::featureBits(FeatureBits $bits): Tag
Tag::metadata(string $hex): Tag
```

### Enums

```php
enum Network: string {
    case Bitcoin = 'bc';
    case Testnet = 'tb';
    case Signet  = 'tbs';
    case Regtest = 'bcrt';
}

enum TagType: int {
    case PaymentHash = 1;
    case PaymentSecret = 16;
    case Description = 13;
    // ... and more
}

enum Multiplier: string {
    case Milli = 'm';
    case Micro = 'u';
    case Nano  = 'n';
    case Pico  = 'p';
}
```

## BOLT 11 Spec Compliance

All 12 official test vectors pass:

| # | Test | Status |
|---|------|--------|
| 1 | Donation (any amount) | ✅ |
| 2 | $3 coffee (2500µ, 60s expiry) | ✅ |
| 3 | UTF-8 description (ナンセンス 1杯) | ✅ |
| 4 | Hashed description (20m) | ✅ |
| 5 | Testnet with P2PKH fallback | ✅ |
| 6 | Mainnet with P2PKH + route hints | ✅ |
| 7 | Feature bits (8, 14, 99) | ✅ |
| 8 | Uppercase invoice | ✅ |
| 9 | Metadata (0x01fafaf0) | ✅ |
| 10 | Pico-BTC amount (9678785340p) | ✅ |
| 11 | High-S signature recovery | ✅ |
| 12 | Unknown tags (silently ignored) | ✅ |

### Supported Tagged Fields

| Code | Letter | Field | Supported |
|------|--------|-------|-----------|
| 1 | `p` | payment_hash | ✅ |
| 16 | `s` | payment_secret | ✅ |
| 13 | `d` | description | ✅ |
| 27 | `m` | metadata | ✅ |
| 19 | `n` | payee node key | ✅ |
| 23 | `h` | description_hash | ✅ |
| 6 | `x` | expiry | ✅ |
| 24 | `c` | min_final_cltv_expiry | ✅ |
| 9 | `f` | fallback address | ✅ |
| 3 | `r` | route hints | ✅ |
| 5 | `9` | feature bits | ✅ |

## Exception Handling

```php
use Nova\Bitcoin\Exception\{
    Bolt11Exception,           // Base exception
    InvalidInvoiceException,   // Malformed invoice
    InvalidChecksumException,  // Bad bech32 checksum
    InvalidSignatureException, // Signature issues
    InvalidAmountException,    // Bad amount format
    UnsupportedNetworkException, // Unknown network
};

try {
    $invoice = Decoder::decode($paymentRequest);
} catch (InvalidChecksumException $e) {
    // Bad checksum
} catch (InvalidInvoiceException $e) {
    // Malformed invoice
} catch (Bolt11Exception $e) {
    // Any BOLT 11 error
}
```

## Development

```bash
# Install dependencies
composer install

# Run tests
vendor/bin/phpunit

# Static analysis
vendor/bin/phpstan analyse

# Code style check
vendor/bin/php-cs-fixer fix --dry-run --diff

# Fix code style
vendor/bin/php-cs-fixer fix
```

## Architecture

```
src/
├── Decoder.php          # Main decoder
├── Encoder.php          # Main encoder
├── Signer.php           # Invoice signing (secp256k1)
├── Invoice.php          # Immutable value object
├── Tag.php              # Tag value object with factory methods
├── TagType.php          # Tag type enum
├── Network.php          # Network enum (Bitcoin, Testnet, Signet, Regtest)
├── Multiplier.php       # Amount multiplier enum (m, u, n, p)
├── Amount.php           # Amount value object
├── RouteHint.php        # Route hint value object
├── FallbackAddress.php  # Fallback address value object
├── FeatureBits.php      # Feature bits handler
├── Bech32.php           # Bech32 encoder/decoder
├── Helpers.php          # Static helper methods
└── Exception/
    ├── Bolt11Exception.php
    ├── InvalidInvoiceException.php
    ├── InvalidChecksumException.php
    ├── InvalidSignatureException.php
    ├── InvalidAmountException.php
    └── UnsupportedNetworkException.php
```

## License

MIT — see [LICENSE](LICENSE).
