# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 0.2.0

A correctness, hardening, and tooling release. Focus areas: tightening
BOLT 11 spec compliance in the decoder, removing leaky public surface
before 1.0, and adding a second static analyzer.

### Added

- **Psalm at `errorLevel="1"`** (the strictest setting) with the official
  `psalm/plugin-phpunit` plugin. Psalm now infers types for 100% of the
  codebase, complementing PHPStan level 9. Wired into `composer ci` and
  the GitHub Actions matrix.
- **Property/fuzz tests** (`tests/FuzzTest.php`): single-character
  bech32 substitutions, truncations, and garbage inputs are applied to
  spec vectors and the decoder must always either succeed or throw a
  typed `Bolt11Exception` — never an uncaught error or warning. Seed is
  fixed for reproducibility.
- **Regression tests** for every correctness fix below.

### Changed — BOLT 11 spec compliance

- **Reject invalid signature recovery flags.** `Decoder::decode()` now
  throws `InvalidSignatureException` when the recovery byte appended
  after the 64-byte compact signature is greater than 3. Previously,
  values 4–31 silently aliased onto valid flags (`flag mod 4`), breaking
  decode→encode round-trip safety and accepting non-conformant invoices.
- **Reject invoices whose signature cannot be recovered.** When no `n`
  tag is provided and ECDSA public-key recovery fails, decode now throws
  `InvalidSignatureException` instead of producing an invoice with
  `payeeNodeKey === null`.
- **Validate the signature against an explicit `n` tag.** When an `n`
  tag is present, the decoder now performs ECDSA recovery and requires
  the recovered key to equal the tag value (case-insensitive hex);
  mismatch throws `InvalidSignatureException`. Previously the tag was
  trusted verbatim, allowing an attacker to pair any pubkey with an
  unrelated valid signature.
- **Reject high-S signatures when an `n` tag is present.** Per spec
  §"Tagged Fields → Requirements", the explicit-n branch MUST fail on
  high-S; only the recovery branch (no `n` tag) accepts high-S.
- **Require valid `p`, `s`, and exactly one of `d`/`h`** at decode
  time. Wrong-length `p`/`h`/`s`/`n` candidates are silently skipped
  (matching spec test vector 12), then the post-parse check fails the
  decode if no valid required tag survived.
- **Skip fallback-address tags with unknown version codes.** Versions
  `0–16` (segwit), `17` (P2PKH), and `18` (P2SH) are accepted; `19–31`
  are skipped per the spec's "MUST skip over `f` fields that use an
  unknown version" rule.
- **Reject non-hex characters in `Bech32::hexToBytes()`.** Previously
  `hexdec()` silently coerced unknown characters to zero, producing
  all-zero byte arrays for malformed `payment_hash` / `payment_secret`
  / `payee` tag data. Now throws `InvalidInvoiceException`.

### Changed — `Encoder` validation

- **Reject zero amounts.** `Encoder::encode(satoshis: 0, …)` and
  `Encoder::encode(millisatoshis: '0', …)` now throw
  `InvalidAmountException`. Per BOLT 11, writers MUST NOT include an
  amount of 0 millisatoshis.
- **Reject duplicate singleton tags.** `payment_hash`, `payment_secret`,
  `description`, `purpose_commit_hash`, `payee`, `expire_time`,
  `min_final_cltv_expiry`, `feature_bits`, and `metadata` MUST appear
  at most once per spec; duplicates now throw `InvalidInvoiceException`.
- **Reject the `description` + `description_hash` combination.** Per
  spec, the two tags are mutually exclusive.

### Changed — internals (no API impact)

- `Decoder` and `Signer` use `pack('C*', …)` /
  `array_map(ord(...), str_split(…))` instead of the previous manual
  `chr`/`ord` loops over byte arrays.
- `Helpers::hrpToMillisatNum()` and `Amount::fromHrp()` use integer-only
  arithmetic via the new `Multiplier::toMsat()` helper, eliminating the
  float multiply-and-round step.
- `Decoder::parseTags()` narrows its loop counter to `int<0, max>` for
  Psalm.
- Unreachable padding loop in `Signer` removed (`eightToFive` on a
  64-byte signature always yields exactly 103 words).

### Removed (breaking)

- **`Multiplier::msatPerUnit(): float`** in favour of the integer-safe
  `Multiplier::toMsat(int $units): int`.
- **`Invoice::wordsTemp`** — encoder-internal artefact leaked onto the
  public value object; always `''` after decode. Construct the unsigned
  bech32 string via `Encoder::encode()` if you need it.
- **`FallbackAddress::address`** — was always `''`. Constructor is now
  `(int $code, string $addressHash)`.
- **Unused `Network` helpers**: `pubKeyHash()`, `scriptHash()`,
  `validWitnessVersions()`, and `fromBech32()`. Use `Network::fromHrp()`
  for the documented decode path.
- **`FeatureBits::extraBits`** is now `null` when no extra bits are
  present (was always populated with an empty stub). Code that did
  `count($fb->extraBits['bits']) > 0` should switch to
  `$fb->extraBits !== null`.

### Other

- All five leaf exception classes (`InvalidAmountException`,
  `InvalidChecksumException`, `InvalidInvoiceException`,
  `InvalidSignatureException`, `UnsupportedNetworkException`) are now
  `final`. The base `Bolt11Exception` remains extensible.
- README badge for Psalm; "Audited crypto dependency" wording in place
  of the previous "constant-time operations" claim — constant-time
  guarantees belong to `paragonie/ecc`, not this library's call sites.
- `composer ci` now runs `phpunit + phpstan + psalm + cs-check`.

## [0.1.0] — Initial release

- BOLT 11 Lightning Network invoice encoder, decoder, and signer for
  PHP 8.3+.
- All 12 official spec test vectors pass.
- PHPStan level 9 clean, PSR-12 enforced.
- Networks: Bitcoin, Testnet, Signet, Regtest.
