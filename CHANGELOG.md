# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 0.2.0

### Security / correctness fixes

- **Reject invalid signature recovery flags.** `Decoder::decode()` now throws
  `InvalidSignatureException` when the recovery byte after the 64-byte compact
  signature is greater than 3. Previously, values 4–31 silently aliased onto
  valid flags (`flag mod 4`), which broke decode→encode round-trip safety
  and accepted spec-non-compliant invoices.
- **`Invoice::complete` now reflects signature recovery.** Previously hardcoded
  to `true` after every successful decode. An invoice with a malformed
  signature and no `n` tag (where ECDSA recovery returns `null`) now reports
  `complete === false`.
- **Reject non-hex characters in `Bech32::hexToBytes`.** Previously, `hexdec()`
  silently coerced unknown characters to `0`, producing all-zero byte arrays
  for malformed `payment_hash` / `payment_secret` / `payee` tag data. The
  function now rejects non-hex input via `ctype_xdigit` and throws
  `InvalidInvoiceException`. This also tightens any user-supplied hex passed
  through `Tag::paymentHash()` etc.
- **Reject zero amounts at encode time.** `Encoder::encode(satoshis: 0, ...)`
  and `Encoder::encode(millisatoshis: '0', ...)` now throw
  `InvalidAmountException`. Previously fell through to `msatToHrpString(0)`,
  emitting a malformed prefix `lnbc0p` that no conformant reader will parse.
  Per BOLT 11, writers MUST NOT include an amount of 0 millisatoshis.
- **Reject duplicate singleton tags at encode time.** `Encoder::encode()` now
  throws `InvalidInvoiceException` if a tag that the spec mandates appear at
  most once is repeated (`payment_hash`, `payment_secret`, `description`,
  `purpose_commit_hash`, `payee`, `expire_time`, `min_final_cltv_expiry`,
  `feature_bits`, `metadata`). It also rejects invoices that include both
  `description` and `purpose_commit_hash` (mutually exclusive per spec).
- **Skip fallback-address tags with invalid version codes.** Per spec,
  readers MUST skip `f` fields whose version is not in `0–18`. Previously
  the decoder accepted any 5-bit value (0–31).

### Breaking API changes

- **Removed `Invoice::wordsTemp`.** This was an internal encoder artefact
  (the bech32-encoded prefix without signature) leaked onto a public
  readonly value object. After decode it was always the empty string.
  Callers reading this field should switch to `Invoice::prefix` for the HRP
  or re-encode via `Encoder::encode()` if they need the unsigned bech32.
- **Removed `FallbackAddress::address`.** This field was always `''`. The
  constructor signature is now `(int $code, string $addressHash)`.
- **Removed unused public methods on `Network`.** `pubKeyHash()`,
  `scriptHash()`, `validWitnessVersions()`, and `fromBech32()` were not
  used internally and were not exercised by tests. They have been removed
  to keep the public surface minimal. Use `Network::fromHrp()` for the
  documented decode path.
- **`FeatureBits::extraBits` returns `null` when empty.** Previously always
  populated with `['start_bit' => 20, 'bits' => [], 'has_required' => false]`
  even when no extra bits were present. Code that did
  `count($fb->extraBits['bits']) > 0` should switch to
  `$fb->extraBits !== null`.

### Internal / refactor (no API change)

- `Decoder::sha256Bytes()` and `Signer` now use `pack('C*', …)` /
  `array_map(ord(...), str_split(…))` instead of manual `chr`/`ord` loops.
- `Helpers::hrpToMillisatNum()` and `Amount::fromHrp()` now use integer-only
  arithmetic via a new `Multiplier::toMsat()` helper, replacing the previous
  float multiply-and-round path.
- `Multiplier::msatPerUnit(): float` removed in favour of
  `Multiplier::toMsat(int $units): int`.
- Removed an unreachable padding loop in `Signer` (`eightToFive` on a
  64-byte signature always yields exactly 103 words).
- README: softened the "constant-time operations" claim — the project
  delegates ECDSA to the `paragonie/ecc` library; lower-level constant-time
  guarantees are scoped to that dependency.

### Tests

- Added 6 regression tests covering each of the correctness fixes above.
- Added `FuzzTest`: property-based tests that mutate spec vectors (single
  character substitution, truncation, garbage input) and assert the decoder
  always throws `Bolt11Exception` rather than crashing with an uncaught
  error or warning. Seed is fixed so failures are reproducible.

## [0.1.0] — Initial release

- BOLT 11 Lightning Network invoice encoder, decoder, and signer for
  PHP 8.3+.
- All 12 official spec test vectors pass.
- PHPStan level 9 clean, PSR-12 enforced.
- Networks: Bitcoin, Testnet, Signet, Regtest.
