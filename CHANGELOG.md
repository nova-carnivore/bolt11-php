# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 0.2.0

A correctness, hardening, and tooling release. Focus areas: tightening
BOLT 11 spec compliance in the decoder, removing leaky public surface
before 1.0, and adding a second static analyzer.

### Added

- **`Invoice::verifyDescription(string $description): bool`** — checks an
  out-of-band description against either the literal `d` tag (byte-exact)
  or the `h` (description_hash) commitment (constant-time SHA-256). BOLT 11
  requires readers to perform this check before paying, but the description
  itself is external; this helper provides the API.
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
- **Skip fallback-address tags with unknown version codes or
  out-of-spec witness lengths.** Versions `0–16` (segwit), `17` (P2PKH),
  and `18` (P2SH) are accepted; `19–31` are skipped per the spec's "MUST
  skip over `f` fields that use an unknown version" rule. P2PKH/P2SH
  must be 20 bytes; segwit v0 must be 20 or 32; segwit v1 (P2TR) must be
  32; v2–16 must be 2–40 bytes per BIP-141. Malformed candidates are
  silently skipped (matching the wrong-length behaviour for `p`/`h`/`s`/`n`).
- **Validate route hint shape.** Per spec, an `r` field is "one or more"
  51-byte hops. The decoder now throws `InvalidInvoiceException` when
  the decoded byte length is zero or not an exact multiple of 51,
  instead of silently truncating partial hops.
- **Validate UTF-8 in description tags.** `Tag::description()` rejects
  invalid UTF-8 at construction time; `Decoder::decode()` rejects
  invalid UTF-8 in the `d` tag of a parsed invoice. Per BOLT 11, `d`
  MUST be valid UTF-8.
- **Reject mixed-case bech32 input.** `Bech32::decode()` requires the
  input string to be either all-lowercase or all-uppercase; mixed-case
  fails per BIP-173. (Spec test vector 8 — uppercase invoice — still
  decodes correctly.)
- **Reject non-minimal `c`, `x`, and `9` tag encodings.** Per spec,
  readers SHOULD treat these fields as invalid if they begin with a
  zero field element. The single-zero `[0]` encoding for the value 0
  remains canonical and is not flagged.
- **Reject non-hex characters in `Bech32::hexToBytes()`.** Previously
  `hexdec()` silently coerced unknown characters to zero, producing
  all-zero byte arrays for malformed `payment_hash` / `payment_secret`
  / `payee` tag data. Now throws `InvalidInvoiceException`.

### Changed — `Encoder` validation

- **Reject zero, negative, and non-numeric amounts.**
  `Encoder::encode(satoshis: 0, …)`, `satoshis: -N`, and
  `millisatoshis: 'abc'` / `'-100'` now throw `InvalidAmountException`.
  Previously `(int) $millisatoshis` quietly returned 0 for non-numeric
  strings, allowing malformed input to look valid.
- **Reject duplicate singleton tags.** `payment_hash`, `payment_secret`,
  `description`, `purpose_commit_hash`, `payee`, `expire_time`,
  `min_final_cltv_expiry`, `feature_bits`, and `metadata` MUST appear
  at most once per spec; duplicates now throw `InvalidInvoiceException`.
- **Reject the `description` + `description_hash` combination.** Per
  spec, the two tags are mutually exclusive.
- **Reject negative `expiry` and `min_final_cltv_expiry`.** `Tag::expiry()`
  and `Tag::minFinalCltvExpiry()` now throw on negative input.
- **Reject invalid UTF-8 descriptions.** `Tag::description()` validates
  the string as UTF-8 at construction time.

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

### Known limitations (deferred follow-ups)

- **Unknown even feature bits are not rejected at decode time.** BOLT 11
  says readers MUST fail on unknown even bits in the `9` field. Faithful
  enforcement requires expanding `FeatureBits` to know all standardised
  BOLT 9 invoice-context bits (e.g. `option_route_blinding` 24/25,
  `option_payment_metadata` 48/49). The current `FeatureBits` map covers
  bits 0–19 only, and the spec's own test vector 9 sets bit 48; until the
  map is extended, decode is permissive about unrecognised bits.
- **Padding bits are not checked.** When 5-bit words are converted to
  bytes for fixed-length fields (`p`/`h`/`s`/`n`) and the signature, any
  trailing padding bits should be zero per canonical encoding. The
  decoder currently discards them silently.

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
