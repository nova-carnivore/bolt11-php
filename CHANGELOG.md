# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-07

A correctness, hardening, and tooling release. Focus areas: tightening
BOLT 11 spec compliance in the decoder, removing leaky public surface
before 1.0, and adding a second static analyzer.

### Added

- **`FeatureBits::$optionRouteBlinding`** (bits 24/25),
  **`FeatureBits::$optionAttributionData`** (bits 36/37), and
  **`FeatureBits::$optionPaymentMetadata`** (bits 48/49) — new readonly
  properties covering all BOLT 9 invoice-context features. Bit 48 is
  required to decode spec test vector 9; bits 24/25 and 36/37 are also
  current invoice-context features per BOLT 9.
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
- **Reject unknown required (even) feature bits, scoped strictly to the
  BOLT 9 *invoice* context.** Per spec, a reader MUST fail the payment
  if the `9` field contains unknown even bits. The known-feature map is
  now derived from BOLT 9's "Context" column — only bits whose context
  contains `9` (plus `var_onion_optin` 8/9 and `payment_secret` 14/15,
  which BOLT 9 marks ASSUMED but BOLT 11 spec test vector 7 sets in
  invoices). This means channel-only features (e.g.
  `option_data_loss_protect`, `option_upfront_shutdown_script`,
  `gossip_queries`, `option_static_remotekey`,
  `option_support_large_channel`) now correctly fall in `extraBits` and,
  if even/required, cause decode to fail. Conversely,
  `option_attribution_data` (36/37) is now tracked because BOLT 9 marks
  it `IN9`.
- **Reject non-zero padding bits in fixed-length fields.** Per canonical
  encoding, the trailing padding bits when 5-bit words are unpacked to
  bytes MUST be zero. The decoder now validates: 4 padding bits at the
  end of `p`/`h`/`s` (52 words → 32 bytes), 1 padding bit at the end of
  `n` (53 words → 33 bytes), and 3 padding bits at the end of the
  signature data (103 words → 64 bytes).
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
- **`Signer::sign()` verifies an explicit `n` tag matches the signing
  key.** Per spec, "MUST set `n` to the public key used to create the
  `signature`." If the unsigned invoice already carries an `n` tag whose
  value differs from the public key derived from the supplied private
  key, sign fails with `InvalidSignatureException`. Without this check,
  the writer would emit an invoice that no compliant reader will accept.
- **`Tag::fallbackAddress()` validates the address-hash length per
  version code at construction time.** P2PKH (17) / P2SH (18) require
  20-byte hashes; segwit v0 requires 20 or 32 bytes; segwit v1 (P2TR)
  requires 32 bytes; segwit v2-16 require 2-40 bytes. Versions outside
  0-18 are rejected. Non-hex input also fails fast.
- **BOLT 9 transitive feature dependencies are enforced at decode.**
  Per BOLT 9, "if the feature vector does not set all known, transitive
  feature dependencies: MUST NOT attempt the payment." The decoder now
  rejects invoices whose `9` field sets `basic_mpp` without
  `payment_secret`, or `payment_secret` without `var_onion_optin`.
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
- **`FeatureBits::extraBits['start_bit']`** removed. The known set is
  no longer contiguous; the remaining shape is
  `{bits: list<int>, has_required: bool}`.
- **Channel- and init-only properties removed from `FeatureBits`:**
  `$optionDataLossProtect` (0/1), `$initialRoutingSync` (2/3),
  `$optionUpfrontShutdownScript` (4/5), `$gossipQueries` (6/7),
  `$gossipQueriesEx` (10/11), `$optionStaticRemotekey` (12/13), and
  `$optionSupportLargeChannel` (18/19). Per BOLT 9, none of these have
  `9` in their Context column — they are not legal in invoice context,
  and a reader claiming to "know" them was being too permissive.
  Bits 2/3 (`initial_routing_sync`) is also no longer in BOLT 9 at all.
  Code that read these properties should either move to channel-context
  parsers or treat them as decode failures (which the new behaviour
  does automatically when the bits are required).

### Spec interpretation notes

- **Wrong-length `p`/`h`/`s`/`n` tags are silently skipped, not failed.**
  The spec prose at `11-payment-encoding.md` line 213 says readers MUST
  fail the payment if any of these fields has the wrong `data_length`.
  Spec test vector 12, however, explicitly marks such candidates
  `(ignored)`. We follow the canonical test vector. The post-parse
  presence check (`validateRequiredTagPresence`) still fails the decode
  if every candidate of a required type is wrong-length.
- **Writer-side `feature_bits` minimum data_length is not enforced
  against `FeatureBits::wordLength`.** `FeatureBits::toWords()` honours
  the user-supplied `wordLength`. A hand-constructed `FeatureBits` with
  an oversized `wordLength` would emit non-minimal output. The natural
  `fromWords()` → `toWords()` round-trip stays canonical, so this only
  triggers if the user constructs `FeatureBits` directly with a
  larger-than-needed length.

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
