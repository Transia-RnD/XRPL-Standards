<pre>
  title: Post-Quantum Signatures (ML-DSA-44)
  description: Introduce CRYSTALS-Dilithium (ML-DSA-44) as a signature scheme available across all XRPL signing surfaces: validator manifests, validations, proposals, UNL signatures, peer handshakes, node identities, and account-level transaction signing.
  implementation: https://github.com/XRPLF/rippled/tree/dilithium-full, https://github.com/XRPLF/xrpl.js/tree/dilithium, https://github.com/XRPLF/xrpld-publisher/tree/quantum
  author: Denis Angell <dangell@transia.co>
  category: Amendment
  status: Draft
  proposal-from: https://github.com/XRPLF/XRPL-Standards/discussions/295
  requires:
  created: 2025-07-08
  updated: 2026-05-20
</pre>

# Post-Quantum Signatures (ML-DSA-44)

## 1. Abstract

This XLS introduces **CRYSTALS-Dilithium2 (NIST ML-DSA-44, FIPS 204)** as a new signature algorithm available throughout the XRPL signing surface: validator manifests, validations, consensus proposals, UNL publisher signatures, peer-to-peer handshakes, node identities, and account-level transaction signing (including multisign, batch signing, and payment-channel claims). A new `KeyType` value, `dilithium`, is added alongside `secp256k1` and `ed25519`. The change is gated by a new amendment, `Quantum`.

The motivation is forward-secrecy against "harvest-now, decrypt-later" attacks and against future cryptanalytic advances (Shor's algorithm) that would render ECDSA over secp256k1 and Ed25519 insecure. The post-quantum scheme is available everywhere a signature is produced or verified. Migration cadence is left to operators and account holders.

## 2. Motivation

XRPL's signing surface currently relies on two pre-quantum signature schemes:

- **secp256k1 ECDSA**: accounts (default), validator identities, manifests, validations, consensus proposals, UNL publisher signatures, peer handshakes, node identities.
- **Ed25519**: accounts (opt-in via key type).

Both are broken by a sufficiently large fault-tolerant quantum computer running Shor's algorithm. The relevant timescale for XRPL is not "when an attacker can run Shor's algorithm" but "when an attacker could have *recorded enough material* that running Shor's algorithm later still lets them forge a signature." That window is open today.

Exposure differs by surface:

- **Validator and publisher keys** are long-lived. A compromised validator master key permits retroactive impersonation in proposals and validations; a compromised UNL publisher key permits arbitrary UNL substitution.
- **Account keys** authorize transfers of value. A high-value account that does not rotate before "Q-day" can be drained by anyone who recorded its on-chain signatures.
- **Node identity keys** authenticate peer-to-peer sessions and shape the gossip topology.

NIST standardized ML-DSA in FIPS 204 (August 2024). ML-DSA-44 (the lowest parameter set, NIST security category 2) fits the volume and latency profile of XRPL signatures.

## 3. Specification

> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 3.1 Amendment

A new amendment, `Quantum`, is added. Until the amendment is enabled on the network, peers MUST reject any protocol-level message that uses the new `dilithium` key type: validator manifests, validations, consensus proposals, UNL signatures, peer-handshake session signatures, and signed transactions (including multisign signer entries, batch inner/outer signatures, and payment-channel claims).

```
XRPL_FEATURE(Quantum, Supported::Yes, VoteBehavior::DefaultNo)
```

Until activation, `dilithium` keys MAY be generated and stored by operators preparing for activation, but signatures produced by them MUST NOT be accepted by peers.

### 3.2 New KeyType

The `KeyType` enumeration is extended:

```cpp
enum class KeyType {
    secp256k1 = 0,
    ed25519   = 1,
    dilithium = 2,   // ML-DSA-44 (FIPS 204)
};
```

The string representation used in configuration and serialized contexts is the lowercase token `"dilithium"`. Implementations MUST accept this exact string in `keyTypeFromString` and emit it from `to_string(KeyType)`.

### 3.3 Algorithm Parameters

This XLS standardizes on **ML-DSA-44** (Dilithium2 in earlier CRYSTALS-Dilithium drafts):

| Component        | Size (bytes) | Notes                                              |
|------------------|--------------|----------------------------------------------------|
| Public key       | 1312         | `pqcrystals_dilithium2_PUBLICKEYBYTES`             |
| Secret key       | 2560         | `pqcrystals_dilithium2_SECRETKEYBYTES`             |
| Signature        | ≤ 2420       | Variable length; the on-wire encoding carries `len` |
| Context string   | empty        | `ctxlen == 0`; see §3.4                            |

A future XLS MAY extend support to ML-DSA-65 / ML-DSA-87. This XLS does not require that.

### 3.4 Signing and Verification

Signing and verification use the FIPS 204 `Sign` / `Verify` interfaces with an empty context string (`ctxlen == 0`). Two flavors mirror the existing pre-quantum API:

- `sign(pk, sk, m)` / `verify(pk, m, sig)`: sign or verify the message `m` as-is.
- `signDigest(pk, sk, digest)` / `verifyDigest(pk, digest, sig, mustBeFullyCanonical)`: sign or verify a 32-byte digest as-is. For `dilithium`, `mustBeFullyCanonical` is ignored.

Implementations MUST treat ML-DSA signatures as opaque variable-length byte strings up to 2420 bytes and MUST NOT apply DER parsing, low-S normalization, or any other secp256k1-specific transform.

### 3.5 Variable-Length Public and Secret Keys

`PublicKey` and `SecretKey` become variable-length containers to hold a 1312-byte ML-DSA public key (vs. 33-byte secp256k1 / Ed25519 public keys) and a 2560-byte ML-DSA secret key (vs. 32-byte secp256k1 / Ed25519 secret keys).

The on-the-wire encoding of a key is determined by length:

- **33 bytes** with leading `0x02`/`0x03` → `secp256k1` public key.
- **33 bytes** with leading `0xED` → `ed25519` public key.
- **1312 bytes** → `dilithium` public key.
- Any other length is invalid.

The Base58 codec is extended to accept inputs longer than the previous 64-character limit. For decoding, implementations MUST fall back from the optimized `b58_fast` path to the reference `b58_ref` path when the optimized path declines an over-length input.

### 3.6 Base58 Token-Type Bytes

XRPL Base58 encodes typed payloads (seeds, public keys, private keys, accounts) with a one- or three-byte version prefix and a 4-byte SHA-256 checksum. This XLS introduces one new prefix and changes two existing ones to variable-length payloads:

| Constant         | Value                | Payload                        | Status         |
|------------------|----------------------|--------------------------------|----------------|
| `FAMILY_SEED`    | `0x21`               | 16-byte secp256k1 seed         | unchanged      |
| `ED25519_SEED`   | `0x01, 0xE1, 0x4B`   | 16-byte ed25519 seed           | unchanged      |
| `DILITHIUM_SEED` | `0x22`               | 16-byte dilithium seed         | **new**        |
| `NODE_PUBLIC`    | `0x1C`               | 33-byte (pre-quantum) or 1312-byte (dilithium) node public key | now variable-length |
| `NODE_PRIVATE`   | `0x20`               | 32-byte (pre-quantum) or 2560-byte (dilithium) node private key | now variable-length |
| `ACCOUNT_PUBLIC` | `0x23`               | 33-byte (pre-quantum) or 1312-byte (dilithium) account public key | now variable-length |

The 16-byte seed payload is constant across all three signing schemes. The discriminator is the **version byte**, not the payload length:

- `0x21` → `secp256k1`
- `[0x01, 0xE1, 0x4B]` → `ed25519`
- `0x22` → `dilithium`

For `NODE_PUBLIC`, `NODE_PRIVATE`, and `ACCOUNT_PUBLIC`, the decode call MUST accept the payload length as a parameter and the encode call MUST be passed an `expectedLength`. The signing scheme is derived by the rules in §3.5.

### 3.7 Validator Configuration

A new configuration section, `[validator_key_type]`, selects the algorithm used when a validator's `[validation_seed]` or `[validator_token]` is consumed to derive a keypair. Acceptable values are `secp256k1`, `ed25519`, `dilithium`. If absent, the default is `secp256k1`.

```
[validator_key_type]
dilithium

[validation_seed]
sn...
```

If `[validator_key_type]` contains an unrecognized value, the implementation MUST mark the configuration as invalid and refuse to start in validating mode.

The same configuration governs the keypair derived for the node identity, so an operator who chooses `dilithium` for their validator key also gets a `dilithium` node identity.

### 3.8 Validator Tokens

The `[validator_token]` blob's `validation_secret` field accepts the following lengths:

| Length (bytes) | Meaning                |
|----------------|------------------------|
| 32             | secp256k1 / Ed25519 secret key |
| 2560           | ML-DSA-44 secret key  |

Other secret-key lengths MUST be rejected.

### 3.9 Validator Manifests

A validator manifest is signed by the validator's master key and (when present) the validator's signing key. Either or both MAY be `dilithium`. When the master key or signing key is `dilithium`, the corresponding `MasterSignature` or `Signature` field is the raw variable-length ML-DSA signature (no DER wrapping). The manifest structure is unchanged; only the embedded public-key and signature field lengths differ.

Pre-amendment peers MUST reject any received manifest whose master or signing key is `dilithium`.

### 3.10 Manifest Serialized-Field Variable-Length Encoding

Manifests are XRPL `STObject`s serialized with the standard binary codec. `PublicKey` (field tag `0x71`) and `SigningPubKey` (field tag `0x73`) are variable-length blobs carrying an XRPL VL-length prefix. Pre-quantum keys (33 bytes) fit the single-byte form; ML-DSA-44 keys (1312 bytes) MUST use the two-byte form.

For a payload of length `L` bytes, implementations MUST encode the length prefix as follows (this is the existing XRPL VL encoding; restated because pre-quantum publisher tooling never exercised the `L > 192` branch):

| `L` range            | Encoding                                                             |
|----------------------|----------------------------------------------------------------------|
| `0 ≤ L ≤ 192`        | single byte: `L`                                                     |
| `193 ≤ L ≤ 12480`    | two bytes: `b0 = 193 + ((L - 193) / 256)`, `b1 = (L - 193) mod 256`  |
| `12481 ≤ L ≤ 918744` | three bytes: standard XRPL three-byte VL form                        |

A 1312-byte dilithium public key encodes as `b0 = 197`, `b1 = 95`. Manifest builders that hard-code the single-byte form MUST be updated. Parsers using the standard codec handle this transparently.

### 3.11 UNL Publisher Lists

A UNL publisher MAY sign the validator list blob with a `dilithium` key. To verify:

1. Look up the publisher master key in `publisherLists_`.
2. If the publisher's effective signing key is `dilithium`, verify with ML-DSA-44.
3. Otherwise verify with the existing secp256k1 / Ed25519 path.

Because dilithium public keys are 1312 bytes, the on-disk cache filename for a publisher list MUST NOT be the hex-encoded public key (that filename would exceed the 255-byte limit on most filesystems). Implementations MUST hash the public key with SHA-256 and use the hex-encoded 32-byte hash as the filename suffix:

```
cache_filename = "<prefix>" + hex(sha256(publisherPublicKey))
```

This applies to all publisher keys, not only dilithium, to keep the cache layout key-type-agnostic.

### 3.12 Consensus Proposals

`TMProposeSet` messages carry a `nodepubkey` and a `signature`. Signature length is bounded by key type:

| Key type        | Permitted signature length |
|-----------------|----------------------------|
| `secp256k1`     | 64–72 bytes (DER)          |
| `ed25519`       | 64 bytes                   |
| `dilithium`     | 64–2420 bytes              |

A proposal whose key type cannot be determined, or whose signature length falls outside the permitted range, MUST be treated as malformed. The originating peer MUST be charged a `kFeeInvalidSignature` resource cost.

### 3.13 Validations

The validation set serialization is unchanged. `STValidation::isValid()` MUST verify using the key type indicated by the validator's public key length and shape (per §3.5). Implementations MUST NOT hard-code an assertion that the validator key is `secp256k1`.

### 3.14 Peer Handshakes

The peer handshake exchanges and verifies a public key over the TLS-derived shared value. With this XLS:

1. The advertised `Public-Key` MAY be a `dilithium` key.
2. The `Session-Signature` is produced and verified with the scheme matching the advertised key.
3. A node MAY reject peers whose advertised key type it does not implement, but MUST do so with a clear error response and not silently drop the connection.

### 3.15 Socket Buffer Sizing

Default TCP socket buffers on some platforms (notably macOS, ~128 KiB) are too small to absorb bursts of large ML-DSA signatures, causing `stream truncated` errors at the TLS layer. Implementations SHOULD set send and receive buffer sizes to at least **1 MiB** on accepted peer connections.

### 3.16 RPCs

The admin RPC `validation_create` returns `validation_public_key` / `validation_private_key`. When `Quantum` is enabled, the RPC SHOULD accept an optional `key_type` parameter (`secp256k1`, `ed25519`, `dilithium`). If omitted, implementations MAY default to `dilithium` post-activation; the default remains `secp256k1` pre-activation.

The admin convenience RPCs `sign` and `wallet_propose` SHOULD be extended in the same way to accept `key_type: "dilithium"`. The reference implementation does not yet lift the existing `secp256k1`/`ed25519`-only restriction in these two RPCs; see §3.18.6.

### 3.17 Client Library Surface

Client libraries (xrpl.js, xrpl-py, xrpld-publisher tooling) MUST expose the following so operators can generate and manage `dilithium` keys without touching server admin RPCs.

#### 3.17.1 Seed and keypair generation

- `generateSeed({ algorithm: 'dilithium' })` MUST produce a 16-byte entropy seed Base58-encoded under `DILITHIUM_SEED` (`0x22`).
- `deriveKeypair(seed)` MUST inspect the decoded seed's type byte and dispatch to the dilithium scheme when it is `0x22`. Implementations MUST self-verify the derived keypair by signing and verifying a known message; if verification fails, generation MUST throw.

#### 3.17.2 Deterministic key derivation from seed

To match the server's `generateSecretKey(KeyType::dilithium, seed)`, client libraries MUST derive the ML-DSA-44 DRBG seed from the 16-byte XRPL seed as follows:

1. Compute `SHA-512(seed_entropy)`.
2. Take the **first 32 bytes** (`sha512Half`) as the input to ML-DSA-44's keygen DRBG seed.

The standalone Python module in `xrpld-publisher/py/xrpld_publisher/dilithium.py` currently uses 48 bytes instead of 32 (tracked in §8.9). The TypeScript publisher path is unaffected; it routes through `@transia/ripple-keypairs`, which uses the canonical first-32-byte form.

#### 3.17.3 Algorithm discrimination from key bytes

Dilithium keys have no leading version byte. Client libraries MUST discriminate the algorithm by `(usage, leading-byte, length)`:

| Usage     | Leading byte | Length | Algorithm         |
|-----------|--------------|--------|-------------------|
| private   | none         | 32     | `ecdsa-secp256k1` |
| private   | `0x00`       | 33     | `ecdsa-secp256k1` |
| private   | `0xED`       | 33     | `ed25519`         |
| private   | n/a          | 2560   | `dilithium`       |
| public    | `0xED`       | 33     | `ed25519`         |
| public    | `0x02`/`0x03`| 33     | `ecdsa-secp256k1` |
| public    | `0x04`       | 65     | `ecdsa-secp256k1` |
| public    | n/a          | 1312   | `dilithium`       |

Implementations MUST reject any key whose `(usage, leading-byte, length)` triple is not in this table.

#### 3.17.4 Node public/private encoding

Library functions that wrap `NODE_PUBLIC` / `NODE_PRIVATE` Base58 encoding (`encodeNodePublic`, `decodeNodePublic`, `encodeNodePrivate`, `decodeNodePrivate`) MUST accept a payload-length parameter. The previous `expectedLength: 33` / `expectedLength: 32` assumptions MUST be removed.

#### 3.17.5 Manifest builder

Manifest builders MUST emit the two-byte VL length prefix from §3.10 when the embedded public key is ≥193 bytes. Single-byte-only builders MUST be updated.

#### 3.17.6 UNL publisher tooling

UNL publisher tooling MUST allow the **VL master key** and the **ephemeral signing key** to be chosen independently. The `createKeys` entry point MUST accept two algorithm arguments. Tooling MUST persist the ephemeral key type alongside the public/private bytes so downstream `sign` / `verify` calls dispatch correctly.

### 3.18 Account-Level Transaction Signing

Account-level signing is supported end-to-end.

#### 3.18.1 Address derivation is key-length-agnostic

An XRPL classic address is derived as:

```
AccountID = RIPEMD-160(SHA-256(publicKey))
```

The derivation is defined over the full byte string of the public key. A 1312-byte ML-DSA-44 public key yields a 20-byte `AccountID` and a normal `r...` address. The `xrpl.js` test fixtures include `rExZWaznm67whoXmLe4xJo6i57qrQK6iPi` as a conformance vector.

#### 3.18.2 Transaction signing and verification

XRPL transactions carry `SigningPubKey` (sfSigningPubKey, tag `0x73`) and `TxnSignature` (sfTxnSignature, tag `0x74`), both serialized as variable-length blobs. The binary codec's VL prefix encoding (§3.10) handles 1-byte (≤192), 2-byte (193–12480), and 3-byte (12481–918744) forms. No codec change is required to carry a dilithium `SigningPubKey` (1312 bytes, 2-byte VL) or `TxnSignature` (up to 2420 bytes, 2-byte VL).

A node verifying a signed transaction MUST:

1. Parse `SigningPubKey` and call `publicKeyType()` (§3.5).
2. Call `verify(pubKey, hashedTxBytes, signature)`, which dispatches to the correct algorithm.

Once the `Quantum` amendment is enabled, `publicKeyType()` recognizes 1312-byte public keys and the existing transaction-verification path accepts them. Pre-amendment, the same dispatch rejects them.

#### 3.18.3 Multisign

The `Signers` array (sfSigners) contains `SignerEntry` objects, each with its own `SigningPubKey` and `TxnSignature`. Each signer's pair MAY independently be `secp256k1`, `ed25519`, or `dilithium`. The reference `xrpl.js` `multisign` path verifies each signer through `verify(pk, m, sig)`, so heterogeneous signer sets are supported.

#### 3.18.4 Batch signing

Inner transactions in a batch (XLS-56) are signed by their respective accounts; the outer batch signature attaches via `BatchSigners`. Each inner signature and the outer batch signature MAY independently be any of the three schemes. The reference `xrpl.js` `batchSigner` dispatches per-signature.

#### 3.18.5 Payment-channel claims

`signPaymentChannelClaim` / `verifyPaymentChannelClaim` accept any of the three schemes. The on-the-wire claim signature is a raw signature, length-prefixed when carried inside a transaction. Off-chain claim transports MUST carry the public key alongside the signature so the verifier can dispatch.

#### 3.18.6 Admin RPC limitation

The admin RPCs `sign` (via `keypairForSignature`) and `wallet_propose` currently reject `key_type: "dilithium"`. These are convenience endpoints; they do not affect the protocol. Clients that sign locally and submit via `submit` are unaffected. A follow-up commit on the reference branch SHOULD lift this restriction.

## 4. Rationale

### 4.1 Why ML-DSA-44 and not Falcon / SLH-DSA?

ML-DSA-44 was selected because:

- It is a NIST-standardized scheme (FIPS 204, August 2024).
- Signing and verification times are competitive with the pre-quantum schemes XRPL already uses.
- Signature size (~2.4 KB) is large but tractable on a 1 MiB TCP buffer.
- It does not require constant-time floating-point arithmetic (a deployment hazard for Falcon).
- SLH-DSA (SPHINCS+) signatures are an order of magnitude larger (~17–49 KB) and prohibitively slow to sign for the validation-per-ledger cadence.

### 4.2 Why expose dilithium everywhere a signature is verified?

ML-DSA-44 enters the codebase as a third case in the `sign` / `verify` primitives every other signing surface already routes through. Once those primitives understand the new key type, every caller supports it transparently: validator manifests, validations, proposals, peer handshakes, transaction signatures, multisign signers, batch signers, payment-channel claims. Gating any of these would require adding a key-type check that doesn't otherwise exist, and would force a second amendment to remove it.

The XRPL binary codec already uses variable-length encoding for `SigningPubKey` and `TxnSignature`. Address derivation is key-length-agnostic. There is no protocol cost to exposing dilithium at the account level; the operational cost (larger transactions, slower per-signature verification) is borne only by accounts that choose to rotate.

### 4.3 Variable-length keys

The pre-quantum codebase used fixed-size key buffers (`kSize = 33` for `PublicKey`, `32` for `SecretKey`). ML-DSA keys do not fit. Alternatives considered:

- **Polymorphism / `std::variant<>`**: would touch every call site that holds a `PublicKey` by value and change the ABI.
- **Heap allocation**: too risky for hot paths (signing, verifying, hashing) and complicates secure erasure.

A fixed-size 1312-byte buffer with an explicit `size_` member preserves value semantics, keeps `PublicKey` trivially copyable, and adds a small constant memory overhead per in-flight key.

### 4.4 Filename hashing for the publisher cache

A 1312-byte hex-encoded public key is 2624 characters. No common filesystem accepts a single filename of that length. Hashing the publisher key, even though only dilithium keys are over-length, keeps the cache lookup uniform and avoids a migration step when future key types are added.

### 4.5 No canonicality flag for ML-DSA

ECDSA over secp256k1 has the "low-S" / "fully canonical" malleability concern, which is why the XRPL signature path carries a `mustBeFullyCanonical` flag. ML-DSA signatures have no analogous malleability surface: a dilithium signature is either valid under the public key or it is not. The flag is ignored for `dilithium`.

## 5. Backwards Compatibility

This XLS introduces backwards incompatibilities, all gated by the `Quantum` amendment:

1. **Pre-amendment nodes cannot validate `dilithium` signatures.** Until the amendment is enabled, any dilithium-signed protocol message (validator manifest, validation, proposal, UNL signature, peer-handshake session signature, signed transaction including multisign/batch/paychan-claim) MUST be rejected. Operators MUST NOT switch `[validator_key_type]` to `dilithium`, and account holders SHOULD NOT rotate to a dilithium signing key, until the amendment has activated on the network they participate in.
2. **The publisher list cache filename changes.** A node upgrading to this version will not find existing cache entries under the new (hashed) names. The cache is regenerated on next refresh; no on-ledger state is affected.
3. **The `decodeBase58` 64-character limit is removed.** Downstream code relying on that early rejection MUST validate by token type and expected length instead.
4. **The `validation_create` RPC may default to `dilithium` post-activation.** Scripts parsing the resulting keypair MUST handle variable-length keys, not the previous fixed 32/33 byte assumption.
5. **Transactions signed with dilithium keys have larger `SigningPubKey` and `TxnSignature` fields.** Tools that hard-code 33-byte / 64–72-byte assumptions when parsing transaction binary form MUST be updated. The XRPL binary codec's standard VL encoding handles this transparently; only callers that bypass the codec are affected. Per-transaction byte overhead is ~3.7 KB.
6. **Admin RPCs `sign` and `wallet_propose` reject `dilithium` today.** Tooling that relies on server-side signing MUST sign client-side via `xrpl.js` or equivalent until the reference implementation lifts this gate.

## 6. Test Plan

The reference implementation includes the following new test suites, all of which MUST pass:

- `src/test/protocol/SecretKey_test.cpp`: keypair generation, signing, verification across `secp256k1`, `ed25519`, `dilithium` (random and deterministic seeds).
- `src/test/protocol/PublicKey_test.cpp`: `publicKeyType` discrimination by length and leading byte, including the 1312-byte dilithium case.
- `src/test/protocol/Seed_test.cpp`: node and account keypair generation for dilithium.
- `src/test/app/Manifest_test.cpp`: manifest serialization and verification with dilithium master and signing keys.
- `src/test/app/ValidatorKeysV2_test.cpp`, `ValidatorListV2_test.cpp`, `ValidatorSiteV2_test.cpp`: validator-key, UNL, and publisher pipelines under dilithium.
- `src/test/app/ValidatorListDRandom_test.cpp`, `ValidatorListExpiration_test.cpp`: UNL expiration and disorderly-input handling.
- `src/test/app/RCLCxPeerPos_test.cpp`, `src/test/app/STTXSigning_test.cpp`: proposal, validation, and account-level transaction signing/verification (single-sig, multisign, batch, payment-channel claim).
- `src/test/overlay/handshake_test.cpp`: peer handshake with pre-quantum and dilithium advertised keys, including cross-version interop.
- `src/test/overlay/stream_truncated_test.cpp`, `socket_buffer_test.cpp`: buffer-sizing regressions under large-signature load.
- `src/test/app/Wildcard_test.cpp`: Base58 decoder over-length input handling.

A multi-node integration test is REQUIRED:

1. A network is initialized pre-amendment with a mix of `secp256k1` and dilithium-keyed validators, with at least one account funded under a dilithium-derived `r...` address. Dilithium validators MUST be ignored and their manifests rejected; dilithium-signed transactions MUST be rejected at submission.
2. The `Quantum` amendment is activated.
3. The dilithium-keyed validators contribute to consensus and produce accepted validations; the dilithium-keyed account produces and submits a Payment, a multisign transaction (mixed signer key types), and a Batch transaction, all of which clear and apply on-ledger.

### 6.1 Client-side conformance

The following client-side suites MUST pass.

**`xrpl.js` (`dilithium` branch):**

- `packages/ripple-keypairs/test/api.test.ts`: keypair generation, signing, verification across all three algorithms; fixtures in `test/fixtures/api.json` include canonical dilithium vectors.
- `packages/ripple-keypairs/test/getAlgorithmFromKey.test.ts`: verifies the discrimination table from §3.17.3.
- Address-codec tests covering `encodeSeed`/`decodeSeed` round-trips under `DILITHIUM_SEED` (`0x22`).

**`xrpld-publisher` (`quantum` branch):**

- `py/tests/unit/test_dilithium.py`: `derive_keypair`, `sign`, `verify` against `dilithium-py`'s `ML_DSA_44`.
- `ts/test/unit/dilithium.test.ts`: same surface, TypeScript side.
- `ts/test/unit/deterministic.test.ts`: deterministic keystore generation from a fixed seed. This suite is the conformance gate for §3.17.2 and MUST be extended with vectors produced by the rippled server.

### 6.2 Cross-implementation conformance vectors

A `tests/vectors/dilithium.json` file MUST be added at the rippled root, generated by the server and asserted by every client:

```json
{
  "seed_base58": "sa...",                 // 16-byte entropy under 0x22
  "seed_entropy_hex": "...",              // 32 hex chars
  "public_key_hex": "...",                // 2624 hex chars
  "private_key_hex": "...",               // 5120 hex chars
  "node_public_base58": "n...",           // ACCOUNT_PUBLIC/NODE_PUBLIC variable-length encoding
  "account_id_base58": "r...",            // RIPEMD-160(SHA-256(publicKey)) classic address
  "message_hex": "...",
  "signature_hex": "..."                  // ≤ 4840 hex chars
}
```

Any divergence in `public_key_hex` for the same `seed_entropy_hex` is a conformance failure and MUST block release of the diverging implementation.

## 7. Reference Implementation

Three coordinated reference implementations cover the server (`xrpld`), client SDK (`xrpl.js`), and UNL publisher tooling (`xrpld-publisher`). A quantum-keyed validator requires the server change; a quantum-keyed UNL publisher additionally requires the publisher tooling; quantum-signed accounts require only the client SDK.

### 7.1 Server: `xrpld` (branch `dilithium-full`)

The single commit `xls-quantum` on `dilithium-full` adds:

- The new `KeyType::dilithium` and variable-length `PublicKey` / `SecretKey` storage.
- The bundled ML-DSA-44 (`pqcrystals_dilithium2`) reference C implementation, exposed through `extern "C"` shims and a `randombytes` adapter drawing from `xrpl::cryptoPrng`.
- A deterministic `pqcrystals_dilithium2_ref_keypair_seed` so `generateSecretKey(KeyType::dilithium, seed)` is reproducible from an XRPL `Seed`.
- A `pqcrystals_dilithium2_ref_publickey` that recovers the public key from the secret key without re-running keygen.
- All call-site changes in §3 (manifests, validations, proposals, handshakes, UNL publisher lists, node identity, RPC, and the generic transaction `sign`/`verify` dispatch).

Production files changed (non-exhaustive):

- `include/xrpl/protocol/PublicKey.h`, `SecretKey.h`, `KeyType.h`
- `src/libxrpl/protocol/PublicKey.cpp`, `SecretKey.cpp`, `STValidation.cpp`, `tokens.cpp`
- `src/libxrpl/server/Manifest.cpp`, `Wallet.cpp`
- `src/libxrpl/tx/Transactor.cpp` (header constants only)
- `src/xrpld/app/main/NodeIdentity.cpp`, `Application.cpp`
- `src/xrpld/app/consensus/RCLConsensus.cpp`, `RCLCxPeerPos.h`
- `src/xrpld/app/misc/detail/ValidatorKeys.cpp`, `ValidatorList.cpp`, `ValidatorSite.cpp`
- `src/xrpld/core/ConfigSections.h`, `detail/Config.cpp`
- `src/xrpld/overlay/detail/Handshake.cpp`, `PeerImp.cpp`
- `src/xrpld/rpc/handlers/admin/keygen/ValidationCreate.cpp`
- `include/xrpl/protocol/detail/features.macro` (the `Quantum` amendment)

### 7.2 Client SDK: `xrpl.js` (branch `dilithium`)

End-to-end dilithium support across three packages.

**`ripple-address-codec`** (`packages/ripple-address-codec/src/xrp-codec.ts`):

- `DILITHIUM_SEED = 0x22` version byte for `encodeSeed` / `decodeSeed`.
- `encodeSeed`, `decodeSeed`, and `Codec.decode` accept `'dilithium'` as a `versionType`.
- `encodeNodePublic` / `decodeNodePublic` / `encodeAccountPublic` accept an `expectedLength` parameter (default 33). New `encodeNodePrivate` / `decodeNodePrivate` for `NODE_PRIVATE` (`0x20`).

**`ripple-keypairs`** (`packages/ripple-keypairs/`):

- New signing scheme `src/signing-schemes/dilithium/index.ts`, backed by `@noble/post-quantum`'s `ml_dsa44`.
- `deriveKeypair` for dilithium uses `Sha512.half(entropy)` as the keygen seed (matches §3.17.2).
- `getAlgorithmFromKey` extended with the discrimination table from §3.17.3.
- `generateSeed` accepts `{ algorithm: 'dilithium' }`.

**`xrpl`** (`packages/xrpl/`):

- `ECDSA.ts` extends the algorithm enum with `dilithium`.
- `Wallet` and related utilities (`authorizeChannel`, `batchSigner`, `signer`, `signPaymentChannelClaim`, etc.) accept dilithium keys through the same dispatch points as `ed25519` / `ecdsa-secp256k1`.

Dependency added: `@noble/post-quantum`.

### 7.3 UNL Publisher Tooling: `xrpld-publisher` (branch `quantum`)

Python (`py/xrpld_publisher/`):

- New module `dilithium.py` wraps `dilithium-py`'s `ML_DSA_44`, exposing `derive_keypair(entropy)`, `sign(message, private_key_hex)`, `verify(message, signature_hex, public_key_hex)`. The DRBG-seed derivation in this module diverges from the server (see §8.9).
- `validator.py`: `generate_keystore(algorithm)` accepts `"dilithium"`; `sign()` dispatches by hex key length; `KeystoreInterface` carries `ephemeral_public_key`, `ephemeral_private_key`, `ephemeral_key_type` so master/VL and ephemeral keys can be distinct algorithms.
- `publisher.py`: `create_keys(vl_algorithm, eph_algorithm)` takes per-key algorithm arguments; signature verification dispatches by ephemeral-key length.

TypeScript (`ts/src/`):

- `validator.ts`: `generateKeystore('dilithium')`, `getAlgorithmFromKeyLength`, and a `generateManifest` that emits the two-byte VL length prefix (§3.10) when an embedded key is ≥193 bytes.
- `publisher.ts`: `createKeys(vlAlgorithm, ephAlgorithm)` mirroring the Python entry point.

Dependencies added: `dilithium-py` (Python), `@noble/post-quantum` via the `ripple-keypairs` upgrade (TypeScript).

## 8. Security Considerations

### 8.1 Trust assumptions

This XLS relies on the unforgeability of ML-DSA-44 under the assumptions of FIPS 204. The bundled reference implementation is the CRYSTALS team's `ref` code path. Implementers SHOULD periodically re-evaluate the choice of implementation against the constant-time and side-channel properties their deployment requires.

### 8.2 RNG sourcing

ML-DSA signing is randomized. The reference implementation wires `randombytes` to `beast::rngfill(buf, size, xrpl::cryptoPrng())`. A degraded `cryptoPrng()` (insufficient startup entropy, misconfigured FIPS mode) puts dilithium signing at risk. The same caveat applies to ECDSA's RFC 6979 nonce derivation in non-deterministic implementations, so this is not a new exposure. Operators MUST verify the host RNG is seeded before the validator begins signing.

### 8.3 Secret-key handling

ML-DSA-44 secret keys are 2560 bytes (eighty times the size of an Ed25519 secret key). The reference implementation pins them inside the existing `SecretKey` buffer and `secureErase`s temporary copies. HSM operators MUST confirm their HSM accepts a 2560-byte secret without truncation and MUST verify the HSM's PQC algorithm matches ML-DSA-44 specifically (not a similarly named variant).

### 8.4 Larger signatures, more network surface

A `TMProposeSet` with a dilithium signature is ~2.4 KB larger than its secp256k1 counterpart. A dilithium-signed transaction is ~3.7 KB larger. With ~150 validators each emitting a proposal per ledger, gossip amplification, and a long tail of dilithium-signed transactions, peer bandwidth and serialization cost rise materially. The 1 MiB socket buffer change (§3.15) mitigates TLS stream-truncation errors observed when many large signatures arrive simultaneously. Implementations SHOULD monitor proposal- and transaction-processing latency after activation.

### 8.5 Denial of service via oversized signatures

Without the per-key-type length cap of §3.12, a malicious peer could submit arbitrarily large "signatures" and force the receiver into expensive ML-DSA verification on garbage. The 2420-byte cap binds the cost of each verification attempt. Transaction-level signatures are similarly bounded by `pqcrystals_dilithium2_BYTES = 2420`; the codec MUST enforce this bound when parsing `TxnSignature` for a 1312-byte `SigningPubKey`. `kFeeInvalidSignature` continues to charge a per-attempt penalty against the source peer.

### 8.6 Filesystem path safety

The publisher-cache filename change (§3.11) replaces an arbitrarily-long hex string with a fixed 64-character SHA-256 hex digest. This fixes the out-of-spec filename length and removes an unbounded path-construction surface.

### 8.7 Amendment activation and split-brain risk

If `[validator_key_type] = dilithium` is set on a validator's host **before** the `Quantum` amendment activates, that validator's validations will be rejected by every peer and the validator will appear offline. The validator's UNL position will be lost during the silent period. Operators MUST either activate the amendment first or rotate via a fresh manifest the moment the amendment is enabled, not before.

The same risk applies to account-level rotation. An account holder who `SetRegularKey`s to a dilithium-derived address pre-activation, then signs with that key, will produce transactions no peer accepts. Account holders SHOULD retain the pre-quantum key as a fallback regular key until amendment activation is confirmed.

### 8.8 Cryptographic agility

This XLS adds one post-quantum scheme. It does not establish a general key-type negotiation framework. A future XLS adding ML-DSA-65 / ML-DSA-87, or replacing ML-DSA entirely, will need to revisit `KeyType`, `publicKeyType`, and the per-message length tables in §3.12. Implementations SHOULD keep the discriminator for new key types centralized (a single `publicKeyType(Slice)` function).

### 8.9 Cross-implementation seed-derivation divergence

One of the four reference code paths diverges in how it expands a 16-byte XRPL seed into the ML-DSA-44 keygen DRBG seed:

| Stack | Derivation | Status |
|---|---|---|
| `xrpld` server | `sha512Half(seed)`, first 32 bytes of SHA-512 | ✓ canonical |
| `xrpl.js` (`dilithium` branch) | `Sha512.half(entropy)`, first 32 bytes | ✓ matches server |
| `xrpld-publisher` TypeScript (uses `@transia/ripple-keypairs`) | first 32 bytes | ✓ matches server |
| `xrpld-publisher` Python (`xrpld_publisher/dilithium.py`) | first **48** bytes of SHA-512 | ✗ diverges |

An operator who generates a UNL publisher key with the Python module and tries to re-derive it from the same XRPL seed using rippled, xrpl.js, or the TypeScript publisher will get a different keypair. A published UNL would not verify under the publisher key the operator believes they have. The TypeScript publisher path is unaffected; it routes through the same `ripple-keypairs` code as xrpl.js.

Before this XLS reaches `Final`, the Python module MUST be patched to use the first 32 bytes of SHA-512, and `tests/vectors/dilithium.json` (§6.2) MUST be wired as a known-answer test in all four code paths. Tracked in `tasks/todo.md` in the rippled repo.

### 8.10 Accounts that do not rotate remain pre-quantum

This XLS makes the post-quantum scheme available at the account level; it does not migrate existing accounts. Accounts that continue to sign with secp256k1 or Ed25519 retain their pre-quantum exposure. An adversary who breaks the underlying scheme can forge transactions on those accounts. Account holders who want long-term post-quantum integrity MUST rotate to a dilithium key (via `SetRegularKey` to a dilithium-derived address, or by sending funds to a freshly-derived dilithium account). Wallets, exchanges, and custodians SHOULD provide rotation tooling.

### 8.11 On-ledger storage growth from per-transaction signatures

A dilithium-signed transaction carries ~3.7 KB more on the wire than a secp256k1-signed one. Per-account multisign with N dilithium signers grows linearly: ~N × 3.7 KB of `Signers` field. Implementations SHOULD monitor ledger size growth after activation. Operators SHOULD price reserves and fees accordingly through standard fee-voting mechanisms. This XLS does not adjust the fee schedule.

# Appendix

## Appendix A: FAQ

### A.1: Does this XLS cover account signatures?

Yes. ML-DSA-44 is available at every signing surface: validator manifests, validations, consensus proposals, UNL signatures, peer handshakes, node identities, and account-level transaction signing including multisign, batch signing, and payment-channel claims. Address derivation (`RIPEMD-160(SHA-256(pubkey))`) is key-length-agnostic, so a dilithium public key yields a normal `r...` address. The XRPL binary codec's variable-length field encoding handles the larger `SigningPubKey` (1312 bytes) and `TxnSignature` (≤2420 bytes) without protocol changes.

This XLS does not force anyone to migrate. Existing accounts continue to use whichever scheme they were created with; only newly-derived or explicitly-rotated keys use dilithium.

### A.2: Will this break existing `secp256k1` validators?

No. The `Quantum` amendment is `DefaultNo` and the new `[validator_key_type]` defaults to `secp256k1`. Existing validators with no configuration changes operate exactly as before.

### A.3: Why ML-DSA-44 and not ML-DSA-65 or ML-DSA-87?

Higher parameter sets give larger security margins but larger signatures (3.3 KB and 4.6 KB respectively) and slower signing. ML-DSA-44 meets NIST Category 2 (≈AES-128), which exceeds the practical strength of secp256k1 today. A follow-on XLS may offer the higher sets as opt-in.

### A.4: What happens if a dilithium signature briefly exceeds 2420 bytes?

It cannot. ML-DSA-44 signatures are bounded by `pqcrystals_dilithium2_BYTES = 2420` by construction. The cap in §3.12 reflects that algorithmic ceiling, not a soft network limit.

### A.5: Can an HSM be used for dilithium validator keys?

Yes, if the HSM exposes a ML-DSA-44 (FIPS 204) interface and accepts the 2560-byte secret-key representation used by the reference implementation. Commercial HSM support for ML-DSA is uneven; operators MUST verify their HSM's algorithm and key-encoding before relying on it for a production validator.

### A.6: Does the dilithium key type change the node's `n...` address?

Yes. The node address is derived from the public key. Dilithium public keys produce a different on-the-wire encoding (1312 bytes vs. 33) and therefore a different base58 `n...` string. An operator who rotates from `secp256k1` to `dilithium` is, from the network's point of view, a new node identity. Existing peer-finder slots and trusted-peer entries referencing the old `n...` must be updated.
