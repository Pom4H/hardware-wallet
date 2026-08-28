# Keys and cryptography

The wallet core describes key identity and cryptographic work without owning secret
bytes. Secret creation and passphrase expansion live in `key-lifecycle`; hierarchical
derivation lives in `hd-key-backend`; signing and hashing live in `crypto-runtime`.

## Authorized key binding

A host or chain request never supplies `WalletContextId` for a cryptographic operation.
It may request only:

```text
KeyTarget = account + relative derivation path + purpose
```

After PIN/passphrase authorization, the reducer exposes `ExecutionContext`. It has no
public constructor and binds the target to the wallet context already stored in the
unlocked session:

```text
untrusted KeyTarget
        +
ExecutionContext from unlocked State
        |
        v
    KeyLocator
```

`KeyLocator` fields are private. A locked state cannot produce the capability, and an
in-flight operation cannot be redirected from a hidden wallet to the base wallet by
changing host bytes.

## Root entropy and wallet contexts

`key-lifecycle` owns the transition from device entropy or recovery material to an
installed root:

```text
EntropySource / recovery mnemonic
               ↓
       staged BIP-39 entropy
               ↓
 backup + PIN onboarding succeeds
               ↓
      RootSecretStore commit
               ↓
 normalized passphrase at unlock
               ↓
  ephemeral WalletContext + 64-byte seed
```

The root is not persisted while the backup is only being displayed or challenged.
`PersistProvisioning` is the first point at which the runtime may perform a durable
commit. A failed commit leaves the same staged root available for retry.

The passphrase and 64-byte seed are ephemeral and never enter `wallet-core::State`.
Current fixed-capacity input accepts ASCII passphrases, which are already NFKD. Arbitrary
Unicode remains fail-closed until a bounded or streaming NFKD normalizer is implemented.

See [`KEY_LIFECYCLE.md`](KEY_LIFECYCLE.md).

## Accounts and derivation

`DerivationPath` is fixed-capacity and allocation-free. Each `ChildNumber` stores index
and hardened state separately, so generic code does not embed BIP-32 integer encoding.

`AccountDescriptor::root` is trusted, device-owned metadata. A request supplies only a
path relative to that root. `hd-key-backend` is bound to one `AccountDescriptor` and
rejects a locator with a different wallet or account.

Implemented families:

```text
Secp256k1Bip32
Ed25519Slip10
```

For secp256k1, the backend uses BIP-32 with `k256`. For Ed25519 it uses the
hardened-only SLIP-0010 recurrence over HMAC-SHA512; non-hardened children fail closed.

The master seed, intermediate child keys and SLIP-0010 chain codes use fixed-capacity
zeroizing storage. A derived child secret is materialized only for the approved
operation and passed to the current one-key software backend. A secure-element backend
may later replace this composition without changing chain adapters.

CI includes official BIP-32 and SLIP-0010 vectors and full local-network paths for:

```text
Bitcoin   m/84'/1'/0'/0/0
Ethereum  m/44'/60'/0'/0/0
Solana    m/44'/501'/0'/0'
```

Each flow begins with deterministic device entropy, creates a BIP-39 wallet, opens a
wallet context, derives the child, funds its public address and signs with that same
child. The node does not provide the wallet-under-test key or signature.

## Generic cryptographic contract

The chain/runtime boundary understands:

```text
DerivePublicKey(key, format)
Hash(algorithm, payload)
Sign(key, scheme, prehash, payload)
```

`PayloadId` is an opaque handle. Transaction, message and digest bytes remain owned by
the active chain execution rather than the generic wallet state.

The vocabulary is broader than the first software backend:

- curves: secp256k1, Ed25519, P-256, sr25519, BLS12-381, custom;
- signatures: ECDSA, secp256k1 Schnorr, Ed25519, sr25519, BLS12-381, custom;
- hashes: SHA-256, double SHA-256, HASH160, Keccak-256, BLAKE2b, SHA-512/256, custom;
- public keys: raw, compressed, uncompressed, x-only, extended, custom.

This is a protocol vocabulary, not a promise that every hardware target implements
every algorithm. A runtime must advertise concrete capabilities and fail closed for the
rest.

## Current software runtime

`hardware-wallet-crypto-runtime` implements:

- compressed, uncompressed, raw and x-only secp256k1 public keys;
- raw Ed25519 public keys;
- deterministic low-S secp256k1 ECDSA;
- recoverable ECDSA for Ethereum;
- Ed25519 signing;
- SHA-256, double-SHA256, HASH160, Keccak-256 and SHA-512/256.

`SoftwareKeyBackend` binds exactly one secret to one authorized
`WalletContextId + KeyTarget` and zeroizes its stored secret on drop. It is a development
and emulation backend, not a production secret store.

## Production backend requirements

The remaining key-security work is hardware composition rather than missing wallet
semantics:

- bind `EntropySource` to the chosen MCU or secure element and define health tests;
- implement atomic, authenticated `RootSecretStore` persistence;
- decide whether root, seed or derived keys may enter MCU memory;
- implement a secure-element-backed derive/sign backend where the selected part allows;
- define debug-lock, fault-injection and memory-erasure policy;
- expose hardware capability discovery to chain adapters;
- measure BIP-39, derivation and signing cycles on the actual target.

The project must not claim “the seed never enters the MCU” until a concrete backend and
board prove it.

## Chain boundary

Chain adapters receive `ExecutionContext` only after review and approval. They request
generic crypto operations, validate the returned public key against transaction-owned
identity, construct protocol hashes themselves and only then request a signature.

Bitcoin, Ethereum and Solana are the initial architecture probes because they exercise
UTXO, account and message models across secp256k1 and Ed25519 without putting any of
those rules into `wallet-core`.
