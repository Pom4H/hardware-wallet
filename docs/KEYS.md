# Keys and cryptography

The wallet core describes keys and cryptographic work without owning any secret bytes.
A `WalletContextId` identifies the active base/passphrase wallet, `AccountId` identifies
an account inside that context, and `KeyTarget` describes an account/path/purpose relative
to whichever wallet is currently authorized.

## Authorized key binding

A host or chain request never supplies `WalletContextId` for a cryptographic operation.
It may request only a `KeyTarget`:

```text
account + derivation path + purpose
```

After PIN/passphrase authorization, the reducer exposes an `ExecutionContext`. This type
has no public constructor. It binds the requested target to the wallet context already
stored in the unlocked session:

```text
untrusted KeyTarget
        +
ExecutionContext from unlocked State
        |
        v
    KeyLocator
```

`KeyLocator` fields are private. This makes the active base/hidden wallet context a
capability derived from authorization rather than another host-controlled parameter.
A locked state cannot produce an `ExecutionContext`.

## Derivation

`DerivationPath` is fixed-capacity and allocation-free. Each `ChildNumber` stores the
index and hardened bit separately so chain modules do not need to smuggle BIP-32 bit
encoding into the generic model.

The core intentionally does not decide whether a path is valid for Bitcoin, Ethereum,
Solana or another chain. The chain adapter validates its own path policy before it
creates a key target for execution.

## Generic crypto operations

The runtime boundary understands two generic operations:

```text
DerivePublicKey(key, format)
Sign(key, scheme, prehash, payload)
```

`PayloadId` is an opaque handle. Transaction/message/digest bytes remain outside the
wallet state machine. This keeps reducer state copyable, deterministic and free of
secret or unbounded data.

Supported vocabulary is intentionally broader than the initial adapters:

- curves: secp256k1, Ed25519, P-256, sr25519, BLS12-381, custom;
- signatures: ECDSA, secp256k1 Schnorr, Ed25519, sr25519, BLS12-381, custom;
- hashes: SHA-256, double SHA-256, Keccak-256, BLAKE2b, SHA-512/256, custom;
- public-key formats: raw, compressed, uncompressed, x-only, extended, custom.

This is a vocabulary, not a promise that every reference hardware target implements
every algorithm. A runtime advertises concrete capabilities and must fail closed when a
requested operation is unsupported.

## Accounts

`AccountDescriptor` is metadata, not an unbounded account database. Hardware wallets
may choose to persist accounts, derive them on demand, or let the host maintain account
catalogues. The trusted device still validates every key target used for address display
or signing.

## Chain boundary

Chain adapters receive `ExecutionContext` only at `prepare_execution`, after review and
approval. They should use `CryptoOperation` when a request reduces to a standard key
operation. They may keep a chain-specific execution type for streaming transactions,
multi-input signing, multisig protocols or other workflows that require several crypto
steps.

Bitcoin, Ethereum and Solana are the initial architecture probes because together they
exercise UTXO/account models, secp256k1 ECDSA/Schnorr, typed data and Ed25519-style
accounts without putting any of those rules into `hardware-wallet-core`.
