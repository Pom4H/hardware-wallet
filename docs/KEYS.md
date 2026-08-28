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

The current software backend binds one concrete secret to one `KeyTarget`; it does not
yet implement BIP-32 or SLIP-0010 derivation. HD derivation belongs behind the crypto
runtime boundary so chain parsers and wallet state do not change when a software key
backend is replaced by a secure element or another key store.

## Generic crypto operations

The runtime boundary understands three generic operations:

```text
DerivePublicKey(key, format)
Hash(algorithm, payload)
Sign(key, scheme, prehash, payload)
```

`PayloadId` is an opaque handle. Transaction/message/digest bytes remain outside the
wallet state machine. This keeps reducer state copyable, deterministic and free of
secret or unbounded data.

Supported vocabulary is intentionally broader than the initial adapters:

- curves: secp256k1, Ed25519, P-256, sr25519, BLS12-381, custom;
- signatures: ECDSA, secp256k1 Schnorr, Ed25519, sr25519, BLS12-381, custom;
- hashes: SHA-256, double SHA-256, HASH160, Keccak-256, BLAKE2b, SHA-512/256, custom;
- public-key formats: raw, compressed, uncompressed, x-only, extended, custom.

This is a vocabulary, not a promise that every reference hardware target implements
every algorithm. A runtime advertises concrete capabilities and must fail closed when a
requested operation is unsupported.

## Crypto runtime

`hardware-wallet-crypto-runtime` is the first real executor of this contract. Its
`SoftwareKeyBackend` is deliberately a development backend: one secret is bound to one
`WalletContextId + KeyTarget`, stored in a zeroizing wrapper, and may only be used when
the `KeyLocator` produced by the authorized wallet session matches both values.

The current backend implements:

- compressed/uncompressed/raw/x-only secp256k1 public keys;
- raw Ed25519 public keys;
- deterministic low-S secp256k1 ECDSA, including recovery ID for Ethereum;
- Ed25519 signing;
- SHA-256, double-SHA256, HASH160, Keccak-256 and SHA-512/256.

The three chain E2Es now use this runtime to produce their signatures. Bitcoin Core,
Anvil and Agave only provide deterministic local chain state and verify/broadcast the
resulting transactions; they do not sign on behalf of the hardware-wallet code.

A production backend must additionally own hardware entropy, master-secret lifecycle,
HD derivation, persistent or secure-element key storage, stronger zeroization guarantees,
and capability discovery for algorithms supported by the selected hardware.

## Accounts

`AccountDescriptor` is metadata, not an unbounded account database. Hardware wallets
may choose to persist accounts, derive them on demand, or let the host maintain account
catalogues. The trusted device still validates every key target used for address display
or signing.

## Chain boundary

Chain adapters receive `ExecutionContext` only at `prepare_execution`, after review and
approval. They use `CryptoOperation` rather than touching a private key or hashing
backend directly. A chain-specific execution can therefore validate a derived public
key, hash one or more protocol-owned payloads, and only then request a signature.

Bitcoin, Ethereum and Solana are the initial architecture probes because together they
exercise UTXO/account/message models and secp256k1/Ed25519 signing without putting any of
those rules into `hardware-wallet-core`.
