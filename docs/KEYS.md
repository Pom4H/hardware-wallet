# Keys and cryptography

The wallet core describes keys and cryptographic work without owning any secret bytes.
A `WalletContextId` identifies the active base/passphrase wallet, `AccountId` identifies
an account inside that context, and `KeyTarget` describes an account/path/purpose relative
to whichever wallet is currently authorized.

## Authorized key binding

A host or chain request never supplies `WalletContextId` for a cryptographic operation.
It may request only a `KeyTarget`:

```text
account + relative derivation path + purpose
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

## Accounts and derivation

`DerivationPath` is fixed-capacity and allocation-free. Each `ChildNumber` stores the
index and hardened bit separately so chain modules do not need to smuggle BIP-32 bit
encoding into the generic model.

`AccountDescriptor::root` is trusted, device-owned account metadata. A request supplies
only a path relative to that root. The current `hd-key-backend` is bound to exactly one
`AccountDescriptor` and rejects a `KeyLocator` whose wallet context or account id does
not match it.

The backend currently implements two key families:

```text
Secp256k1Bip32
Ed25519Slip10
```

For secp256k1 it uses the heap-free generic engine from `bip32` with the project's
current `k256` implementation as its private/public-key provider. For Ed25519 it uses
the hardened-only SLIP-0010 recurrence over HMAC-SHA512. Non-hardened Ed25519 children
fail closed.

The master seed is kept in fixed-capacity storage and zeroized on drop. Intermediate
SLIP-0010 keys and chain codes use zeroizing buffers. A derived child secret is turned
into the existing one-key `SoftwareKeyBackend` for the approved operation. That is the
host/emulator composition path; a future secure-element backend can replace it without
changing chain adapters.

CI includes the official BIP-32 and SLIP-0010 derivation vectors and verifies complete
HD-derived network flows for:

```text
Bitcoin   m/84'/1'/0'/0/0
Ethereum  m/44'/60'/0'/0/0
Solana    m/44'/501'/0'/0'
```

The local node funds the public address produced from the derived key, then the same
child key signs the reviewed transaction. The node never provides the wallet-under-test
private key or signature.

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
every algorithm. A runtime must fail closed when a requested operation is unsupported.

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

The chain E2Es execute these operations against child secrets produced by
`hd-key-backend`. Bitcoin Core, Anvil and Agave only provide local chain state,
funding/faucet services, validation and broadcast.

Production key lifecycle work still includes hardware entropy, mnemonic/recovery
material to seed conversion, passphrase-derived wallet seeds, persistent or
secure-element-backed secret storage, stronger memory-erasure guarantees and hardware
capability discovery.

## Chain boundary

Chain adapters receive `ExecutionContext` only at `prepare_execution`, after review and
approval. They use `CryptoOperation` rather than touching a private key or hashing
backend directly. A chain-specific execution can therefore validate a derived public
key, hash one or more protocol-owned payloads, and only then request a signature.

Bitcoin, Ethereum and Solana are the initial architecture probes because together they
exercise UTXO/account/message models and secp256k1/Ed25519 signing without putting any of
those rules into `hardware-wallet-core`.
