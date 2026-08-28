# Hardware Wallet

A minimal, auditable, chain-agnostic hardware wallet built in Rust.

The project is a reference device, not a wallet for one specific blockchain. The
trusted core owns generic wallet behavior — provisioning, authorization, sessions,
accounts, key locators, user approval, security policy and operation lifecycle — while
chain-specific parsing, review and cryptographic rules live in isolated modules.

> **Status:** the domain, a software cryptographic runtime, and three narrow reference
> chain flows are implemented and exercised end-to-end in CI. Bitcoin Core, Anvil and
> Agave validate transactions signed by this repository's own runtime; they are no
> longer used as reference signers. The project is still experimental and must not be
> used to protect real funds.

## What the core models

- create a new wallet and generate key material;
- recover from mnemonic, Shamir, or a future recovery format;
- mandatory backup display + verification for newly generated wallets;
- persistent generated/recovered wallet and backup-verification metadata;
- PIN setup with durable monotonic retry accounting and optional wipe on exhaustion;
- reboot-safe restoration that always returns provisioned wallets to a locked state;
- optional/required passphrase wallets represented by opaque wallet contexts;
- host- and wallet-context-bound unlock sessions;
- device-owned trusted-host resolution, pairing and revocation;
- automatic locking on disconnect/expiry;
- account identifiers and fixed-capacity hierarchical derivation paths;
- generic derive/hash/sign crypto operations across multiple schemes;
- address display, public-key export and account creation operations;
- transaction, message, typed-data, arbitrary-data and custom chain operations;
- device-owned review before execution;
- mandatory physical confirmation for every private-key operation;
- blind-signing policy (disabled by default);
- physically confirmed, persist-before-apply security settings;
- cancellation, request correlation and stale-callback rejection after lock/reboot;
- PIN change, backup verification and factory reset;
- runtime failure and tamper handling.

## Architecture

```text
untrusted host request
        │
        ▼
   Device Protocol
        │
        ▼
 chain-specific parser
        │
        ├── human review
        └── ReviewPlan
              │
              ▼
      Hardware Wallet Core
      State + Event -> State + Effect
              │
              ▼
      approved ChainExecution
              │
      ┌───────┼────────┐
      ▼       ▼        ▼
 derive     hash      sign
 pubkey               payload
      │       │        │
      └───────┼────────┘
              ▼
         Crypto Runtime
              │
              ▼
     key backend / secure element
```

`ChainExecution` is intentionally multi-step. A chain can derive and validate the
actual wallet public key, hash protocol-specific payloads, and only then request a
signature. Raw transactions and messages stay outside `wallet-core::State`.

The core must never contain `if chain == bitcoin` / `if chain == ethereum` branches.
It never stores seed, PIN, passphrase, private key or raw transaction bytes, and it
never accepts a host-provided signing digest as trusted input.

## Crypto runtime

`crypto-runtime` executes the generic operations requested by an already-approved
chain execution. The current `SoftwareKeyBackend` is intentionally small: it binds one
secret to one authorized `WalletContextId + KeyTarget`, zeroizes its stored secret on
drop, implements secp256k1 ECDSA, Ed25519, SHA-256, double-SHA256, HASH160, Keccak-256
and SHA-512/256, and fails closed for unsupported algorithms or a mismatched wallet/key.

This software backend is for tests, emulation and architecture validation. It is not a
production secret store. HD derivation, persistent key storage, secure-element-backed
keys and hardware entropy are separate backend responsibilities still to be implemented.

## Validated reference flows

| Chain | Current fully reviewed subset | Local compatibility target |
| --- | --- | --- |
| Bitcoin | PSBT v0, 1-in/1-out native P2WPKH, `SIGHASH_ALL`, BIP143 | Bitcoin Core 31.1 regtest |
| Ethereum | EIP-1559 native ETH transfer, empty calldata/access list | Anvil / Foundry 1.8.0 |
| Solana | legacy one-signer System Program transfer | Agave 4.2.1 local validator |

Each adapter deliberately rejects transaction classes it cannot yet independently
parse and explain. See the per-chain `SUPPORTED.md` files for the exact fail-closed
boundary.

The GitHub `Chain integration` workflow starts disposable local nodes through
`Pom4H/chain-sandbox`, runs each adapter in a separate job, executes every requested
crypto operation with `crypto-runtime`, broadcasts the resulting transaction, and
verifies acceptance by the local chain. Required CI does not depend on public devnets,
faucets, third-party RPC credentials, or node-provided signing.

## Workspace

```text
crates/
  wallet-core/        no_std lifecycle, auth, keys, policy and operation state machine
  chain-api/          heap-free parse/review/multi-step execution contract
  crypto-runtime/     no_std generic crypto executor + software key backend
  chain-bitcoin/      strict PSBT/P2WPKH reference adapter
  chain-ethereum/     strict EIP-1559 native-transfer reference adapter
  chain-solana/       strict System Program transfer reference adapter

docs/
  DOMAIN.md           state machine and invariants
  KEYS.md             account, derivation and generic cryptographic model
  SECURITY.md         trust boundaries and fail-closed rules
```

Bitcoin, Ethereum and Solana are the initial architecture probes because they exercise
very different UTXO/account/message and ECDSA/Ed25519 models. Additional chains must be
addable without changing the wallet state machine.

## Core rule

```text
State + Event -> State + Effect
```

The runtime executes effects and feeds results back as events. The same domain logic
can therefore run in pure tests, a firmware sandbox, co-simulation, and later the real
board.

See [`docs/DOMAIN.md`](docs/DOMAIN.md), [`docs/KEYS.md`](docs/KEYS.md) and
[`docs/SECURITY.md`](docs/SECURITY.md).

## Target hardware

Initial reference direction:

- Cortex-M-class MCU;
- 128×64 display;
- two physical buttons;
- USB device transport;
- dedicated secure element;
- USB-powered, battery-free design.

The exact MCU and secure-element responsibility are intentionally not frozen yet.

## License

MIT.
