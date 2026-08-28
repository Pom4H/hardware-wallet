# Hardware Wallet

A minimal, auditable, chain-agnostic hardware wallet built in Rust.

The project is a reference device, not a wallet for one blockchain. The trusted
domain owns generic wallet behavior — provisioning, authorization, sessions,
accounts, user approval, security policy and operation lifecycle — while chain
parsing and signing rules remain isolated.

> **Experimental:** do not use this repository to protect real funds. The domain
> and software cryptographic path are exercised end-to-end, but production
> firmware, hardware-backed entropy, secure storage, boot security and a reviewed
> PCB do not exist yet.

## Implemented path

The repository currently proves this complete software flow:

```text
device-owned entropy
        ↓
BIP-39 recovery mnemonic
        ↓
atomic root-store capability
        ↓
optional passphrase wallet context
        ↓
BIP-32 secp256k1 / SLIP-0010 Ed25519
        ↓
device-owned transaction review
        ↓
local signature
        ↓
Bitcoin Core / Anvil / Agave validation
```

Bitcoin Core, Anvil and Agave provide clean local networks and funding only.
They do not hold or use the wallet-under-test private keys.

## Domain

`wallet-core` is a heap-free deterministic reducer:

```text
State + Event -> State + Effect
```

It models create and recovery, backup verification, PIN policy, passphrase
wallets, host-bound sessions, trusted-host pairing, account/key locators,
device-owned review, physical confirmation, settings, cancellation, reboot,
tamper handling and factory reset.

The domain never stores seed, PIN, passphrase, private key or raw transaction
bytes.

## Secret lifecycle

`key-lifecycle` maps onboarding and unlock Effects to secret-bearing operations
without moving secrets into reducer state.

- 12/15/18/21/24-word BIP-39 wallets;
- device-owned `EntropySource`;
- staged roots that are not installed until `PersistProvisioning`;
- retryable failed durable commit;
- BIP-39 recovery back to the same root;
- passphrase-derived ephemeral `WalletContext` and 64-byte seed;
- zeroizing root, passphrase and seed buffers;
- `RootSecretStore` contract for atomic commit, authenticated reads and durable
  wipe.

The included memory store and deterministic entropy source are test
infrastructure only.

## Keys and cryptography

The host selects only a relative `KeyTarget`:

```text
account + relative derivation path + purpose
```

Only an unlocked reducer state can create `ExecutionContext`, which binds that
target to the active base or hidden-wallet `WalletContextId`.

Implemented software backends:

- BIP-32 secp256k1;
- hardened-only SLIP-0010 Ed25519;
- compressed, uncompressed, raw and x-only secp256k1 public keys;
- raw Ed25519 public keys;
- deterministic low-S secp256k1 ECDSA, including Ethereum recovery id;
- Ed25519 signatures;
- SHA-256, double-SHA256, HASH160, Keccak-256 and SHA-512/256.

The software key backend is for tests, emulation and architecture validation.
The same chain interface is intended to accept a secure-element backend later.

## Chain boundary

A chain adapter owns every chain-specific security decision:

```text
untrusted request
      ↓
parse and validate
      ↓
human-readable Review
      ↓
wallet-core approval
      ↓
ChainExecution
      ↓
derive / hash / sign
```

The core must never grow branches such as `if chain == bitcoin`.

Current deliberately narrow, fail-closed flows:

| Chain | Reviewed subset | Local compatibility target |
| --- | --- | --- |
| Bitcoin | PSBT v0, one native P2WPKH input/output, `SIGHASH_ALL`, BIP143 | Bitcoin Core 31.1 regtest |
| Ethereum | EIP-1559 native transfer, empty calldata and access list | Anvil / Foundry 1.8.0 |
| Solana | legacy one-signer System Program transfer | Agave 4.2.1 validator |

Unsupported transaction classes are rejected rather than blind-signed.

## Deterministic integration tests

`Pom4H/chain-sandbox` starts disposable local networks. Each chain job runs:

```text
entropy
→ BIP-39
→ persisted root
→ wallet context
→ HD child
→ funded address
→ parse and review
→ repository-produced signature
→ network acceptance
```

Required CI has no public devnet, faucet, RPC credential or node-provided
signing dependency.

## Measured hardware class

`firmware-budget` links the full trusted software surface as one Cortex-M ELF.
The current baseline is:

| Target profile | Linked trusted-core Flash | A/B projection | RAM projection |
| --- | ---: | ---: | ---: |
| Cortex-M4/M7 | 226.4 KiB | 936 KiB | 82 KiB |
| Cortex-M33 | 227.4 KiB | 944 KiB | 82 KiB |

The practical selection floor is therefore:

```text
production with rollback-safe A/B update:
  Flash >= 1 MiB
  RAM   >= 128 KiB

single-slot prototype:
  Flash >= 512 KiB
  RAM   >= 128 KiB
```

The RAM floor deliberately exceeds the current 96 KiB calculated class because
peak stack, interrupt nesting, USB and secure-element driver state have not yet
been measured. Clock frequency is not guessed from host benchmarks; Firmverse
or evaluation-board cycle counts will determine it.

`hardware-budget.toml` holds the reviewed margins and reserves.
`mcu-requirements.toml` holds hard peripheral/security requirements.
`tools/mcu_candidate.py` checks manually verified candidate descriptions against
both the generated budget and those requirements.

See:

- [`docs/HARDWARE_BASELINE.md`](docs/HARDWARE_BASELINE.md)
- [`docs/HARDWARE_REQUIREMENTS.md`](docs/HARDWARE_REQUIREMENTS.md)

## Workspace

```text
crates/
  wallet-core/        lifecycle, auth, policy and operation reducer
  chain-api/          fixed-capacity review/execution/crypto contract
  key-lifecycle/      entropy, BIP-39, passphrase contexts and root-store contract
  crypto-runtime/     generic hash/sign executor and software key backend
  hd-key-backend/     BIP-32 and hardened SLIP-0010
  chain-bitcoin/      strict PSBT/P2WPKH adapter
  chain-ethereum/     strict EIP-1559 native-transfer adapter
  chain-solana/       strict System Program transfer adapter
  firmware-budget/    linked Cortex-M resource probe, not product firmware

tools/
  hardware_budget.py  ELF-to-MCU memory projection
  mcu_candidate.py    hard-requirement check and preferred-feature score
```

## Target device direction

The reference product is still expected to use:

- Cortex-M-class MCU;
- 128×64 display;
- two physical buttons;
- USB device transport;
- dedicated secure element;
- USB-only, battery-free power.

The MCU and secure element will be selected only after resource, timing, power
and security contracts are tested against concrete parts. Until then the
project must not claim that seed or private keys never enter the MCU.

## Documentation

- [`docs/DOMAIN.md`](docs/DOMAIN.md)
- [`docs/KEYS.md`](docs/KEYS.md)
- [`docs/KEY_LIFECYCLE.md`](docs/KEY_LIFECYCLE.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)
- [`docs/HARDWARE_BASELINE.md`](docs/HARDWARE_BASELINE.md)
- [`docs/HARDWARE_REQUIREMENTS.md`](docs/HARDWARE_REQUIREMENTS.md)

## License

MIT.
