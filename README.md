# Hardware Wallet

A minimal, auditable, chain-agnostic hardware wallet built in Rust.

The project is a reference device, not a wallet for one specific blockchain. The
trusted core owns generic wallet behavior — provisioning, authorization, sessions,
user approval, security policy and operation lifecycle — while chain-specific parsing,
review and cryptographic rules live in isolated modules.

> **Status:** architecture and domain implementation in progress. Do not use this
> project to protect real funds.

## What the core already models

- create a new wallet and generate key material;
- recover from mnemonic, Shamir, or a future recovery format;
- mandatory backup display + verification for newly generated wallets;
- PIN setup, retry accounting, optional wipe on exhaustion;
- optional/required passphrase wallet contexts;
- host-bound unlock sessions and automatic locking on disconnect/expiry;
- trusted-host pairing;
- address display, public-key export and account creation operations;
- transaction, message, typed-data, arbitrary-data and custom chain operations;
- device-owned review before execution;
- mandatory physical confirmation for every private-key operation;
- blind-signing policy (disabled by default);
- cancellation and request-id correlation;
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
       ┌──────┼───────────┐
       ▼      ▼           ▼
      UI   secure ops   persistence
```

The core must never contain `if chain == bitcoin` / `if chain == ethereum` branches.
It also never stores secret bytes or accepts a host-provided signing digest as trusted
input.

## Workspace

```text
crates/
  wallet-core/        no_std lifecycle, auth, policy and operation state machine
  chain-api/          contract for on-device parsing, review and execution
  chain-bitcoin/      Bitcoin adapter (parsers intentionally still incomplete)
  chain-ethereum/     Ethereum adapter (parsers intentionally still incomplete)

docs/
  DOMAIN.md           state machine and invariants
  SECURITY.md         trust boundaries and fail-closed rules
```

Bitcoin and Ethereum are the first chain adapters because they exercise very different
transaction and signing models. Additional chains must be addable without changing the
wallet state machine.

## Core rule

```text
State + Event -> State + Effect
```

The runtime executes effects and feeds results back as events. The same domain logic
can therefore run in pure tests, a firmware sandbox, co-simulation, and later the real
board.

See [`docs/DOMAIN.md`](docs/DOMAIN.md) and [`docs/SECURITY.md`](docs/SECURITY.md).

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
