# Hardware Wallet

A minimal, auditable, chain-agnostic hardware wallet built in Rust.

This project is a reference hardware wallet rather than a wallet for one specific blockchain. The trusted device core owns generic wallet behavior — accounts, derivation requests, signing intents, policy, user approval and state transitions — while chain-specific parsing and signing rules live in isolated modules.

## Principles

- Chain-agnostic core.
- Rust `no_std` for trusted device code.
- No heap in the firmware path where practical.
- No RTOS unless a concrete requirement proves it necessary.
- Deterministic domain logic: events in, state + effects out.
- Physical confirmation before any sensitive signing operation.
- Chain modules must expose human-reviewable signing intents rather than opaque bytes.
- Reproducible builds and explicit firmware size budgets.
- The same scenarios should run against the pure domain, virtual hardware, and later the real device.

## Architecture

```text
Host request
    │
    ▼
Device Protocol
    │
    ▼
Hardware Wallet Core
    │
    ├── account / key policy
    ├── approval state machine
    ├── session state
    └── signing intents
            │
     ┌──────┼────────┐
     ▼      ▼        ▼
  Bitcoin Ethereum  ...
   module   module
     │      │
     └──► signing effects
```

The core must not contain `if chain == bitcoin` / `if chain == ethereum` branches. A chain module is responsible for decoding its transaction format, validating it, producing a canonical human-reviewable intent, and defining the digest/signature operation it requires.

## Initial chain modules

Bitcoin and Ethereum are good first implementations because they exercise very different transaction and signing models. Additional chains should be addable without changing the wallet state machine or hardware runtime.

## Target hardware

Initial reference target:

- Cortex-M-class MCU;
- 128×64 display;
- two physical buttons;
- USB device transport;
- dedicated secure element;
- USB-powered, battery-free design.

The exact MCU and secure-element role are intentionally not frozen yet. We will not claim that secrets never enter the MCU until the implemented architecture can actually prove it.

## Planned repository layout

```text
crates/
  wallet-core/        chain-agnostic state machine and policy
  chain-bitcoin/      Bitcoin parsing, intent and signing rules
  chain-ethereum/     Ethereum parsing, intent and signing rules

firmware/             thin composition for the reference device
hardware/             schematic, PCB and BOM
scenarios/            behavior and security scenarios

docs/
  ARCHITECTURE.md
  THREAT_MODEL.md
  SECURITY.md
```

Reusable embedded concerns — protocol, persistence, UI, device specification, simulation and fault injection — should remain separate projects when their contracts become stable enough to reuse.

## Status

Early architecture skeleton. Do not use this project to protect real funds.

## License

MIT.
