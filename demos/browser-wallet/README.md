# Browser wallet firmware

This crate is the executable firmware half of the Anatomy hardware-wallet twin.
It is a **teaching target**, not the production firmware image.

The binary links the real `hardware-wallet-core` reducer for a PHY6252-class
Cortex-M0 target that Firmverse can execute directly in the browser. It proves
one complete physical interaction path:

```text
Elements button
  -> Firmverse GPIO P14 / P16
  -> Cortex-M instruction stream
  -> wallet-core Event
  -> State + Effect
  -> firmware-owned WLT1 display frame
  -> Elements trusted display
```

The right button drives unlock, review, and confirmation. The left button locks
or rejects. Signing completes only after the reducer has emitted
`ExecuteOperation`; a rejection produces `UserRejected` without a private-key
execution effect.

## Display protocol

Firmware emits a bounded mailbox frame:

```text
WLT1 | version | screen state | flags | sequence
     | title\0 | line 1\0 | line 2\0 | footer\0
     | left label\0 | right label\0
```

The browser decodes this frame but does not invent device state or review copy.

## Build

From the repository root:

```bash
bash tools/build_browser_wallet_demo.sh
```

Outputs:

```text
demos/browser-wallet/dist/wallet-demo.hex
demos/browser-wallet/dist/wallet-demo.elf
```

The build uses Rust 1.98.0, the `thumbv6m-none-eabi` target, and the Firmverse
SRAM vector-table layout at `0x1fff0000`.

## Evidence boundary

The browser demo executes the genuine domain reducer but intentionally replaces
the full cryptographic runtime with a deterministic completion delay. The
repository's Cortex-M4/M33 Firmverse and hardware-budget paths remain the
evidence for the complete linked cryptographic surface, cycle counts, stack
high-water measurements, and MCU sizing.
