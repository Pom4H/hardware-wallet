# Hardware sizing baseline

Measured on **2026-08-28** from commit `3f1fa7f156cdc5af60b9781da2c68d739b9af1e4`.

The linked probe includes the wallet reducer, BIP-39 lifecycle, BIP-32 and
SLIP-0010, secp256k1 and Ed25519 signing, all implemented hashes, and the
Bitcoin, Ethereum and Solana adapters. It does not include the future USB
runtime, display/input drivers, production storage, bootloader, secure-element
driver or board HAL.

## Linked trusted core

| Target | Flash image | `.text` | `.rodata` | vector table | Static RAM |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cortex-M4/M7 profile (`thumbv7em-none-eabi`) | 231,844 B / 226.4 KiB | 169,296 B | 61,524 B | 1,024 B | 0 B |
| Cortex-M33 profile (`thumbv8m.main-none-eabi`) | 232,808 B / 227.4 KiB | 169,300 B | 61,524 B | 1,984 B | 0 B |

The near-identical result means Flash size does not decide between M4/M7 and
M33. Security boundaries, boot/update features, peripheral quality, power,
availability and price should decide.

Static RAM is zero because the synthetic probe has no long-lived globals.
That does **not** mean the firmware needs no RAM: transaction envelopes,
cryptographic temporaries and BIP-39/HD state are currently local stack data.
Peak stack remains the largest unmeasured memory variable.

## Projected product requirement

The current policy reserves:

- 64 KiB for USB/UI/HAL/secure-element/platform code;
- 64 KiB for future supported transaction classes;
- 32 KiB bootloader;
- 16 KiB persistent records;
- 25% Flash and RAM margin;
- provisional 32 KiB main stack;
- IRQ, transport, framebuffer, storage scratch and future RAM reserves.

Results:

| Configuration | M4/M7 calculation | M33 calculation | Selection class |
| --- | ---: | ---: | ---: |
| Single firmware slot | 492 KiB Flash | 496 KiB Flash | 512 KiB Flash |
| A/B rollback-safe update | 936 KiB Flash | 944 KiB Flash | 1 MiB Flash |
| Runtime RAM projection | 82 KiB | 82 KiB | 96 KiB calculated |

## Current selection decision

Until stack high-water and target-cycle measurements replace the provisional
allowances, candidate search should use:

```text
Production / A-B update:
  Flash >= 1 MiB
  RAM   >= 128 KiB

Prototype / single slot:
  Flash >= 512 KiB
  RAM   >= 128 KiB

Instrumentation-heavy development board:
  Flash >= 1 MiB
  RAM   >= 256 KiB preferred
```

The gap from the calculated 96 KiB RAM class to the **128 KiB selection floor**
is intentional. It protects the first board revision from stack error,
interrupt nesting and USB/secure-element driver state that are not linked yet.

## Architecture direction

Both profiles fit. The initial shortlist should prefer Cortex-M33 when the
exact part provides useful TrustZone-M, MPU, secure boot/update and debug-lock
semantics. Cortex-M4/M7 remains valid when a separate secure element and
bootloader design provide the required security properties.

No minimum clock frequency is claimed yet. It will be computed from target
cycles:

```text
required_MHz =
  max(ceil(worst_case_cycles_i / latency_budget_i_microseconds))
```

The decisive scenarios are BIP-39/passphrase opening, secp256k1 signing,
Ed25519 signing, and maximum accepted transaction parsing.

## What must be measured before freezing the chip

1. Firmverse stack high-water for every create/recover/sign/update scenario.
2. Firmverse or evaluation-board target cycles for latency requirements.
3. NodeSpice and board measurements for USB cable drop, regulator transients,
   brownout and peak signing/display current.
4. Power-loss injection for root storage, PIN counters and firmware update.
5. Hardware-in-the-loop agreement with the emulator traces.
6. Exact ordering-code review: errata, temperature/package, lifecycle status,
   distributor stock and price.

The generated Actions artifacts (`budget.json`, `budget.md`, `probe.elf`) are
the audit evidence. `mcu-requirements.toml` and `tools/mcu_candidate.py` turn
that evidence into repeatable candidate checks.
