# Hardware requirements and MCU selection

The MCU must be selected from measured product requirements, not from the sum of crate
sizes and not from a generic “Rust needs more memory” assumption.

This repository therefore maintains two related numbers:

1. **linked trusted-core probe** — what the current wallet domain, key lifecycle,
   cryptography and chain adapters consume when linked as one Cortex-M image;
2. **product projection** — the probe plus explicit reserves for the platform code that
   does not exist yet: USB, display, input, bootloader, board HAL, secure-element driver,
   production persistence and future chain features.

The first number is measured. The second is a reviewable policy model. Both are kept in
CI so a dependency or feature cannot silently invalidate the selected chip.

## Reproducible probe

`crates/firmware-budget` is not product firmware. It is a synthetic `no_std` Cortex-M
binary that deliberately reaches every trusted layer:

```text
wallet-core
    + key-lifecycle / BIP-39
    + hd-key-backend / BIP-32 / SLIP-0010
    + crypto-runtime / secp256k1 / Ed25519 / hashes
    + Bitcoin parser and execution
    + Ethereum parser and execution
    + Solana parser and execution
```

The probe uses dynamic, opaque inputs so release LTO cannot keep only one convenient
match arm. The three maximum-size request envelopes are exercised sequentially, because
a real device handles one foreground operation at a time.

CI links it for two candidate CPU profiles:

- `thumbv7em-none-eabi`: Cortex-M4/M7 class without making an FPU mandatory;
- `thumbv8m.main-none-eabi`: Cortex-M33 class.

The generic linker map is intentionally larger than any expected chip. It only provides
addresses so the ELF can link; it is not a hardware recommendation.

## Flash calculation

Flash usage is read from the final ELF, including the initialized `.data` load image:

```text
probe_flash = vector table + text + rodata + unwind tables + initialized data
```

Crate or object-file sizes are not used because they contain code the final linker may
remove and omit cross-crate LTO effects.

The projected firmware slot is:

```text
slot_payload = probe_flash
             + platform_flash_reserve
             + future_feature_reserve

firmware_slot = align(slot_payload × flash_margin)
```

The report calculates two device classes:

```text
single-slot = bootloader + persistent region + firmware_slot
A/B update  = bootloader + persistent region + 2 × firmware_slot
```

A/B is the preferred production configuration: a failed update can leave the previous
signed image intact. A single-slot number is still reported for prototypes or MCUs with
a ROM bootloader and an external recovery mechanism.

## RAM calculation

The ELF directly provides only static RAM:

```text
static_ram = .data + .bss + .uninit
```

The product requirement is larger:

```text
required_ram = static_ram
             + measured_peak_stack
             + interrupt_nesting_reserve
             + USB / protocol buffers
             + display framebuffer
             + storage transaction scratch
             + HAL / driver state
             + future-feature reserve
             + margin
```

`hardware-budget.toml` currently uses a provisional 32 KiB stack allowance. This is a
conservative placeholder, not a measurement.

### How peak stack will be measured

The final firmware stack region will be filled with a known byte pattern at boot. After
each deterministic scenario, Firmverse and hardware-in-the-loop tests will scan the
remaining pattern and record the high-water mark.

Required scenarios:

- fresh 24-word wallet creation and BIP-39 seed derivation;
- recovery and passphrase wallet opening;
- maximum accepted Bitcoin PSBT parsing and signing;
- maximum accepted Ethereum transaction parsing and signing;
- maximum accepted Solana message parsing and signing;
- USB receive while display and button interrupts are active;
- persistent commit, reboot recovery and firmware update;
- every error path that renders a device-owned warning.

The production stack budget becomes:

```text
stack_budget = align(max_scenario_high_water × 1.5
                   + maximum_interrupt_frame_cost)
```

Static stack metadata may be collected from LLVM as an additional lower bound, but it
cannot replace whole-program high-water tests when indirect calls and interrupts exist.

## CPU frequency and latency

Host benchmarks do not select the MCU clock. Firmverse or the physical target must
measure target instruction cycles for each acceptance scenario.

For operation `i`:

```text
required_MHz_i = ceil(worst_case_cycles_i / latency_budget_i_microseconds)
required_MHz   = max(required_MHz_i)
```

Current acceptance targets in `hardware-budget.toml` are product requirements, not
claims about current performance:

- boot to ready: 250 ms;
- transaction parse/review preparation: 100 ms;
- BIP-39/passphrase context opening: 1500 ms;
- secp256k1 derive and sign: 500 ms;
- Ed25519 derive and sign: 250 ms.

The cycle benchmark must use release firmware, the chosen constant-time crypto backend,
and the slowest allowed voltage/clock configuration.

## Persistent storage

The current projection reserves 16 KiB independently from executable Flash. This region
must eventually hold versioned, atomic records for:

- root-secret handle or authenticated encrypted root record;
- PIN verifier and monotonic failed-attempt counter;
- security policy;
- trusted hosts;
- wallet/account metadata;
- anti-rollback/update metadata;
- two-phase commit headers and migration state.

The storage implementation must be power-loss safe. Raw capacity is insufficient if the
chip cannot meet erase endurance, write granularity or atomicity requirements.

## Mandatory MCU capabilities

A candidate is rejected if the product cannot obtain all of the following from the MCU,
secure element or their combination:

- supported 32-bit Cortex-M Rust target;
- USB Full-Speed device controller or an explicitly budgeted external USB bridge;
- device-owned cryptographic entropy with documented health-test strategy;
- independent watchdog and brownout reset;
- enough internal Flash and RAM for the CI budget;
- deterministic debug-port disable/readout protection for production units;
- monotonic or rollback-resistant storage strategy for PIN/update counters;
- SPI or I²C for display and secure element, plus two button GPIOs;
- unique device identity or a securely provisioned identity;
- a signed boot/update path with recovery from interrupted updates.

Preferred capabilities:

- TrustZone-M or another useful privilege/isolation boundary;
- dual-bank Flash or hardware-assisted bank swap;
- memory protection unit;
- hardware SHA/AES acceleration when it does not compromise auditability;
- secure-element interface that does not require exporting wallet secrets;
- USB clock source that remains accurate across supported supply conditions.

## Electrical requirements

Memory and cycles do not determine the entire chip. NodeSpice and board measurements
must additionally establish:

- peak and average current for boot, display, USB and signing;
- regulator transient response;
- brownout threshold and reset timing;
- USB cable-drop tolerance;
- secure-element load steps;
- power loss during every persistent-write boundary.

Those results select the regulator, decoupling and brownout configuration, and may also
exclude an MCU whose peak current is incompatible with the intended USB-only power path.

## CI outputs

`.github/workflows/hardware-budget.yml` builds both CPU profiles, checks explicit probe
ceilings, and uploads for each target:

```text
budget.json
budget.md
probe.elf
```

The Markdown report is also added to the GitHub Actions summary. `hardware-budget.toml`
is the single reviewable source for reserves, margins, latency targets and normal MCU
memory classes.

## Decision rule

Do not choose the exact chip until all four stages exist:

1. linked-ELF Flash/static-RAM report;
2. Firmverse cycle and stack high-water report;
3. NodeSpice power/brownout report;
4. one-board hardware-in-the-loop confirmation.

The current CI report is sufficient to choose a **memory class for early evaluation
boards**, but not yet a production part number.
