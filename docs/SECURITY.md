# Security model

This repository is experimental and must not be used to protect real funds yet.

The current code proves a software security architecture. It does **not** yet prove that a seed or private key cannot be extracted from a physical device. Any production claim must be narrower than the hardware evidence that supports it.

## Security goal

The target property is stronger than “the private key never crosses USB”:

> A fully compromised host must be unable to read secret key material or make the device silently authorize an operation different from the one the user reviewed and physically approved.

The design therefore protects two things at the same time:

1. **secret material** — root secret, seed, chain code, derived private keys and signing nonce state;
2. **meaning** — the exact transaction, message or operation the human believes they are authorizing.

A secure element can protect the first property and still sign the wrong transaction. A trusted display can show the right transaction while a weak signer leaks the key. Production hardware needs both boundaries to hold.

## Threat model

Assume the following are hostile unless a section explicitly says otherwise:

- the connected computer or phone;
- the companion application;
- USB/BLE packets and framing;
- transaction/message bytes and chain metadata;
- host-decoded amounts, recipients, calldata and signing digests;
- every correlation id received over transport;
- stale callbacks after disconnect, reboot, lock or cancellation;
- any non-secure firmware component that does not need access to secrets;
- an attacker with temporary physical possession of the device.

The first production version does not claim resistance to unlimited invasive laboratory attacks. Decapsulation, microprobing, focused-ion-beam work and advanced side-channel/fault-injection resistance require silicon-specific evaluation and are outside the evidence produced by this repository today.

## Target trust boundaries

The production architecture is intended to converge on four explicit zones:

```text
UNTRUSTED HOST
computer / phone / browser / malware
        │
        │ structured request (for Bitcoin: PSBT or equivalent)
        ▼
NON-SECURE DEVICE WORLD
USB / BLE / framing / transport / update download
        │
        │ narrow validated call boundary
        ▼
TRUSTED DEVICE WORLD
parser / policy / trusted display / physical input / authorization
        │
        │ authenticated secure-element protocol
        ▼
HARDWARE SECURITY ROOT
PIN policy / durable counters / device secret / protected key wrapping
and, where the selected part allows it safely, private-key operations
```

A Cortex-M33/TrustZone implementation is one candidate way to separate the non-secure and trusted device worlds. A dedicated secure element is the expected hardware security root. Exact parts are deliberately **not frozen** until their required cryptography, lifecycle, update, debug, fault and provisioning behavior has been tested.

The architecture must not depend on a marketing label such as “secure element.” The selected part has to satisfy the actual wallet protocol. For example, supporting one elliptic curve signing primitive is not the same as supporting BIP-32 key derivation, wallet-root lifecycle, anti-rollback or the exact signing protocol required by every supported chain.

## Production security invariants

These are design requirements, not claims that current prototype hardware already satisfies them.

1. The host is always untrusted.
2. Recovery material never crosses USB/BLE during normal operation.
3. Private keys never enter non-secure RAM.
4. Only trusted code may request secret-bearing operations.
5. The external protocol never exposes a generic `sign(arbitrary_digest)` capability.
6. Security-relevant payloads are parsed and validated inside the trusted boundary.
7. Transaction details shown to the user are derived from the exact object that will be signed.
8. Physical confirmation is read by the trusted boundary, not synthesized by the host.
9. A navigation gesture cannot accidentally mean “approve.”
10. Unknown or unsupported transaction classes fail closed rather than blind-signing.
11. Only authenticated firmware in the approved boot chain may reach trusted services.
12. Firmware rollback below the security floor is rejected by durable monotonic policy.
13. Production debug/readout paths are irreversibly disabled or cryptographically authenticated according to the selected MCU policy.
14. PIN retry state is durable and cannot be reset by reboot or power cycling.
15. Secret-bearing RAM is explicitly zeroized after use and on lock, timeout, fatal error, relevant tamper events and update transitions.
16. One broken entropy source must not silently determine the wallet root where the hardware architecture can combine independent entropy sources safely.
17. A compromised host must not be sufficient to spend funds without a matching trusted-display review and physical approval.
18. Compromise of one security component should not automatically reveal the wallet root where a split/wrapped-secret design can make that practical.
19. Signature generation must not provide an avoidable covert channel for leaking private key material.
20. Every production security claim must identify the test, hardware evidence or certification artifact that supports it.

## Trust boundaries in the current software

Untrusted inputs include the connected host, USB packets, transaction/message bytes, chain metadata supplied by external software and every correlation id received over a transport. Chain modules parse security-relevant payloads on the device and do not trust host-decoded amounts, destinations, contract calls or signing digests.

`wallet-core` trusts only correlated results from device-owned adapters and runtime capabilities.

Host trust is device-owned. `UnlockRequested` carries only host identity; the core emits `ResolveHostTrust`, and only trusted storage may answer with `HostTrustResolved`. Connected software cannot mark itself trusted in its request.

## The external signer API is semantic

The host must ask the device to authorize a meaningful operation, not an opaque hash.

For Bitcoin the useful boundary is conceptually:

```text
sign_bitcoin_transaction(psbt)
```

not:

```text
sign(hash)
```

The trusted path owns:

```text
untrusted transaction
      ↓
parse
      ↓
validate supported policy
      ↓
build human review
      ↓
display that review
      ↓
physical approval
      ↓
derive the exact signing payload
      ↓
sign
```

This is why the chain adapter owns both review generation and execution material. The host must not be able to submit one human-readable description while independently selecting another digest for the signer.

## Authentication durability

PIN retry accounting belongs to a durable authentication backend, not volatile wallet state. A rejected-PIN event carries the total failed-attempt count already committed by that backend. The reducer accepts only a strictly increasing non-zero count and applies lock/wipe policy to it.

A successful PIN result means the backend has already durably reset its retry counter. Reboot therefore cannot reset brute-force attempts.

For production hardware, the preferred implementation places the retry primitive below ordinary application firmware: a secure element, protected monotonic counter or equivalent security service should enforce attempts so a compromised non-secure world cannot simply patch the counter to zero.

## Secret installation boundary

The pure domain contains no entropy, mnemonic, seed, PIN, passphrase, private key or raw transaction.

For a newly generated wallet, key material is staged in volatile `key-lifecycle` state. It is not installed while the backup is merely displayed or checked. Only the `PersistProvisioning` Effect may call `RootSecretStore::persist_root`, and the reducer must not receive `ProvisioningPersisted` until that operation is durably complete.

A failed store commit keeps the same staged root available for retry. Cancelling the flow drops it. Recovery follows the same commit boundary.

A production `RootSecretStore` must provide:

- atomic durable commit;
- authenticated encryption or a hardware key-lifecycle primitive;
- fail-closed corruption/authentication handling;
- rollback strategy where policy counters require it;
- durable wipe semantics;
- no host-accessible root export.

The current memory store is test-only.

A realistic first hardware design may keep only ciphertext in MCU flash and derive/unlock its key-encryption key from a hardware secret plus authorization state. A stronger design keeps derivation/signing material entirely inside a programmable secure signer. Which claim is valid depends on what the selected secure element can actually execute without exporting sensitive intermediates.

## Wallet contexts and key selection

The persisted root becomes a BIP-39 seed only when opening a base or passphrase wallet. Passphrase and seed remain ephemeral. The reducer receives only `WalletContextId`.

Chain requests select a relative `KeyTarget`; they cannot construct `ExecutionContext`. Only an unlocked state can bind the target to the active wallet and create `KeyLocator`. This prevents host-controlled wallet-context substitution.

The exact secure-element design is not frozen. The project must not claim that seed or private key never enters the MCU until the concrete implementation proves it.

### The BIP-32 trap

“ECDSA inside the secure element” is not enough to claim “Bitcoin keys never leave the secure element.”

A Bitcoin HD wallet also needs a secure strategy for root material, chain codes and BIP-32 child derivation. If the secure element can hold a static secp256k1 key but firmware must export an extended private key or derived scalar to implement the wallet tree, the strong isolation claim has already failed.

Before selecting a part, the hardware gate must therefore test the complete key lifecycle needed by the supported wallet policy, not only a single signing demo.

## Review and signing

A chain adapter must independently parse the raw operation, construct the human review and derive every signing payload from the reviewed object. Host-provided digests are not trusted.

Private-key operations require physical confirmation. Unsupported transaction classes fail closed. Blind signing is disabled by default and can be enabled only through a physically confirmed, persist-before-apply setting change.

The trusted screen and confirmation GPIOs belong to the same security argument as the signer. If compromised non-secure code can rewrite the display after the trusted parser makes its decision, the device does not have a trustworthy “what you see is what you sign” property.

## Signature exfiltration

A malicious signer can leak secret bits without ever exporting a private key directly. For ECDSA, a malicious implementation may encode information into its nonce choices while still producing valid signatures.

A production Bitcoin path should therefore evaluate a host-assisted anti-exfiltration protocol such as the anti-klepto construction used by BitBox for secp256k1 ECDSA. The security property is that the signer cannot freely choose the final nonce after committing to its contribution because host randomness is mixed into the signing protocol.

This control is algorithm-specific. It must not be advertised as covering Schnorr/Taproot or other signature schemes unless the concrete protocol and implementation provide equivalent protection.

## Boot and update chain

Secret isolation is irrelevant if an attacker can boot arbitrary old or unsigned firmware that asks the secure services to misbehave.

The production boot path must be explicit:

```text
immutable ROM / root of trust
        ↓ verifies
boardloader or first-stage boot
        ↓ verifies
update-capable bootloader
        ↓ verifies + checks security version
application firmware
```

Required properties:

- signed images;
- authenticated metadata;
- rollback-safe A/B or equivalent interrupted-update recovery;
- a monotonic security-version floor;
- fail-closed verification errors;
- no unsigned “recovery convenience” path in production;
- update authorization that cannot silently downgrade security policy.

Development and production units must intentionally diverge: development hardware may keep SWD/JTAG and diagnostic transport available, while production provisioning must lock or authenticate those paths according to the selected MCU's documented mechanism.

## RAM, zeroization and fault boundaries

If secret material is present in trusted MCU SRAM, its lifetime must be short and observable in tests.

Secret-bearing buffers must be explicitly zeroized with a primitive the compiler cannot optimize away. Zeroization is required after successful use and on transitions that invalidate the session, including lock, timeout, disconnect where policy requires it, fatal error, update entry and relevant tamper/fault events.

This is necessary but not sufficient. Memory scanning in an emulator can prove that a test canary is absent from modeled RAM after a lifecycle transition; it cannot prove resistance to voltage glitching, bus probing, electromagnetic leakage or invasive extraction.

Brownout handling is part of the same boundary. Power failure must not leave partially committed root data, reset retry counters or restore a security-sensitive transition in a more privileged state.

## Reboot and persistence

Only stable non-secret state is snapshot-able. Sessions, wallet-context handles and foreground flows are never restored; a provisioned wallet resumes locked.

Provisioning and wipe are not snapshot-able because their crash-safe protocol belongs to the persistence runtime. Setting changes become active only after persistence. A power loss before commit restores the old state, and stale callbacks are rejected.

The same rule applies to operations: reboot drops them and completion callbacks cannot resurrect them.

## Hardware evidence gates

A feature becomes a security claim only when its evidence gate passes.

| Claim | Minimum evidence before claiming it |
| --- | --- |
| Host cannot choose what is signed | Parser/review/execution tests from the same raw request plus malformed-input tests |
| PIN attempts survive reboot | Durable backend tests with forced reset/power-loss cases |
| Private keys never enter non-secure RAM | Hardware/emulator memory canaries across every derive/sign/error path |
| Private keys never enter MCU RAM at all | Concrete secure-signer implementation plus bus/memory instrumentation proving only public outputs cross the boundary |
| Unsigned firmware cannot run | Boot-chain tests on selected silicon, including corrupted image and key mismatch |
| Old vulnerable firmware cannot run | Monotonic anti-rollback test on selected silicon |
| Debug cannot dump secrets | Production-fused device verification and documented recovery/manufacturing policy |
| Device resists nonce exfiltration | Protocol-level anti-exfil tests for each claimed signature algorithm |
| Physical tamper wipes secrets | Hardware-in-the-loop tamper/fault tests on the final board |
| Side-channel resistance | Dedicated silicon/board evaluation; not inferred from functional tests |

## Hardware and boot assumptions still missing

Production security additionally requires:

- verified device-owned entropy and health tests;
- selected and validated authenticated root storage or secure-signer lifecycle;
- signed boot and firmware update on the chosen MCU;
- rollback protection and interrupted-update recovery;
- production debug/readout lock policy;
- brownout-safe persistence;
- stack, timing and fault-injection tests on the selected MCU;
- secure display/input ownership proof;
- secure-element protocol and provisioning review;
- PCB and power-path review.

The hardware resource report selects memory classes; it does not prove these security properties. See [`HARDWARE_REQUIREMENTS.md`](HARDWARE_REQUIREMENTS.md).

## Fail-closed rules

- unknown or out-of-order transitions do not advance a flow;
- mismatched request/session/setup/settings ids do not advance a flow;
- stale callbacks after disconnect, lock or reboot do not advance a flow;
- host trust is resolved by device-owned storage;
- PIN retry counts are durable and monotonic;
- generated/recovered roots are not installed before durable commit;
- signing is never silent;
- custom operations cannot bypass private-key confirmation;
- blind signing is off by default;
- settings require physical confirmation and successful persistence;
- host changes cannot take over an unlocked session;
- wallet-context changes cannot take over an in-flight operation;
- a locked state cannot produce a key execution capability;
- reboot never restores an unlocked session or foreground operation;
- tamper and configured PIN-attempt exhaustion enter the wipe flow;
- unsupported transaction/signature modes fail closed;
- non-secure transport code cannot obtain secret-bearing buffers;
- firmware below the production security-version floor cannot boot.

## Current claim

Today this repository can honestly claim that its **software architecture** separates domain state, secret lifecycle, chain parsing, review and signing capabilities and tests many fail-closed transitions end-to-end.

It cannot yet honestly claim that a production seed/private key is physically isolated from the MCU, that debug/fault attacks are defeated, or that a final board is resistant to side channels. Those claims start only after the target MCU, secure element, boot chain, provisioning process and PCB exist and pass the evidence gates above.
