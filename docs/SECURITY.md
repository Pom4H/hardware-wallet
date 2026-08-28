# Security model

This repository is experimental and must not be used to protect real funds yet.

## Trust boundaries

Untrusted inputs include the connected host, USB packets, transaction/message bytes,
chain metadata supplied by external software and every correlation id received over a
transport. Chain modules parse security-relevant payloads on the device and do not trust
host-decoded amounts, destinations, contract calls or signing digests.

`wallet-core` trusts only correlated results from device-owned adapters and runtime
capabilities.

Host trust is device-owned. `UnlockRequested` carries only host identity; the core emits
`ResolveHostTrust`, and only trusted storage may answer with `HostTrustResolved`.
Connected software cannot mark itself trusted in its request.

## Authentication durability

PIN retry accounting belongs to a durable authentication backend, not volatile wallet
state. A rejected-PIN event carries the total failed-attempt count already committed by
that backend. The reducer accepts only a strictly increasing non-zero count and applies
lock/wipe policy to it.

A successful PIN result means the backend has already durably reset its retry counter.
Reboot therefore cannot reset brute-force attempts.

## Secret installation boundary

The pure domain contains no entropy, mnemonic, seed, PIN, passphrase, private key or raw
transaction.

For a newly generated wallet, key material is staged in volatile `key-lifecycle` state.
It is not installed while the backup is merely displayed or checked. Only the
`PersistProvisioning` Effect may call `RootSecretStore::persist_root`, and the reducer
must not receive `ProvisioningPersisted` until that operation is durably complete.

A failed store commit keeps the same staged root available for retry. Cancelling the
flow drops it. Recovery follows the same commit boundary.

A production `RootSecretStore` must provide:

- atomic durable commit;
- fail-closed corruption/authentication handling;
- rollback strategy where policy counters require it;
- durable wipe semantics;
- no host-accessible root export.

The current memory store is test-only.

## Wallet contexts and key selection

The persisted root becomes a BIP-39 seed only when opening a base or passphrase wallet.
Passphrase and seed remain ephemeral. The reducer receives only `WalletContextId`.

Chain requests select a relative `KeyTarget`; they cannot construct `ExecutionContext`.
Only an unlocked state can bind the target to the active wallet and create `KeyLocator`.
This prevents host-controlled wallet-context substitution.

The exact secure-element design is not frozen. The project must not claim that seed or
private key never enters the MCU until the concrete implementation proves it.

## Review and signing

A chain adapter must independently parse the raw operation, construct the human review
and derive every signing payload from the reviewed object. Host-provided digests are not
trusted.

Private-key operations require physical confirmation. Unsupported transaction classes
fail closed. Blind signing is disabled by default and can be enabled only through a
physically confirmed, persist-before-apply setting change.

## Reboot and persistence

Only stable non-secret state is snapshot-able. Sessions, wallet-context handles and
foreground flows are never restored; a provisioned wallet resumes locked.

Provisioning and wipe are not snapshot-able because their crash-safe protocol belongs
to the persistence runtime. Setting changes become active only after persistence. A
power loss before commit restores the old state, and stale callbacks are rejected.

The same rule applies to operations: reboot drops them and completion callbacks cannot
resurrect them.

## Hardware and boot assumptions still missing

Production security additionally requires:

- verified device-owned entropy and health tests;
- authenticated root storage or a secure-element key lifecycle;
- signed boot and firmware update;
- rollback protection and interrupted-update recovery;
- debug/readout lock policy;
- brownout-safe persistence;
- stack, timing and fault-injection tests on the selected MCU;
- PCB and power-path review.

The hardware resource report selects memory classes; it does not prove these security
properties. See [`HARDWARE_REQUIREMENTS.md`](HARDWARE_REQUIREMENTS.md).

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
- tamper and configured PIN-attempt exhaustion enter the wipe flow.
