# Security model

This repository is experimental and must not be used to protect real funds yet.

## Trust boundaries

Untrusted inputs include the connected host, USB packets, transaction/message bytes,
chain metadata supplied by external software, and all correlation ids received over a
transport. Chain modules must parse raw security-relevant payloads on the device and
must not trust pre-decoded amounts, destinations, contract calls, or signing digests
from the host.

`hardware-wallet-core` trusts only the results of its device-owned chain adapter and
runtime effects that are correlated to an active request.

Host trust is also device-owned. `UnlockRequested` carries only the host identity. The
core emits `ResolveHostTrust`, and only the trusted-host backend may answer with
`HostTrustResolved`. Connected software therefore cannot mark itself trusted by placing
a trust flag in the unlock request.

## Authentication durability

PIN retry accounting must live in a durable authentication backend, not in volatile
wallet state. A rejected PIN event carries the total failed-attempt count that has
already been durably recorded. The core accepts only a strictly increasing non-zero
count and applies wipe/lockout policy to that durable value.

A successful PIN result means the authentication backend has already durably reset its
retry counter. Rebooting the device therefore cannot be used to reset brute-force
attempts.

## Secrets and wallet contexts

The domain state intentionally contains no seed, PIN, passphrase, private key, or raw
transaction. Secret-bearing operations are represented as effects so the eventual
secure runtime can choose whether the material lives in MCU protected memory, a
secure element, or another isolated implementation.

An unlocked session carries only an opaque `WalletContextId`. This is the identity of
the exact base or passphrase-derived wallet currently opened by the secure runtime.
Every operation is bound to that context so an in-flight review cannot be executed
against a different hidden wallet.

Chain requests select only a relative `KeyTarget` (account, derivation path and purpose).
They cannot construct `ExecutionContext`, and `KeyLocator` does not expose writable
wallet-context fields. Only an unlocked `State` can produce an `ExecutionContext`, which
binds the relative target to the already authorized wallet. This prevents wallet-context
selection from becoming an untrusted host parameter.

The exact secure-element design is not frozen. The project must not claim that a seed
or private key never enters the MCU until the actual implementation can prove that.

## Reboot and persistence

Only stable non-secret state is snapshot-able. Sessions, wallet-context handles and
foreground flows are never restored after reboot; a provisioned wallet always resumes
locked.

Provisioning and wiping are deliberately not snapshot-able because their crash-safe
commit protocol belongs to the persistence runtime. Likewise, a setting change becomes
active only after persistence succeeds. If power is lost after user confirmation but
before persistence, reboot restores the old setting and any stale persistence callback
is rejected because its foreground flow no longer exists.

The same rule applies to in-flight operations: reboot drops the operation and stale
completion callbacks cannot resurrect it.

## Security settings

A host cannot directly toggle a security policy. Changes go through a device-owned
review, physical confirmation, persistence, and only then become active. In particular,
`BlindSigningPolicy::Allow` cannot be enabled silently by connected software.

Trusted-host revocation also becomes effective only after persistence. If the revoked
host owns the active session, its trust is immediately downgraded after the persistent
change succeeds.

## Fail-closed rules

- unknown or out-of-order transitions do not advance a flow;
- mismatched request/session/setup/settings ids do not advance a flow;
- stale callbacks after disconnect, lock or reboot do not advance a flow;
- host trust is resolved by device-owned storage, never supplied by the host;
- PIN retry counts come from durable authentication storage and must increase monotonically;
- signing is never silent;
- custom operations cannot bypass the private-key confirmation rule when marked as private-key operations;
- blind signing is off by default;
- security settings require physical confirmation and successful persistence;
- host changes cannot take over an unlocked session;
- wallet-context changes cannot take over an in-flight operation;
- host/chain input cannot select a different wallet context for key execution;
- a locked state cannot produce a key execution capability;
- reboot never restores an unlocked session or foreground operation;
- tamper and configured PIN-attempt exhaustion enter the wipe flow.
