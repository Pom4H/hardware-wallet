# Wallet domain

`hardware-wallet-core` is a pure `no_std` reducer. It stores no seed, private key,
PIN, passphrase, transaction bytes, address bytes, or chain-specific payloads.

```text
State + Event -> State + Effect
```

The runtime owns side effects. It executes an `Effect`, then feeds the result back
as another `Event`. This keeps the trusted domain deterministic and lets the same
logic run in host tests, virtual hardware, and the physical device.

## Lifecycle

```text
Empty
  ├─ create ──> generate key material ──> show backup ──> verify backup ──┐
  └─ recover -> capture recovery data -> derive key material ─────────────┤
                                                                          v
                                                                    configure PIN
                                                                          |
                                                                       persist
                                                                          |
                                                                        Locked
                                                                          |
                                                             PIN + optional passphrase
                                                                          |
                                                                       Unlocked
```

A failed setup never leaves a partially provisioned logical state. A factory reset,
PIN-attempt exhaustion, or tamper event enters `Wiping` until the runtime confirms
that persistent secrets are gone.

Provisioned wallets retain non-secret metadata: whether the wallet was generated or
recovered, the recovery format, backup verification status, and passphrase policy.

## Authorization and wallet contexts

An unlocked session is bound to one `HostId` and one opaque `WalletContextId`.
`WalletContextId` represents the exact key context selected by the secure runtime:
the base seed wallet and every passphrase-derived hidden wallet are different
contexts, but the domain never sees their secret material.

Every foreground operation copies the current `WalletContextId` into its pending
state. Before review and before execution the core verifies that the active session
still refers to the same host and wallet context. An unfinished operation therefore
cannot migrate between hidden wallets.

Disconnect and session expiry can lock the wallet and clear all transient state.
Host pairing is deliberately separate from PIN unlock. Pairing establishes host
trust; PIN/passphrase authorization opens a wallet context. A policy may require a
trusted host before any private-key operation.

## Operations

The host does not tell the core that a request is a transaction, message, or custom
signing operation. The core receives only an opaque operation id and asks the chain
module to prepare a review.

After on-device parsing, the chain adapter returns a `ReviewPlan` containing:

- operation kind;
- whether private-key material is required;
- review assurance (`Full`, `Limited`, or `Blind`);
- minimum requested interaction.

The core can only strengthen these requirements. Any operation that uses private-key
material is forced to explicit physical confirmation. Blind review is disabled by
default. This rule also applies to custom chain operations.

## Settings

Security-sensitive settings are their own foreground flow:

```text
request -> render change -> physical confirm -> persist -> apply
```

The domain does not change policy when the host requests a setting, or even when the
user confirms it. The change becomes active only after the runtime reports successful
persistence. This flow covers blind signing, trusted-host-only signing, disconnect
behavior, PIN-exhaustion behavior, passphrase policy, and trusted-host revocation.

Revoking the currently connected trusted host also downgrades the active session to
`Untrusted` after persistence. Passphrase-policy changes apply to future unlocks; the
already-open session keeps its current `WalletContextId` until it is locked.

## Invariants

1. No private-key operation executes before device-owned review preparation.
2. No private-key operation executes without physical confirmation.
3. Blind signing is rejected unless a physically confirmed persisted policy enables it.
4. An operation is correlated by id from request through completion.
5. A session is correlated to one host and one wallet context.
6. A pending operation is bound to the wallet context that created it.
7. Locking clears the foreground flow and requests transient-secret cleanup.
8. PIN failures are monotonic and may trigger a persistent wipe.
9. Factory reset is a two-step user-confirmed flow.
10. Security settings are applied only after confirmation and successful persistence.
11. The core never contains chain-specific parsing or signature rules.
12. The core never stores secret bytes.
