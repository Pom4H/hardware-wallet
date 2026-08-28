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

## Authorization

An unlocked session is bound to one `HostId`. Sensitive foreground work cannot be
continued by another host. Disconnect and session expiry can lock the wallet and
clear all transient state.

Host pairing is deliberately separate from PIN unlock. Pairing establishes host
trust; PIN/passphrase authorization opens the wallet. A policy may require a trusted
host before any private-key operation.

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

## Invariants

1. No private-key operation executes before device-owned review preparation.
2. No private-key operation executes without physical confirmation.
3. Blind signing is rejected unless policy explicitly enables it.
4. An operation is correlated by id from request through completion.
5. A session is correlated to one host.
6. Locking clears the foreground flow and requests transient-secret cleanup.
7. PIN failures are monotonic and may trigger a persistent wipe.
8. Factory reset is a two-step user-confirmed flow.
9. The core never contains chain-specific parsing or signature rules.
10. The core never stores secret bytes.
