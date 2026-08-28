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

## Secrets and wallet contexts

The domain state intentionally contains no seed, PIN, passphrase, private key, or raw
transaction. Secret-bearing operations are represented as effects so the eventual
secure runtime can choose whether the material lives in MCU protected memory, a
secure element, or another isolated implementation.

An unlocked session carries only an opaque `WalletContextId`. This is the identity of
the exact base or passphrase-derived wallet currently opened by the secure runtime.
Every operation is bound to that context so an in-flight review cannot be executed
against a different hidden wallet.

The exact secure-element design is not frozen. The project must not claim that a seed
or private key never enters the MCU until the actual implementation can prove that.

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
- signing is never silent;
- custom operations cannot bypass the private-key confirmation rule;
- blind signing is off by default;
- security settings require physical confirmation and successful persistence;
- host changes cannot take over an unlocked session;
- wallet-context changes cannot take over an in-flight operation;
- tamper and configured PIN-attempt exhaustion enter the wipe flow.
