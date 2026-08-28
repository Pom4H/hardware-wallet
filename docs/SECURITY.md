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

## Secrets

The domain state intentionally contains no seed, PIN, passphrase, private key, or raw
transaction. Secret-bearing operations are represented as effects so the eventual
secure runtime can choose whether the material lives in MCU protected memory, a
secure element, or another isolated implementation.

The exact secure-element design is not frozen. The project must not claim that a seed
or private key never enters the MCU until the actual implementation can prove that.

## Fail-closed rules

- unknown or out-of-order transitions do not advance a flow;
- mismatched request/session/setup ids do not advance a flow;
- signing is never silent;
- custom operations cannot bypass the private-key confirmation rule;
- blind signing is off by default;
- host changes cannot take over an unlocked session;
- tamper and configured PIN-attempt exhaustion enter the wipe flow.
