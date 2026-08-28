# Key lifecycle

The wallet domain never owns secret bytes. Secret creation, recovery, persistence and
passphrase-derived wallet contexts live behind `hardware-wallet-key-lifecycle`.

## Creation

The domain starts onboarding with:

```text
StartCreate
    -> GenerateKeyMaterial
```

The runtime executes that effect with a device-owned `EntropySource`. `KeyLifecycle`
generates 128–256 bits of entropy and creates a BIP-39 mnemonic, but keeps the root only
in staged volatile state.

The staged root is deliberately **not persisted** while the user is still viewing or
verifying the backup:

```text
GenerateKeyMaterial
    -> KeyMaterialReady
    -> ShowBackup
    -> ChallengeBackup
    -> BackupVerified
    -> ConfigurePin
    -> PersistProvisioning
```

Only `PersistProvisioning` may call `RootSecretStore::persist_root`. A failed durable
commit leaves the same staged root available for retry; the reducer must not receive
`ProvisioningPersisted` until that commit succeeds.

## Recovery

A validated BIP-39 mnemonic is converted back to its entropy and staged through the
same durable-commit boundary. Recovery therefore has the same power-loss semantics as
creation: before the commit there is no installed wallet; after the commit the root can
be reopened after reboot.

## Passphrase wallets

The persisted root is converted to the BIP-39 512-bit seed only when opening a wallet
context. A passphrase produces a different ephemeral `WalletContextId` and seed:

```text
persisted root entropy
        +
normalized passphrase
        |
        v
BIP-39 PBKDF2-HMAC-SHA512
        |
        v
WalletContextId + 64-byte seed
```

The passphrase and seed do not enter `wallet-core::State`. `SessionOpened` receives only
the opaque `WalletContextId`, which later becomes part of the authorized `KeyLocator`.

The current heap-free reference input accepts ASCII passphrases, which are already NFKD.
Non-ASCII text fails closed until a fixed-capacity or streaming Unicode NFKD normalizer
is added to the device-input layer.

## HD derivation

The ephemeral context seed feeds `hd-key-backend`:

- BIP-32 for secp256k1;
- hardened-only SLIP-0010 for Ed25519.

Account roots remain device-owned metadata, while requests carry only paths relative to
those roots.

## Storage contract

`RootSecretStore` is a capability, not a storage format. A production implementation
must guarantee:

- atomic durable commit before returning success;
- fail-closed reads on corruption or authentication failure;
- integrity/authenticity protection when the medium is not intrinsically trusted;
- durable wipe semantics;
- no exposure of the root through host-controlled APIs.

`MemorySecretStore` exists only under `test-utils`; it is intentionally non-durable and
must never be treated as a production secret store.

## Entropy contract

`EntropySource` is also a capability. Production firmware must bind it to the selected
MCU/secure-element random source and implement the required health checks. The host must
never provide wallet-generation entropy.

`FixedEntropySource` is deterministic test infrastructure only.

## What CI proves

Unit/regression tests currently prove:

- the official BIP-39 zero-entropy mnemonic/`TREZOR` seed vector;
- create and recovery reopen the same seed after a simulated reboot;
- different passphrases create different wallet contexts and seeds;
- uncommitted roots disappear on cancel and never reach persistent storage;
- wipe removes the installed root;
- non-ASCII passphrases fail closed without a normalizer;
- a failed durable commit keeps the staged root retryable;
- wallet-domain Effects drive the lifecycle without putting secret bytes into domain state.

The chain integration workflow goes further. Bitcoin, Ethereum and Solana each start
from deterministic **device entropy**, create a BIP-39 wallet, open a base wallet
context, derive the chain account, sign locally, and submit the transaction to a clean
local node.

## Still outside this layer

This crate does not claim production secret protection. Remaining hardware work includes:

- a real MCU/secure-element `EntropySource`;
- a durable authenticated `RootSecretStore` implementation;
- the final decision on which secret material lives in MCU flash versus the secure element;
- hardware-backed zeroization and debug/fault-injection policy;
- non-ASCII NFKD input support;
- firmware composition that maps the reducer Effects to these capabilities.
