# Bitcoin support

The current adapter intentionally supports a narrow PSBT subset that the device can fully parse and verify without trusting host-decoded transaction metadata.

## Supported

- PSBT v0.
- Exactly one input and one output.
- Native SegWit P2WPKH input with `witness_utxo`.
- Native SegWit P2WPKH output.
- `SIGHASH_ALL` only.
- Device-owned review of input amount, output amount, destination witness program and fee.
- Compressed secp256k1 public-key derivation.
- `HASH160(derived_pubkey)` equality check against the input witness program before any signing request.
- BIP143 component hashes and signing preimage assembled by the adapter.
- Double-SHA256 + non-recoverable secp256k1 ECDSA through the generic crypto runtime.
- Low-S compact signature validation, canonical DER encoding and final SegWit transaction serialization.

## Rejected for now

- Multiple inputs or outputs.
- Legacy inputs.
- P2SH-wrapped SegWit.
- Multisig and script-path spending.
- Taproot / PSBT v2.
- Sighash modes other than `SIGHASH_ALL`.
- Unknown global/input/output fields outside the explicitly accepted subset.
- Bitcoin message signing.

Unsupported PSBTs fail closed rather than being downgraded to blind signing. The local CI compatibility test uses Bitcoin Core regtest with a deterministic descriptor wallet and compares the finalized raw transaction byte-for-byte before broadcasting it.
