# Solana support

The current adapter supports a deliberately narrow transaction class that the device can fully parse and explain.

## Supported

- Legacy Solana messages.
- Exactly one required signer; the signer is also the fee payer.
- Exactly three account keys: signer, recipient, System Program.
- Exactly one System Program `Transfer` instruction.
- Device-owned review of signer, recipient, recent blockhash and lamport amount.
- Raw Ed25519 signing of the exact serialized message.
- Public-key derivation and equality check against the required signer before any signature is requested.
- Final transaction serialization with one 64-byte signature.

## Rejected for now

- Versioned messages and address lookup tables.
- Multiple signers.
- Multiple instructions.
- Arbitrary programs and program data.
- Stake, token and memo instructions.
- Standalone message signing.

Unsupported messages fail closed. The adapter does not downgrade an unknown program or instruction to blind signing.
