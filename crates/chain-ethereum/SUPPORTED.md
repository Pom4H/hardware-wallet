# Ethereum support

The current chain adapter intentionally supports a narrow, fully reviewable subset.

## Supported

- EIP-1559 typed transaction envelope (`0x02`).
- Canonical RLP decoding and encoding.
- Native ETH transfer to an existing 20-byte address.
- Empty calldata.
- Empty access list.
- Device-owned review of chain id, nonce, gas limit, max priority fee, max fee, destination and value.
- Recoverable secp256k1 ECDSA over `keccak256(0x02 || rlp(unsigned_fields))`.
- Reconstruction of the complete signed envelope from `(y_parity, r, s)`.

## Rejected for now

- Contract creation.
- Contract calldata / token transfers.
- Non-empty access lists.
- Personal-message signing.
- EIP-712 typed-data signing.
- Non-canonical or malformed RLP.

Unsupported requests fail closed instead of being downgraded to blind signing. New transaction classes should only move into the supported set once the device can independently parse and present the security-relevant meaning to the user.
