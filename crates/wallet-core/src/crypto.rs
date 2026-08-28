use crate::KeyLocator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Curve {
    Secp256k1,
    Ed25519,
    P256,
    Sr25519,
    Bls12381,
    Custom(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureScheme {
    Ecdsa {
        curve: Curve,
        recoverable: bool,
    },
    SchnorrSecp256k1,
    Ed25519,
    Sr25519,
    Bls12381,
    Custom(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    None,
    Sha256,
    DoubleSha256,
    Keccak256,
    Blake2b256,
    Blake2b512,
    Sha512_256,
    Custom(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyFormat {
    Raw,
    Compressed,
    Uncompressed,
    XOnly,
    Extended,
    Custom(u16),
}

/// Opaque handle to bytes owned by the chain/runtime boundary.
///
/// The wallet domain never stores transaction, message, digest or secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoOperation {
    DerivePublicKey {
        key: KeyLocator,
        format: PublicKeyFormat,
    },
    Sign {
        key: KeyLocator,
        scheme: SignatureScheme,
        prehash: HashAlgorithm,
        payload: PayloadId,
    },
}

impl CryptoOperation {
    #[must_use]
    pub const fn uses_private_key(self) -> bool {
        matches!(self, Self::Sign { .. })
    }

    #[must_use]
    pub const fn key(self) -> KeyLocator {
        match self {
            Self::DerivePublicKey { key, .. } | Self::Sign { key, .. } => key,
        }
    }
}
