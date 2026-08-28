#![no_std]

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hardware_wallet_chain_api::{
    BoundedBytes, CryptoOperation, CryptoOutput, Curve, HashAlgorithm, KeyLocator,
    MAX_DIGEST_BYTES, MAX_PUBLIC_KEY_BYTES, PublicKeyFormat, SignatureScheme,
};
use hardware_wallet_core::{KeyTarget, WalletContextId};
use k256::ecdsa::{Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512_256};
use sha3::Keccak256;
use signature::Signer;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongWallet,
    WrongKeyTarget,
    InvalidSecret,
    MissingPayload,
    UnexpectedPayload,
    UnsupportedPublicKeyFormat,
    UnsupportedHash,
    UnsupportedSignatureScheme,
    CapacityExceeded,
}

struct Secret32([u8; 32]);

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

enum SoftwareSecret {
    Secp256k1(Secret32),
    Ed25519(Secret32),
}

/// Minimal in-memory key backend used by host tests and emulation.
///
/// It is deliberately bound to exactly one authorized wallet context and one
/// key target. Production hardware can replace this backend without changing
/// chain adapters or [`CryptoRuntime`].
pub struct SoftwareKeyBackend {
    wallet: WalletContextId,
    target: KeyTarget,
    secret: SoftwareSecret,
}

impl SoftwareKeyBackend {
    /// Creates a single-key secp256k1 backend.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSecret`] if `secret` is not a valid non-zero
    /// secp256k1 scalar.
    pub fn secp256k1(
        wallet: WalletContextId,
        target: KeyTarget,
        secret: [u8; 32],
    ) -> Result<Self, Error> {
        Secp256k1SigningKey::from_slice(&secret).map_err(|_| Error::InvalidSecret)?;
        Ok(Self {
            wallet,
            target,
            secret: SoftwareSecret::Secp256k1(Secret32(secret)),
        })
    }

    #[must_use]
    pub const fn ed25519(wallet: WalletContextId, target: KeyTarget, secret: [u8; 32]) -> Self {
        Self {
            wallet,
            target,
            secret: SoftwareSecret::Ed25519(Secret32(secret)),
        }
    }

    fn authorize(&self, key: KeyLocator) -> Result<(), Error> {
        if key.wallet() != self.wallet {
            return Err(Error::WrongWallet);
        }
        if key.target() != self.target {
            return Err(Error::WrongKeyTarget);
        }
        Ok(())
    }

    fn derive_public_key(
        &self,
        key: KeyLocator,
        format: PublicKeyFormat,
    ) -> Result<BoundedBytes<MAX_PUBLIC_KEY_BYTES>, Error> {
        self.authorize(key)?;
        match &self.secret {
            SoftwareSecret::Secp256k1(secret) => {
                let signing =
                    Secp256k1SigningKey::from_slice(&secret.0).map_err(|_| Error::InvalidSecret)?;
                let verifying = signing.verifying_key();
                match format {
                    PublicKeyFormat::Compressed => {
                        let point = verifying.to_sec1_point(true);
                        bounded_public_key(point.as_bytes())
                    }
                    PublicKeyFormat::Uncompressed => {
                        let point = verifying.to_sec1_point(false);
                        bounded_public_key(point.as_bytes())
                    }
                    PublicKeyFormat::XOnly => {
                        let point = verifying.to_sec1_point(false);
                        bounded_public_key(&point.as_bytes()[1..33])
                    }
                    PublicKeyFormat::Raw => {
                        let point = verifying.to_sec1_point(false);
                        bounded_public_key(&point.as_bytes()[1..])
                    }
                    PublicKeyFormat::Extended | PublicKeyFormat::Custom(_) => {
                        Err(Error::UnsupportedPublicKeyFormat)
                    }
                }
            }
            SoftwareSecret::Ed25519(secret) => {
                if format != PublicKeyFormat::Raw {
                    return Err(Error::UnsupportedPublicKeyFormat);
                }
                let signing = Ed25519SigningKey::from_bytes(&secret.0);
                bounded_public_key(signing.verifying_key().as_bytes())
            }
        }
    }

    fn sign(
        &self,
        key: KeyLocator,
        scheme: SignatureScheme,
        prehash: HashAlgorithm,
        payload: &[u8],
    ) -> Result<CryptoOutput, Error> {
        self.authorize(key)?;
        match (&self.secret, scheme) {
            (
                SoftwareSecret::Secp256k1(secret),
                SignatureScheme::Ecdsa {
                    curve: Curve::Secp256k1,
                    recoverable,
                },
            ) => {
                let signing =
                    Secp256k1SigningKey::from_slice(&secret.0).map_err(|_| Error::InvalidSecret)?;
                let digest = prehash32(prehash, payload)?;
                let (signature, recovery_id): (Secp256k1Signature, _) =
                    signing.sign_prehash_recoverable(&digest);
                let compact = signature.to_bytes();
                let bytes = BoundedBytes::from_slice(compact.as_slice())
                    .map_err(|_| Error::CapacityExceeded)?;
                Ok(CryptoOutput::Signature {
                    scheme,
                    bytes,
                    recovery_id: recoverable.then(|| recovery_id.to_byte()),
                })
            }
            (SoftwareSecret::Ed25519(secret), SignatureScheme::Ed25519) => {
                if prehash != HashAlgorithm::None {
                    return Err(Error::UnsupportedHash);
                }
                let signing = Ed25519SigningKey::from_bytes(&secret.0);
                let signature = signing.sign(payload);
                let bytes = BoundedBytes::from_slice(&signature.to_bytes())
                    .map_err(|_| Error::CapacityExceeded)?;
                Ok(CryptoOutput::Signature {
                    scheme,
                    bytes,
                    recovery_id: None,
                })
            }
            _ => Err(Error::UnsupportedSignatureScheme),
        }
    }
}

/// Executes generic cryptographic work requested by an approved chain session.
pub struct CryptoRuntime<B> {
    backend: B,
}

impl<B> CryptoRuntime<B> {
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }
}

impl CryptoRuntime<SoftwareKeyBackend> {
    /// Executes one generic crypto operation.
    ///
    /// `payload` must be `None` for public-key derivation and must contain the
    /// chain-owned bytes referenced by `PayloadId` for hash/sign operations.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for an unauthorized key, missing payload,
    /// unsupported algorithm or invalid secret.
    pub fn execute(
        &self,
        operation: CryptoOperation,
        payload: Option<&[u8]>,
    ) -> Result<CryptoOutput, Error> {
        match operation {
            CryptoOperation::DerivePublicKey { key, format } => {
                if payload.is_some() {
                    return Err(Error::UnexpectedPayload);
                }
                let bytes = self.backend.derive_public_key(key, format)?;
                Ok(CryptoOutput::PublicKey { format, bytes })
            }
            CryptoOperation::Hash { algorithm, .. } => {
                let payload = payload.ok_or(Error::MissingPayload)?;
                let bytes = hash(algorithm, payload)?;
                Ok(CryptoOutput::Digest { algorithm, bytes })
            }
            CryptoOperation::Sign {
                key,
                scheme,
                prehash,
                ..
            } => {
                let payload = payload.ok_or(Error::MissingPayload)?;
                self.backend.sign(key, scheme, prehash, payload)
            }
        }
    }
}

fn bounded_public_key(value: &[u8]) -> Result<BoundedBytes<MAX_PUBLIC_KEY_BYTES>, Error> {
    BoundedBytes::from_slice(value).map_err(|_| Error::CapacityExceeded)
}

fn hash(algorithm: HashAlgorithm, payload: &[u8]) -> Result<BoundedBytes<MAX_DIGEST_BYTES>, Error> {
    match algorithm {
        HashAlgorithm::Sha256 => bounded_digest(&Sha256::digest(payload)),
        HashAlgorithm::DoubleSha256 => {
            let first = Sha256::digest(payload);
            bounded_digest(&Sha256::digest(first))
        }
        HashAlgorithm::Hash160 => {
            let sha = Sha256::digest(payload);
            bounded_digest(&Ripemd160::digest(sha))
        }
        HashAlgorithm::Keccak256 => bounded_digest(&Keccak256::digest(payload)),
        HashAlgorithm::Sha512_256 => bounded_digest(&Sha512_256::digest(payload)),
        HashAlgorithm::None
        | HashAlgorithm::Blake2b256
        | HashAlgorithm::Blake2b512
        | HashAlgorithm::Custom(_) => Err(Error::UnsupportedHash),
    }
}

fn bounded_digest(value: &[u8]) -> Result<BoundedBytes<MAX_DIGEST_BYTES>, Error> {
    BoundedBytes::from_slice(value).map_err(|_| Error::CapacityExceeded)
}

fn prehash32(algorithm: HashAlgorithm, payload: &[u8]) -> Result<[u8; 32], Error> {
    let digest = match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(payload),
        HashAlgorithm::DoubleSha256 => Sha256::digest(Sha256::digest(payload)),
        HashAlgorithm::Keccak256 => {
            let digest = Keccak256::digest(payload);
            let mut output = [0_u8; 32];
            output.copy_from_slice(&digest);
            return Ok(output);
        }
        HashAlgorithm::Sha512_256 => {
            let digest = Sha512_256::digest(payload);
            let mut output = [0_u8; 32];
            output.copy_from_slice(&digest);
            return Ok(output);
        }
        HashAlgorithm::None
        | HashAlgorithm::Hash160
        | HashAlgorithm::Blake2b256
        | HashAlgorithm::Blake2b512
        | HashAlgorithm::Custom(_) => return Err(Error::UnsupportedHash),
    };
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardware_wallet_chain_api::PayloadId;
    use hardware_wallet_core::{AccountId, DerivationPath, KeyPurpose};

    fn target() -> KeyTarget {
        KeyTarget {
            account: AccountId(0),
            path: DerivationPath::new(),
            purpose: KeyPurpose::ExternalAddress,
        }
    }

    fn locator() -> KeyLocator {
        let mut state = hardware_wallet_core::State::default();
        let setup = hardware_wallet_core::SetupId(1);
        let auth = hardware_wallet_core::AuthId(2);
        let host = hardware_wallet_core::HostId(3);
        state = hardware_wallet_core::update(
            state,
            hardware_wallet_core::Event::StartCreate {
                id: setup,
                passphrase: hardware_wallet_core::PassphraseMode::Disabled,
            },
        )
        .state;
        state = hardware_wallet_core::update(
            state,
            hardware_wallet_core::Event::KeyMaterialReady(setup),
        )
        .state;
        state =
            hardware_wallet_core::update(state, hardware_wallet_core::Event::BackupShown(setup))
                .state;
        state =
            hardware_wallet_core::update(state, hardware_wallet_core::Event::BackupVerified(setup))
                .state;
        state =
            hardware_wallet_core::update(state, hardware_wallet_core::Event::PinConfigured(setup))
                .state;
        state = hardware_wallet_core::update(
            state,
            hardware_wallet_core::Event::ProvisioningPersisted(setup),
        )
        .state;
        state = hardware_wallet_core::update(
            state,
            hardware_wallet_core::Event::UnlockRequested { id: auth, host },
        )
        .state;
        state = hardware_wallet_core::update(
            state,
            hardware_wallet_core::Event::HostTrustResolved {
                id: auth,
                trust: hardware_wallet_core::HostTrust::Trusted,
            },
        )
        .state;
        state = hardware_wallet_core::update(state, hardware_wallet_core::Event::PinVerified(auth))
            .state;
        state = hardware_wallet_core::update(
            state,
            hardware_wallet_core::Event::SessionOpened {
                auth,
                session: hardware_wallet_core::SessionId(4),
                wallet: WalletContextId(5),
            },
        )
        .state;
        state
            .execution_context()
            .expect("unlocked")
            .bind_key(target())
    }

    #[test]
    fn secp256k1_scalar_one_derives_generator_pubkey() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let backend = SoftwareKeyBackend::secp256k1(WalletContextId(5), target(), secret)
            .expect("scalar one");
        let runtime = CryptoRuntime::new(backend);
        let output = runtime
            .execute(
                CryptoOperation::DerivePublicKey {
                    key: locator(),
                    format: PublicKeyFormat::Compressed,
                },
                None,
            )
            .expect("derive");
        let CryptoOutput::PublicKey { bytes, .. } = output else {
            panic!("expected public key")
        };
        assert_eq!(
            bytes.as_slice(),
            &[
                0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98,
            ]
        );
    }

    #[test]
    fn hash160_is_available_to_chain_executions() {
        let backend = SoftwareKeyBackend::ed25519(WalletContextId(5), target(), [7; 32]);
        let runtime = CryptoRuntime::new(backend);
        let output = runtime
            .execute(
                CryptoOperation::Hash {
                    algorithm: HashAlgorithm::Hash160,
                    payload: PayloadId(1),
                },
                Some(b"abc"),
            )
            .expect("hash");
        let CryptoOutput::Digest { bytes, .. } = output else {
            panic!("expected digest")
        };
        assert_eq!(bytes.len(), 20);
    }
}
