#![no_std]

use bip32::{
    ChildNumber as Bip32ChildNumber, Error as Bip32Error, ExtendedPrivateKey,
    PrivateKey as Bip32PrivateKey, PrivateKeyBytes, PublicKey as Bip32PublicKey, PublicKeyBytes,
};
use hardware_wallet_core::{AccountDescriptor, AccountKind, ChildNumber, KeyLocator, KeyTarget};
use hardware_wallet_crypto_runtime::{Error as RuntimeError, SoftwareKeyBackend};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;
const MAX_SEED_BYTES: usize = 64;
const MIN_SEED_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFamily {
    Secp256k1Bip32,
    Ed25519Slip10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSeedLength,
    AccountWalletMismatch,
    UnsupportedAccountKind,
    WrongWallet,
    WrongAccount,
    InvalidDerivation,
    Ed25519RequiresHardened,
    Runtime(RuntimeError),
}

impl From<RuntimeError> for Error {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct Seed {
    bytes: [u8; MAX_SEED_BYTES],
    len: u8,
}

impl Seed {
    fn from_slice(seed: &[u8]) -> Result<Self, Error> {
        if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&seed.len()) {
            return Err(Error::InvalidSeedLength);
        }
        let mut bytes = [0_u8; MAX_SEED_BYTES];
        bytes[..seed.len()].copy_from_slice(seed);
        Ok(Self {
            bytes,
            len: u8::try_from(seed.len()).map_err(|_| Error::InvalidSeedLength)?,
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len.zeroize();
    }
}

/// Heap-free HD key source bound to one device-owned account descriptor.
///
/// `AccountDescriptor::root` is trusted account metadata. The host supplies only
/// a path relative to that root through `KeyTarget`. The active wallet context is
/// still taken from `KeyLocator`, so a hidden/passphrase wallet cannot select the
/// base wallet's seed by changing request bytes.
pub struct HdKeyBackend {
    account: AccountDescriptor,
    family: KeyFamily,
    seed: Seed,
}

impl HdKeyBackend {
    /// Creates an HD backend for one already-authorized wallet account.
    ///
    /// # Errors
    ///
    /// Returns an error for non-HD accounts, inconsistent wallet metadata or a
    /// seed outside the BIP32/BIP39 128..512-bit input range.
    pub fn new(
        account: AccountDescriptor,
        family: KeyFamily,
        wallet_seed: &[u8],
    ) -> Result<Self, Error> {
        if account.kind != AccountKind::Hd {
            return Err(Error::UnsupportedAccountKind);
        }
        Ok(Self {
            account,
            family,
            seed: Seed::from_slice(wallet_seed)?,
        })
    }

    #[must_use]
    pub const fn account(&self) -> AccountDescriptor {
        self.account
    }

    #[must_use]
    pub const fn family(&self) -> KeyFamily {
        self.family
    }

    /// Materializes a one-operation software backend from the HD seed.
    ///
    /// This is the host/emulator composition path. Production firmware can
    /// replace it with a secure-element backend while keeping the account and
    /// derivation policy unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the locator is outside the bound wallet/account,
    /// derivation fails, or the derived secret is invalid for the selected
    /// signing backend.
    pub fn software_backend(&self, key: KeyLocator) -> Result<SoftwareKeyBackend, Error> {
        let secret = self.derive_secret(key)?;
        let target = key.target();
        match self.family {
            KeyFamily::Secp256k1Bip32 => SoftwareKeyBackend::secp256k1(
                self.account.wallet,
                target,
                *secret,
            )
            .map_err(Into::into),
            KeyFamily::Ed25519Slip10 => Ok(SoftwareKeyBackend::ed25519(
                self.account.wallet,
                target,
                *secret,
            )),
        }
    }

    fn authorize(&self, key: KeyLocator) -> Result<KeyTarget, Error> {
        if key.wallet() != self.account.wallet {
            return Err(Error::WrongWallet);
        }
        let target = key.target();
        if target.account != self.account.id {
            return Err(Error::WrongAccount);
        }
        Ok(target)
    }

    fn derive_secret(&self, key: KeyLocator) -> Result<Zeroizing<[u8; 32]>, Error> {
        let target = self.authorize(key)?;
        match self.family {
            KeyFamily::Secp256k1Bip32 => self.derive_secp256k1(target),
            KeyFamily::Ed25519Slip10 => self.derive_ed25519(target),
        }
    }

    fn derive_secp256k1(&self, target: KeyTarget) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut extended = ExtendedPrivateKey::<K256Private>::new(self.seed.as_slice())
            .map_err(|_| Error::InvalidDerivation)?;
        for child in self
            .account
            .root
            .as_slice()
            .iter()
            .chain(target.path.as_slice())
        {
            extended = extended
                .derive_child(to_bip32_child(*child)?)
                .map_err(|_| Error::InvalidDerivation)?;
        }
        Ok(Zeroizing::new(extended.to_bytes()))
    }

    fn derive_ed25519(&self, target: KeyTarget) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut node = Slip10Node::master(self.seed.as_slice())?;
        for child in self
            .account
            .root
            .as_slice()
            .iter()
            .chain(target.path.as_slice())
        {
            node = node.derive_child(*child)?;
        }
        Ok(node.key)
    }
}

fn to_bip32_child(child: ChildNumber) -> Result<Bip32ChildNumber, Error> {
    Bip32ChildNumber::new(child.index(), child.is_hardened())
        .map_err(|_| Error::InvalidDerivation)
}

struct Slip10Node {
    key: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl Slip10Node {
    fn master(seed: &[u8]) -> Result<Self, Error> {
        let mut hmac = HmacSha512::new_from_slice(b"ed25519 seed")
            .map_err(|_| Error::InvalidDerivation)?;
        hmac.update(seed);
        Self::from_hmac(hmac)
    }

    fn derive_child(&self, child: ChildNumber) -> Result<Self, Error> {
        if !child.is_hardened() {
            return Err(Error::Ed25519RequiresHardened);
        }
        let mut hmac = HmacSha512::new_from_slice(self.chain_code.as_ref())
            .map_err(|_| Error::InvalidDerivation)?;
        hmac.update(&[0]);
        hmac.update(self.key.as_ref());
        let encoded = child.index() | 0x8000_0000;
        hmac.update(&encoded.to_be_bytes());
        Self::from_hmac(hmac)
    }

    fn from_hmac(hmac: HmacSha512) -> Result<Self, Error> {
        let mut result = hmac.finalize().into_bytes();
        if result.len() != 64 {
            return Err(Error::InvalidDerivation);
        }
        let mut key = [0_u8; 32];
        let mut chain_code = [0_u8; 32];
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
        result.as_mut_slice().zeroize();
        Ok(Self {
            key: Zeroizing::new(key),
            chain_code: Zeroizing::new(chain_code),
        })
    }
}

struct K256Private(k256::SecretKey);
struct K256Public(k256::PublicKey);

impl Bip32PrivateKey for K256Private {
    type PublicKey = K256Public;

    fn from_bytes(bytes: &PrivateKeyBytes) -> bip32::Result<Self> {
        k256::SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| Bip32Error::Crypto)
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        self.0.to_bytes().into()
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> bip32::Result<Self> {
        let child_scalar = Option::<k256::NonZeroScalar>::from(
            k256::NonZeroScalar::from_repr(other.into()),
        )
        .ok_or(Bip32Error::Crypto)?;
        let derived = self.0.to_nonzero_scalar().as_ref() + child_scalar.as_ref();
        Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(derived))
            .map(|scalar| Self(scalar.into()))
            .ok_or(Bip32Error::Crypto)
    }

    fn public_key(&self) -> Self::PublicKey {
        K256Public(self.0.public_key())
    }
}

impl Bip32PublicKey for K256Public {
    fn from_bytes(bytes: PublicKeyBytes) -> bip32::Result<Self> {
        k256::PublicKey::from_sec1_bytes(&bytes)
            .map(Self)
            .map_err(|_| Bip32Error::Crypto)
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        let point = self.0.to_sec1_point(true);
        let mut output = [0_u8; 33];
        output.copy_from_slice(point.as_bytes());
        output
    }

    fn derive_child(&self, _other: PrivateKeyBytes) -> bip32::Result<Self> {
        // This provider is intentionally private-derivation-only. The wallet
        // never exports an xpub capability from which untrusted code can derive
        // descendants. Non-hardened private derivation still works because
        // `PrivateKey::derive_tweak` only needs this public serialization.
        Err(Bip32Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardware_wallet_core::{
        AccountId, AuthId, DerivationPath, Event, HostId, HostTrust, KeyPurpose, PassphraseMode,
        SessionId, SetupId, State, WalletContextId, update,
    };

    fn child(index: u32, hardened: bool) -> ChildNumber {
        ChildNumber::new(index, hardened).expect("valid child")
    }

    fn path(children: &[(u32, bool)]) -> DerivationPath {
        let mut path = DerivationPath::new();
        for &(index, hardened) in children {
            path.push(child(index, hardened)).expect("path fits");
        }
        path
    }

    fn descriptor(root: DerivationPath) -> AccountDescriptor {
        AccountDescriptor {
            id: AccountId(0),
            wallet: WalletContextId(5),
            kind: AccountKind::Hd,
            root,
        }
    }

    fn target(relative: DerivationPath) -> KeyTarget {
        KeyTarget {
            account: AccountId(0),
            path: relative,
            purpose: KeyPurpose::ExternalAddress,
        }
    }

    fn locator(target: KeyTarget) -> KeyLocator {
        let setup = SetupId(1);
        let auth = AuthId(2);
        let host = HostId(3);
        let mut state = State::default();
        state = update(
            state,
            Event::StartCreate {
                id: setup,
                passphrase: PassphraseMode::Disabled,
            },
        )
        .state;
        state = update(state, Event::KeyMaterialReady(setup)).state;
        state = update(state, Event::BackupShown(setup)).state;
        state = update(state, Event::BackupVerified(setup)).state;
        state = update(state, Event::PinConfigured(setup)).state;
        state = update(state, Event::ProvisioningPersisted(setup)).state;
        state = update(state, Event::UnlockRequested { id: auth, host }).state;
        state = update(
            state,
            Event::HostTrustResolved {
                id: auth,
                trust: HostTrust::Trusted,
            },
        )
        .state;
        state = update(state, Event::PinVerified(auth)).state;
        state = update(
            state,
            Event::SessionOpened {
                auth,
                session: SessionId(4),
                wallet: WalletContextId(5),
            },
        )
        .state;
        state
            .execution_context()
            .expect("unlocked")
            .bind_key(target)
    }

    #[test]
    fn bip32_matches_official_secp256k1_vector() {
        let seed = decode_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let backend = HdKeyBackend::new(
            descriptor(path(&[(0, true)])),
            KeyFamily::Secp256k1Bip32,
            &seed,
        )
        .expect("backend");
        let secret = backend
            .derive_secret(locator(target(path(&[(1, false)]))))
            .expect("derive m/0'/1");
        assert_eq!(
            *secret,
            decode_hex::<32>("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
        );
    }

    #[test]
    fn slip10_matches_official_ed25519_vector() {
        let seed = decode_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let backend = HdKeyBackend::new(
            descriptor(path(&[(0, true)])),
            KeyFamily::Ed25519Slip10,
            &seed,
        )
        .expect("backend");
        let secret = backend
            .derive_secret(locator(target(path(&[(1, true)]))))
            .expect("derive m/0'/1'");
        assert_eq!(
            *secret,
            decode_hex::<32>("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2")
        );
    }

    #[test]
    fn ed25519_rejects_non_hardened_children() {
        let seed = [7_u8; 32];
        let backend = HdKeyBackend::new(
            descriptor(path(&[(44, true), (501, true), (0, true)])),
            KeyFamily::Ed25519Slip10,
            &seed,
        )
        .expect("backend");
        assert_eq!(
            backend.derive_secret(locator(target(path(&[(0, false)])))),
            Err(Error::Ed25519RequiresHardened)
        );
    }

    #[test]
    fn account_and_wallet_are_capabilities_not_host_parameters() {
        let seed = [9_u8; 32];
        let backend = HdKeyBackend::new(
            descriptor(DerivationPath::new()),
            KeyFamily::Secp256k1Bip32,
            &seed,
        )
        .expect("backend");
        let wrong_account = KeyTarget {
            account: AccountId(7),
            path: DerivationPath::new(),
            purpose: KeyPurpose::ExternalAddress,
        };
        assert_eq!(
            backend.derive_secret(locator(wrong_account)),
            Err(Error::WrongAccount)
        );
    }

    fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut output = [0_u8; N];
        for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
            output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        output
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
