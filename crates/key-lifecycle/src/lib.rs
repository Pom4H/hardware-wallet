#![no_std]

use bip39::{Language, Mnemonic};
use hardware_wallet_core::WalletContextId;
use zeroize::{Zeroize, Zeroizing};

const MAX_ROOT_ENTROPY_BYTES: usize = 32;
const MAX_PASSPHRASE_BYTES: usize = 128;

/// Device-owned cryptographic entropy source.
///
/// Production implementations must use a hardware-backed CSPRNG/TRNG health-
/// checked according to the selected MCU and board design. The host must never
/// implement this capability.
pub trait EntropySource {
    type Error;

    fn fill(&mut self, output: &mut [u8]) -> Result<(), Self::Error>;
}

/// Durable storage for the wallet root entropy.
///
/// A production implementation must return from `persist_root` only after an
/// atomic durable commit. If the underlying medium is not intrinsically trusted,
/// the record must also be integrity/authenticity protected. `load_root` must
/// fail closed on corruption and `wipe_root` must make the previous root
/// unavailable before it reports success.
pub trait RootSecretStore {
    type Error;

    fn persist_root(&mut self, root: &[u8]) -> Result<(), Self::Error>;
    fn load_root(
        &mut self,
        output: &mut [u8; MAX_ROOT_ENTROPY_BYTES],
    ) -> Result<Option<usize>, Self::Error>;
    fn wipe_root(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MnemonicSize {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl MnemonicSize {
    #[must_use]
    pub const fn entropy_len(self) -> usize {
        match self {
            Self::Words12 => 16,
            Self::Words15 => 20,
            Self::Words18 => 24,
            Self::Words21 => 28,
            Self::Words24 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassphraseError {
    TooLong,
    NonAsciiNeedsNormalizer,
}

/// A BIP-39 passphrase already known to be valid NFKD text.
///
/// The heap-free reference implementation currently constructs this type only
/// from ASCII, because ASCII is already NFKD. A future device UI may add a
/// streaming/fixed-capacity Unicode normalizer without changing the key
/// lifecycle or wallet-domain APIs.
pub struct NormalizedPassphrase {
    bytes: [u8; MAX_PASSPHRASE_BYTES],
    len: u8,
}

impl NormalizedPassphrase {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_PASSPHRASE_BYTES],
            len: 0,
        }
    }

    /// Creates a normalized passphrase from ASCII input.
    ///
    /// # Errors
    ///
    /// Returns an error for non-ASCII text or input exceeding the fixed device
    /// passphrase budget.
    pub fn from_ascii(value: &str) -> Result<Self, PassphraseError> {
        if !value.is_ascii() {
            return Err(PassphraseError::NonAsciiNeedsNormalizer);
        }
        if value.len() > MAX_PASSPHRASE_BYTES {
            return Err(PassphraseError::TooLong);
        }
        let mut bytes = [0_u8; MAX_PASSPHRASE_BYTES];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: u8::try_from(value.len()).map_err(|_| PassphraseError::TooLong)?,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        // Constructors admit ASCII only, therefore this byte range is valid UTF-8.
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).expect("ASCII is UTF-8")
    }
}

impl Drop for NormalizedPassphrase {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len.zeroize();
    }
}

#[derive(Debug)]
pub enum Error<StoreError, EntropyError> {
    PendingProvisioning,
    NoPendingProvisioning,
    RootNotFound,
    InvalidStoredRoot,
    ContextIdExhausted,
    Bip39(bip39::Error),
    Store(StoreError),
    Entropy(EntropyError),
}

struct PendingRoot {
    entropy: Zeroizing<[u8; MAX_ROOT_ENTROPY_BYTES]>,
    len: u8,
    mnemonic: Mnemonic,
}

/// Owns the secret lifecycle outside the pure wallet reducer.
///
/// It maps generic domain effects onto concrete secret operations without ever
/// putting entropy, mnemonic words, passphrases or seeds into `wallet-core::State`.
pub struct KeyLifecycle<S, E> {
    store: S,
    entropy: E,
    pending: Option<PendingRoot>,
    next_context_id: u32,
}

impl<S, E> KeyLifecycle<S, E>
where
    S: RootSecretStore,
    E: EntropySource,
{
    #[must_use]
    pub const fn new(store: S, entropy: E) -> Self {
        Self {
            store,
            entropy,
            pending: None,
            next_context_id: 1,
        }
    }

    /// Generates fresh entropy and stages a BIP-39 recovery mnemonic.
    ///
    /// The root is deliberately not persisted yet. The runtime should display
    /// and verify the backup first and call [`Self::commit_pending`] only for
    /// the reducer's `PersistProvisioning` effect.
    ///
    /// # Errors
    ///
    /// Returns an error if another provisioning flow is already staged, entropy
    /// generation fails, or BIP-39 rejects the generated entropy length.
    pub fn begin_create(&mut self, size: MnemonicSize) -> Result<(), Error<S::Error, E::Error>> {
        if self.pending.is_some() {
            return Err(Error::PendingProvisioning);
        }

        let len = size.entropy_len();
        let mut entropy = Zeroizing::new([0_u8; MAX_ROOT_ENTROPY_BYTES]);
        self.entropy
            .fill(&mut entropy[..len])
            .map_err(Error::Entropy)?;
        let mnemonic =
            Mnemonic::from_entropy_in(Language::English, &entropy[..len]).map_err(Error::Bip39)?;
        self.pending = Some(PendingRoot {
            entropy,
            len: u8::try_from(len).map_err(|_| Error::InvalidStoredRoot)?,
            mnemonic,
        });
        Ok(())
    }

    /// Stages an already validated BIP-39 recovery mnemonic.
    ///
    /// # Errors
    ///
    /// Returns an error when another provisioning flow is already staged or the
    /// mnemonic decodes to an unsupported root length.
    pub fn begin_recovery(&mut self, mnemonic: Mnemonic) -> Result<(), Error<S::Error, E::Error>> {
        if self.pending.is_some() {
            return Err(Error::PendingProvisioning);
        }

        let (mut source, len) = mnemonic.to_entropy_array();
        if !is_valid_root_len(len) {
            source.zeroize();
            return Err(Error::InvalidStoredRoot);
        }
        let mut entropy = Zeroizing::new([0_u8; MAX_ROOT_ENTROPY_BYTES]);
        entropy[..len].copy_from_slice(&source[..len]);
        source.zeroize();
        self.pending = Some(PendingRoot {
            entropy,
            len: u8::try_from(len).map_err(|_| Error::InvalidStoredRoot)?,
            mnemonic,
        });
        Ok(())
    }

    /// Returns the staged recovery mnemonic for on-device backup rendering.
    #[must_use]
    pub fn pending_mnemonic(&self) -> Option<&Mnemonic> {
        self.pending.as_ref().map(|pending| &pending.mnemonic)
    }

    /// Durably installs the staged root after backup/PIN onboarding succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when no root is staged or the secure store fails. A
    /// failed store operation leaves the pending root available for retry.
    pub fn commit_pending(&mut self) -> Result<(), Error<S::Error, E::Error>> {
        let pending = self.pending.as_ref().ok_or(Error::NoPendingProvisioning)?;
        let len = usize::from(pending.len);
        self.store
            .persist_root(&pending.entropy[..len])
            .map_err(Error::Store)?;
        self.pending = None;
        Ok(())
    }

    /// Discards any uncommitted onboarding/recovery secret.
    pub fn cancel_pending(&mut self) {
        self.pending = None;
    }

    /// Opens an ephemeral wallet/passphrase context from the persisted root.
    ///
    /// The returned seed and identifier are session-scoped. Hidden-wallet
    /// passphrases are never persisted or placed in reducer state.
    ///
    /// # Errors
    ///
    /// Returns an error if no root is provisioned, stored material is malformed,
    /// BIP-39 derivation fails, or the ephemeral context-id space is exhausted.
    pub fn open_context(
        &mut self,
        passphrase: &NormalizedPassphrase,
    ) -> Result<WalletContext, Error<S::Error, E::Error>> {
        let mut root = Zeroizing::new([0_u8; MAX_ROOT_ENTROPY_BYTES]);
        let len = self
            .store
            .load_root(&mut root)
            .map_err(Error::Store)?
            .ok_or(Error::RootNotFound)?;
        if !is_valid_root_len(len) {
            return Err(Error::InvalidStoredRoot);
        }
        let mnemonic = Mnemonic::from_entropy(&root[..len]).map_err(Error::Bip39)?;
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(passphrase.as_str()));

        let current = self.next_context_id;
        self.next_context_id = current.checked_add(1).ok_or(Error::ContextIdExhausted)?;
        Ok(WalletContext {
            id: WalletContextId(current),
            seed,
        })
    }

    /// Removes pending and persisted wallet roots.
    ///
    /// # Errors
    ///
    /// Returns the secure-store error if durable wipe fails.
    pub fn wipe(&mut self) -> Result<(), Error<S::Error, E::Error>> {
        self.pending = None;
        self.store.wipe_root().map_err(Error::Store)?;
        self.next_context_id = 1;
        Ok(())
    }

    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    #[must_use]
    pub fn into_parts(self) -> (S, E) {
        let Self {
            store,
            entropy,
            pending: _,
            next_context_id: _,
        } = self;
        (store, entropy)
    }
}

fn is_valid_root_len(len: usize) -> bool {
    matches!(len, 16 | 20 | 24 | 28 | 32)
}

/// Ephemeral seed material for one unlocked base/hidden-wallet context.
pub struct WalletContext {
    id: WalletContextId,
    seed: Zeroizing<[u8; 64]>,
}

impl WalletContext {
    #[must_use]
    pub const fn id(&self) -> WalletContextId {
        self.id
    }

    #[must_use]
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use core::convert::Infallible;

    use super::{EntropySource, MAX_ROOT_ENTROPY_BYTES, RootSecretStore};
    use zeroize::Zeroize;

    /// Deterministic entropy source for tests and emulators only.
    pub struct FixedEntropySource {
        bytes: [u8; MAX_ROOT_ENTROPY_BYTES],
    }

    impl FixedEntropySource {
        #[must_use]
        pub const fn new(bytes: [u8; MAX_ROOT_ENTROPY_BYTES]) -> Self {
            Self { bytes }
        }
    }

    impl EntropySource for FixedEntropySource {
        type Error = Infallible;

        fn fill(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.copy_from_slice(&self.bytes[..output.len()]);
            Ok(())
        }
    }

    impl Drop for FixedEntropySource {
        fn drop(&mut self) {
            self.bytes.zeroize();
        }
    }

    /// Non-durable test store. Production firmware must provide a real secure
    /// implementation of `RootSecretStore`.
    pub struct MemorySecretStore {
        root: [u8; MAX_ROOT_ENTROPY_BYTES],
        len: u8,
        present: bool,
    }

    impl MemorySecretStore {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                root: [0; MAX_ROOT_ENTROPY_BYTES],
                len: 0,
                present: false,
            }
        }

        #[must_use]
        pub const fn is_provisioned(&self) -> bool {
            self.present
        }
    }

    impl Default for MemorySecretStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RootSecretStore for MemorySecretStore {
        type Error = Infallible;

        fn persist_root(&mut self, root: &[u8]) -> Result<(), Self::Error> {
            self.root.zeroize();
            self.root[..root.len()].copy_from_slice(root);
            self.len = u8::try_from(root.len()).expect("root length fits u8");
            self.present = true;
            Ok(())
        }

        fn load_root(
            &mut self,
            output: &mut [u8; MAX_ROOT_ENTROPY_BYTES],
        ) -> Result<Option<usize>, Self::Error> {
            if !self.present {
                return Ok(None);
            }
            let len = usize::from(self.len);
            output[..len].copy_from_slice(&self.root[..len]);
            Ok(Some(len))
        }

        fn wipe_root(&mut self) -> Result<(), Self::Error> {
            self.root.zeroize();
            self.len = 0;
            self.present = false;
            Ok(())
        }
    }

    impl Drop for MemorySecretStore {
        fn drop(&mut self) {
            self.root.zeroize();
            self.len.zeroize();
            self.present = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::{FixedEntropySource, MemorySecretStore};
    use super::*;

    const ZERO_ENTROPY: [u8; 32] = [0; 32];

    #[test]
    fn create_matches_official_bip39_vector() {
        let mut lifecycle = KeyLifecycle::new(
            MemorySecretStore::new(),
            FixedEntropySource::new(ZERO_ENTROPY),
        );
        lifecycle
            .begin_create(MnemonicSize::Words12)
            .expect("generate mnemonic");
        let mnemonic = lifecycle.pending_mnemonic().expect("pending backup");
        let expected = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ];
        assert!(mnemonic.words().eq(expected));

        lifecycle.commit_pending().expect("persist root");
        let passphrase = NormalizedPassphrase::from_ascii("TREZOR").expect("ASCII passphrase");
        let context = lifecycle
            .open_context(&passphrase)
            .expect("derive BIP39 seed");
        assert_eq!(
            context.seed(),
            &decode_hex::<64>(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
                 1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
        );
    }

    #[test]
    fn recovery_and_reboot_reopen_same_seed() {
        let mnemonic = Mnemonic::from_entropy(&[0_u8; 16]).expect("vector mnemonic");
        let mut lifecycle =
            KeyLifecycle::new(MemorySecretStore::new(), FixedEntropySource::new([7; 32]));
        lifecycle.begin_recovery(mnemonic).expect("stage recovery");
        lifecycle.commit_pending().expect("persist recovered root");
        let empty = NormalizedPassphrase::empty();
        let before = *lifecycle
            .open_context(&empty)
            .expect("open before reboot")
            .seed();

        let (store, entropy) = lifecycle.into_parts();
        let mut rebooted = KeyLifecycle::new(store, entropy);
        let after = *rebooted
            .open_context(&empty)
            .expect("open after reboot")
            .seed();
        assert_eq!(before, after);
    }

    #[test]
    fn passphrases_create_distinct_ephemeral_contexts() {
        let mut lifecycle =
            KeyLifecycle::new(MemorySecretStore::new(), FixedEntropySource::new([3; 32]));
        lifecycle
            .begin_create(MnemonicSize::Words24)
            .expect("create");
        lifecycle.commit_pending().expect("commit");

        let base = lifecycle
            .open_context(&NormalizedPassphrase::empty())
            .expect("base wallet");
        let hidden = lifecycle
            .open_context(&NormalizedPassphrase::from_ascii("hidden").expect("ASCII"))
            .expect("hidden wallet");
        assert_ne!(base.id(), hidden.id());
        assert_ne!(base.seed(), hidden.seed());
    }

    #[test]
    fn uncommitted_root_disappears_on_cancel() {
        let mut lifecycle =
            KeyLifecycle::new(MemorySecretStore::new(), FixedEntropySource::new([5; 32]));
        lifecycle
            .begin_create(MnemonicSize::Words12)
            .expect("create");
        lifecycle.cancel_pending();
        assert!(lifecycle.pending_mnemonic().is_none());
        assert!(!lifecycle.store().is_provisioned());
        assert!(matches!(
            lifecycle.open_context(&NormalizedPassphrase::empty()),
            Err(Error::RootNotFound)
        ));
    }

    #[test]
    fn wipe_removes_persisted_root() {
        let mut lifecycle =
            KeyLifecycle::new(MemorySecretStore::new(), FixedEntropySource::new([9; 32]));
        lifecycle
            .begin_create(MnemonicSize::Words12)
            .expect("create");
        lifecycle.commit_pending().expect("commit");
        lifecycle.wipe().expect("wipe");
        assert!(!lifecycle.store().is_provisioned());
        assert!(matches!(
            lifecycle.open_context(&NormalizedPassphrase::empty()),
            Err(Error::RootNotFound)
        ));
    }

    #[test]
    fn non_ascii_passphrase_fails_closed_without_normalizer() {
        assert_eq!(
            NormalizedPassphrase::from_ascii("пароль").err(),
            Some(PassphraseError::NonAsciiNeedsNormalizer)
        );
    }

    fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
        let compact = input.as_bytes();
        let mut output = [0_u8; N];
        let mut index = 0_usize;
        let mut high = None;
        for byte in compact
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
        {
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex"),
            };
            if let Some(first) = high.take() {
                output[index] = (first << 4) | nibble;
                index += 1;
            } else {
                high = Some(nibble);
            }
        }
        assert!(high.is_none());
        assert_eq!(index, N);
        output
    }
}
