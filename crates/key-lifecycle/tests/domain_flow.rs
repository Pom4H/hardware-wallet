use core::convert::Infallible;

use hardware_wallet_core::{
    AccountId, AuthId, DerivationPath, Effect, Event, HostId, HostTrust, KeyPurpose, KeyTarget,
    PassphraseMode, SessionId, SetupId, State, update,
};
use hardware_wallet_key_lifecycle::{
    EntropySource, Error as LifecycleError, KeyLifecycle, MnemonicSize, NormalizedPassphrase,
    RootSecretStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreError {
    Injected,
}

struct TestStore {
    root: [u8; 32],
    len: usize,
    present: bool,
    fail_next_commit: bool,
}

impl TestStore {
    const fn new(fail_next_commit: bool) -> Self {
        Self {
            root: [0; 32],
            len: 0,
            present: false,
            fail_next_commit,
        }
    }
}

impl RootSecretStore for TestStore {
    type Error = StoreError;

    fn persist_root(&mut self, root: &[u8]) -> Result<(), Self::Error> {
        if self.fail_next_commit {
            self.fail_next_commit = false;
            return Err(StoreError::Injected);
        }
        self.root = [0; 32];
        self.root[..root.len()].copy_from_slice(root);
        self.len = root.len();
        self.present = true;
        Ok(())
    }

    fn load_root(&mut self, output: &mut [u8; 32]) -> Result<Option<usize>, Self::Error> {
        if !self.present {
            return Ok(None);
        }
        output[..self.len].copy_from_slice(&self.root[..self.len]);
        Ok(Some(self.len))
    }

    fn wipe_root(&mut self) -> Result<(), Self::Error> {
        self.root = [0; 32];
        self.len = 0;
        self.present = false;
        Ok(())
    }
}

struct TestEntropy([u8; 32]);

impl EntropySource for TestEntropy {
    type Error = Infallible;

    fn fill(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        output.copy_from_slice(&self.0[..output.len()]);
        Ok(())
    }
}

#[test]
fn domain_effects_drive_secret_lifecycle_without_secret_state() {
    let setup = SetupId(1);
    let auth = AuthId(2);
    let host = HostId(3);
    let session = SessionId(4);
    let mut lifecycle = KeyLifecycle::new(TestStore::new(false), TestEntropy([7; 32]));
    let mut state = State::default();

    let transition = update(
        state,
        Event::StartCreate {
            id: setup,
            passphrase: PassphraseMode::Optional,
        },
    );
    assert_eq!(transition.effect, Effect::GenerateKeyMaterial(setup));
    state = transition.state;

    lifecycle
        .begin_create(MnemonicSize::Words24)
        .expect("runtime executes GenerateKeyMaterial");
    assert!(lifecycle.pending_mnemonic().is_some());
    assert!(!lifecycle.store().present);

    let transition = update(state, Event::KeyMaterialReady(setup));
    assert_eq!(transition.effect, Effect::ShowBackup(setup));
    state = transition.state;

    let transition = update(state, Event::BackupShown(setup));
    assert_eq!(transition.effect, Effect::ChallengeBackup(setup));
    state = transition.state;

    let transition = update(state, Event::BackupVerified(setup));
    assert_eq!(transition.effect, Effect::ConfigurePin(setup));
    state = transition.state;

    let transition = update(state, Event::PinConfigured(setup));
    assert_eq!(transition.effect, Effect::PersistProvisioning(setup));
    state = transition.state;
    assert!(!lifecycle.store().present);

    lifecycle
        .commit_pending()
        .expect("runtime atomically executes PersistProvisioning");
    assert!(lifecycle.store().present);

    let transition = update(state, Event::ProvisioningPersisted(setup));
    assert_eq!(transition.effect, Effect::ProvisioningComplete(setup));
    state = transition.state;

    let transition = update(state, Event::UnlockRequested { id: auth, host });
    assert_eq!(
        transition.effect,
        Effect::ResolveHostTrust { id: auth, host }
    );
    state = transition.state;

    let transition = update(
        state,
        Event::HostTrustResolved {
            id: auth,
            trust: HostTrust::Trusted,
        },
    );
    assert_eq!(transition.effect, Effect::VerifyPin { id: auth, host });
    state = transition.state;

    let transition = update(state, Event::PinVerified(auth));
    assert_eq!(transition.effect, Effect::RequestPassphrase(auth));
    state = transition.state;

    let passphrase = NormalizedPassphrase::from_ascii("hidden").expect("ASCII is already NFKD");
    let wallet = lifecycle
        .open_context(&passphrase)
        .expect("runtime derives passphrase wallet seed");

    let transition = update(state, Event::PassphraseProvided(auth));
    assert_eq!(transition.effect, Effect::OpenSession { id: auth, host });
    state = transition.state;

    let transition = update(
        state,
        Event::SessionOpened {
            auth,
            session,
            wallet: wallet.id(),
        },
    );
    assert_eq!(transition.effect, Effect::SessionReady);

    let target = KeyTarget {
        account: AccountId(0),
        path: DerivationPath::new(),
        purpose: KeyPurpose::ExternalAddress,
    };
    let locator = transition
        .state
        .execution_context()
        .expect("session is unlocked")
        .bind_key(target);
    assert_eq!(locator.wallet(), wallet.id());
}

#[test]
fn failed_durable_commit_keeps_staged_root_retryable() {
    let mut lifecycle = KeyLifecycle::new(TestStore::new(true), TestEntropy([11; 32]));
    lifecycle
        .begin_create(MnemonicSize::Words24)
        .expect("stage root");

    assert!(matches!(
        lifecycle.commit_pending(),
        Err(LifecycleError::Store(StoreError::Injected))
    ));
    assert!(lifecycle.pending_mnemonic().is_some());
    assert!(!lifecycle.store().present);

    lifecycle
        .commit_pending()
        .expect("retry commits the same staged root");
    assert!(lifecycle.pending_mnemonic().is_none());
    assert!(lifecycle.store().present);

    let wallet = lifecycle
        .open_context(&NormalizedPassphrase::empty())
        .expect("committed root opens normally");
    assert_ne!(wallet.seed(), &[0; 64]);
}
