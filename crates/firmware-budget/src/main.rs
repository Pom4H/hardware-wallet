#![no_main]
#![no_std]

use core::hint::black_box;

use cortex_m_rt::entry;
use hardware_wallet_chain_api::{
    BoundedBytes, ChainExecution, ChainModule, CryptoOperation, HashAlgorithm, PayloadId,
    PublicKeyFormat,
};
use hardware_wallet_chain_bitcoin::{Bitcoin, MAX_PSBT_BYTES, Request as BitcoinRequest};
use hardware_wallet_chain_ethereum::{
    Ethereum, MAX_UNSIGNED_TX_BYTES as MAX_ETHEREUM_TX_BYTES, Request as EthereumRequest,
};
use hardware_wallet_chain_solana::{MAX_MESSAGE_BYTES, Request as SolanaRequest, Solana};
use hardware_wallet_core::{
    AccountDescriptor, AccountId, AccountKind, AuthId, BlindSigningPolicy, ChildNumber, Curve,
    DerivationPath, DisconnectPolicy, Event, HostId, HostTrust, Interaction, KeyPurpose, KeyTarget,
    MaintenanceId, OperationId, OperationKind, PairingId, PassphraseMode, PinExhaustion,
    RecoveryFormat, ReviewAssurance, ReviewPlan, SecuritySetting, SessionId, SettingChange,
    SettingsId, SetupId, SignatureScheme, SigningHostPolicy, State, WalletContextId, update,
};
use hardware_wallet_crypto_runtime::{CryptoRuntime, SoftwareKeyBackend};
use hardware_wallet_hd_key_backend::{HdKeyBackend, KeyFamily};
use hardware_wallet_key_lifecycle::{
    EntropySource, KeyLifecycle, MnemonicSize, NormalizedPassphrase, RootSecretStore,
};
use panic_halt as _;

const ROOT_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeError {
    InvalidLength,
    MissingRoot,
}

struct ProbeEntropy {
    bytes: [u8; ROOT_BYTES],
}

impl ProbeEntropy {
    fn new(selector: u8) -> Self {
        let mut bytes = [0_u8; ROOT_BYTES];
        let mut index = 0;
        while index < ROOT_BYTES {
            bytes[index] = selector.wrapping_add(u8::try_from(index).unwrap_or(0));
            index += 1;
        }
        Self { bytes }
    }
}

impl EntropySource for ProbeEntropy {
    type Error = ProbeError;

    fn fill(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        if output.len() > self.bytes.len() {
            return Err(ProbeError::InvalidLength);
        }
        output.copy_from_slice(&self.bytes[..output.len()]);
        Ok(())
    }
}

impl Drop for ProbeEntropy {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

struct ProbeStore {
    root: [u8; ROOT_BYTES],
    len: u8,
    present: bool,
}

impl ProbeStore {
    const fn new() -> Self {
        Self {
            root: [0; ROOT_BYTES],
            len: 0,
            present: false,
        }
    }
}

impl RootSecretStore for ProbeStore {
    type Error = ProbeError;

    fn persist_root(&mut self, root: &[u8]) -> Result<(), Self::Error> {
        if !matches!(root.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(ProbeError::InvalidLength);
        }
        self.root.fill(0);
        self.root[..root.len()].copy_from_slice(root);
        self.len = u8::try_from(root.len()).map_err(|_| ProbeError::InvalidLength)?;
        self.present = true;
        Ok(())
    }

    fn load_root(&mut self, output: &mut [u8; ROOT_BYTES]) -> Result<Option<usize>, Self::Error> {
        if !self.present {
            return Ok(None);
        }
        let len = usize::from(self.len);
        if len > self.root.len() {
            return Err(ProbeError::InvalidLength);
        }
        output.fill(0);
        output[..len].copy_from_slice(&self.root[..len]);
        Ok(Some(len))
    }

    fn wipe_root(&mut self) -> Result<(), Self::Error> {
        if !self.present {
            return Err(ProbeError::MissingRoot);
        }
        self.root.fill(0);
        self.len = 0;
        self.present = false;
        Ok(())
    }
}

impl Drop for ProbeStore {
    fn drop(&mut self) {
        self.root.fill(0);
        self.len = 0;
        self.present = false;
    }
}

#[entry]
fn main() -> ! {
    let selector = black_box(0x5a_u8);
    let result = exercise(selector);
    black_box(result);

    loop {
        cortex_m::asm::nop();
    }
}

#[inline(never)]
fn exercise(selector: u8) -> u32 {
    let mut score = exercise_domain_surface(selector);

    let mut lifecycle = KeyLifecycle::new(ProbeStore::new(), ProbeEntropy::new(selector));
    if lifecycle.begin_create(MnemonicSize::Words24).is_err() {
        return score ^ 1;
    }

    let recovery_mnemonic = lifecycle.pending_mnemonic().cloned();
    if let Some(mnemonic) = lifecycle.pending_mnemonic() {
        score ^= mnemonic.word_count() as u32;
    }
    if lifecycle.commit_pending().is_err() {
        return score ^ 2;
    }

    let passphrase = if selector & 1 == 0 {
        NormalizedPassphrase::empty()
    } else {
        match NormalizedPassphrase::from_ascii("hardware-budget") {
            Ok(value) => value,
            Err(_) => NormalizedPassphrase::empty(),
        }
    };
    let wallet = match lifecycle.open_context(&passphrase) {
        Ok(wallet) => wallet,
        Err(_) => return score ^ 4,
    };
    score ^= wallet.id().0;

    let context = match unlocked_context(wallet.id(), selector) {
        Some(context) => context,
        None => return score ^ 8,
    };

    let secp_target = key_target(AccountId(1), selector, false);
    let secp_locator = context.bind_key(secp_target);
    let secp_account = account_descriptor(wallet.id(), AccountId(1), false);
    if let Ok(hd) = HdKeyBackend::new(secp_account, KeyFamily::Secp256k1Bip32, wallet.seed())
        && let Ok(backend) = hd.software_backend(secp_locator)
    {
        let runtime = CryptoRuntime::new(backend);
        score ^= exercise_secp_runtime(&runtime, secp_locator, selector);
    }

    let ed_target = key_target(AccountId(2), selector, true);
    let ed_locator = context.bind_key(ed_target);
    let ed_account = account_descriptor(wallet.id(), AccountId(2), true);
    if let Ok(hd) = HdKeyBackend::new(ed_account, KeyFamily::Ed25519Slip10, wallet.seed())
        && let Ok(backend) = hd.software_backend(ed_locator)
    {
        let runtime = CryptoRuntime::new(backend);
        score ^= exercise_ed25519_runtime(&runtime, ed_locator, selector);
    }

    score ^= exercise_chains(selector, context, secp_target, ed_target);

    if let Some(mnemonic) = recovery_mnemonic {
        let mut recovered = KeyLifecycle::new(
            ProbeStore::new(),
            ProbeEntropy::new(selector.wrapping_add(1)),
        );
        if recovered.begin_recovery(mnemonic).is_ok() {
            let _ = recovered.commit_pending();
            let _ = recovered.open_context(&NormalizedPassphrase::empty());
        }
        let _ = recovered.wipe();
    }

    let _ = lifecycle.wipe();
    black_box(score)
}

#[inline(never)]
fn exercise_secp_runtime(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    locator: hardware_wallet_core::KeyLocator,
    selector: u8,
) -> u32 {
    let payload = [selector; 128];
    let operations = [
        CryptoOperation::DerivePublicKey {
            key: locator,
            format: PublicKeyFormat::Compressed,
        },
        CryptoOperation::DerivePublicKey {
            key: locator,
            format: PublicKeyFormat::Uncompressed,
        },
        CryptoOperation::Hash {
            algorithm: HashAlgorithm::Sha256,
            payload: PayloadId(1),
        },
        CryptoOperation::Hash {
            algorithm: HashAlgorithm::DoubleSha256,
            payload: PayloadId(2),
        },
        CryptoOperation::Hash {
            algorithm: HashAlgorithm::Hash160,
            payload: PayloadId(3),
        },
        CryptoOperation::Hash {
            algorithm: HashAlgorithm::Keccak256,
            payload: PayloadId(4),
        },
        CryptoOperation::Hash {
            algorithm: HashAlgorithm::Sha512_256,
            payload: PayloadId(5),
        },
        CryptoOperation::Sign {
            key: locator,
            scheme: SignatureScheme::Ecdsa {
                curve: Curve::Secp256k1,
                recoverable: true,
            },
            prehash: HashAlgorithm::Sha256,
            payload: PayloadId(6),
        },
    ];

    let mut score = 0_u32;
    for operation in operations {
        let input = match operation {
            CryptoOperation::DerivePublicKey { .. } => None,
            CryptoOperation::Hash { .. } | CryptoOperation::Sign { .. } => Some(payload.as_slice()),
        };
        if let Ok(output) = runtime.execute(operation, input) {
            score = score.wrapping_add(core::mem::size_of_val(&output) as u32);
            black_box(output);
        }
    }
    score
}

#[inline(never)]
fn exercise_ed25519_runtime(
    runtime: &CryptoRuntime<SoftwareKeyBackend>,
    locator: hardware_wallet_core::KeyLocator,
    selector: u8,
) -> u32 {
    let payload = [selector.wrapping_add(1); 128];
    let operations = [
        CryptoOperation::DerivePublicKey {
            key: locator,
            format: PublicKeyFormat::Raw,
        },
        CryptoOperation::Sign {
            key: locator,
            scheme: SignatureScheme::Ed25519,
            prehash: HashAlgorithm::None,
            payload: PayloadId(7),
        },
    ];

    let mut score = 0_u32;
    for operation in operations {
        let input = match operation {
            CryptoOperation::DerivePublicKey { .. } => None,
            CryptoOperation::Hash { .. } | CryptoOperation::Sign { .. } => Some(payload.as_slice()),
        };
        if let Ok(output) = runtime.execute(operation, input) {
            score = score.wrapping_add(core::mem::size_of_val(&output) as u32);
            black_box(output);
        }
    }
    score
}

#[inline(never)]
fn exercise_chains(
    selector: u8,
    context: hardware_wallet_core::ExecutionContext,
    secp_target: KeyTarget,
    ed_target: KeyTarget,
) -> u32 {
    let mut score = 0_u32;

    let bitcoin_payload = [selector; MAX_PSBT_BYTES];
    let bitcoin_request = if selector & 1 == 0 {
        BitcoinRequest::ShowAddress(secp_target)
    } else {
        BitcoinRequest::SignPsbt {
            key: secp_target,
            psbt: BoundedBytes::from_slice(&bitcoin_payload).unwrap_or_default(),
        }
    };
    if let Ok(review) = Bitcoin::prepare_review(&black_box(bitcoin_request)) {
        score ^= core::mem::size_of_val(&review) as u32;
        black_box(Bitcoin::review_plan(&review));
        if let Ok(mut execution) = Bitcoin::prepare_execution(&review, context) {
            let _ = black_box(execution.next(None));
            score ^= core::mem::size_of_val(&execution) as u32;
        }
    }

    let ethereum_payload = [selector.wrapping_add(1); MAX_ETHEREUM_TX_BYTES];
    let ethereum_request = if selector & 2 == 0 {
        EthereumRequest::ShowAddress(secp_target)
    } else {
        EthereumRequest::SignEip1559 {
            key: secp_target,
            unsigned: BoundedBytes::from_slice(&ethereum_payload).unwrap_or_default(),
        }
    };
    if let Ok(review) = Ethereum::prepare_review(&black_box(ethereum_request)) {
        score ^= core::mem::size_of_val(&review) as u32;
        black_box(Ethereum::review_plan(&review));
        if let Ok(mut execution) = Ethereum::prepare_execution(&review, context) {
            let _ = black_box(execution.next(None));
            score ^= core::mem::size_of_val(&execution) as u32;
        }
    }

    let solana_payload = [selector.wrapping_add(2); MAX_MESSAGE_BYTES];
    let solana_request = if selector & 4 == 0 {
        SolanaRequest::ShowAddress(ed_target)
    } else {
        SolanaRequest::SignSystemTransfer {
            key: ed_target,
            message: BoundedBytes::from_slice(&solana_payload).unwrap_or_default(),
        }
    };
    if let Ok(review) = Solana::prepare_review(&black_box(solana_request)) {
        score ^= core::mem::size_of_val(&review) as u32;
        black_box(Solana::review_plan(&review));
        if let Ok(mut execution) = Solana::prepare_execution(&review, context) {
            let _ = black_box(execution.next(None));
            score ^= core::mem::size_of_val(&execution) as u32;
        }
    }

    score
}

#[inline(never)]
fn exercise_domain_surface(selector: u8) -> u32 {
    let setup = SetupId(1);
    let auth = AuthId(2);
    let host = HostId(3);
    let operation = OperationId(4);
    let pairing = PairingId(5);
    let maintenance = MaintenanceId(6);
    let settings = SettingsId(7);
    let session = SessionId(8);
    let wallet = WalletContextId(9);
    let review = ReviewPlan {
        kind: OperationKind::SignTransaction,
        uses_private_key: true,
        assurance: ReviewAssurance::Full,
        interaction: Interaction::Confirm,
    };
    let change = SettingChange::Security(SecuritySetting::BlindSigning(BlindSigningPolicy::Allow));

    let event = match selector % 45 {
        0 => Event::StartCreate {
            id: setup,
            passphrase: PassphraseMode::Optional,
        },
        1 => Event::StartRecovery {
            id: setup,
            format: RecoveryFormat::Mnemonic,
            passphrase: PassphraseMode::Required,
        },
        2 => Event::RecoveryMaterialCaptured(setup),
        3 => Event::KeyMaterialReady(setup),
        4 => Event::BackupShown(setup),
        5 => Event::BackupVerified(setup),
        6 => Event::PinConfigured(setup),
        7 => Event::ProvisioningPersisted(setup),
        8 => Event::UnlockRequested { id: auth, host },
        9 => Event::HostTrustResolved {
            id: auth,
            trust: HostTrust::Trusted,
        },
        10 => Event::PinVerified(auth),
        11 => Event::PinRejected {
            id: auth,
            failed_attempts: 1,
        },
        12 => Event::PassphraseProvided(auth),
        13 => Event::PassphraseSkipped(auth),
        14 => Event::SessionOpened {
            auth,
            session,
            wallet,
        },
        15 => Event::LockRequested,
        16 => Event::SessionExpired(session),
        17 => Event::HostDisconnected(host),
        18 => Event::PairingRequested { id: pairing, host },
        19 => Event::PairingConfirmed(pairing),
        20 => Event::PairingRejected(pairing),
        21 => Event::TrustedHostPersisted(pairing),
        22 => Event::OperationRequested {
            id: operation,
            host,
        },
        23 => Event::ReviewPrepared {
            id: operation,
            plan: review,
        },
        24 => Event::ReviewDisplayed(operation),
        25 => Event::OperationConfirmed(operation),
        26 => Event::OperationRejected(operation),
        27 => Event::OperationCompleted(operation),
        28 => Event::OperationFailed(operation),
        29 => Event::OperationCancelled(operation),
        30 => Event::SettingChangeRequested {
            id: settings,
            host,
            change,
        },
        31 => Event::SettingChangeConfirmed(settings),
        32 => Event::SettingChangeRejected(settings),
        33 => Event::SettingChangePersisted(settings),
        34 => Event::ChangePinRequested {
            id: maintenance,
            host,
        },
        35 => Event::PinChanged(maintenance),
        36 => Event::BackupCheckRequested {
            id: maintenance,
            host,
        },
        37 => Event::BackupCheckCompleted {
            id: maintenance,
            valid: true,
        },
        38 => Event::FactoryResetRequested {
            id: maintenance,
            host,
        },
        39 => Event::FactoryResetConfirmed(maintenance),
        40 => Event::FactoryResetRejected(maintenance),
        41 => Event::WipeCompleted,
        42 => Event::RuntimeFailure,
        43 => Event::TamperDetected,
        _ => Event::SettingChangeRequested {
            id: settings,
            host,
            change: SettingChange::Security(SecuritySetting::PinExhaustion(PinExhaustion::Lock)),
        },
    };

    let transition = update(black_box(State::default()), black_box(event));
    let policies = [
        SecuritySetting::Disconnect(DisconnectPolicy::KeepSession),
        SecuritySetting::SigningHosts(SigningHostPolicy::TrustedOnly),
        SecuritySetting::BlindSigning(BlindSigningPolicy::Deny),
        SecuritySetting::PinExhaustion(PinExhaustion::Wipe),
    ];
    black_box(policies);
    core::mem::size_of_val(&transition) as u32
}

#[inline(never)]
fn unlocked_context(
    wallet: WalletContextId,
    selector: u8,
) -> Option<hardware_wallet_core::ExecutionContext> {
    let setup = SetupId(100);
    let host = HostId(101);
    let auth = AuthId(102);
    let mode = if selector & 1 == 0 {
        PassphraseMode::Disabled
    } else {
        PassphraseMode::Optional
    };

    let mut state = State::default();
    state = update(
        state,
        Event::StartCreate {
            id: setup,
            passphrase: mode,
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
    if mode != PassphraseMode::Disabled {
        state = update(state, Event::PassphraseProvided(auth)).state;
    }
    state = update(
        state,
        Event::SessionOpened {
            auth,
            session: SessionId(103),
            wallet,
        },
    )
    .state;
    state.execution_context()
}

fn account_descriptor(
    wallet: WalletContextId,
    account: AccountId,
    ed25519: bool,
) -> AccountDescriptor {
    let root = if ed25519 {
        path(&[(44, true), (501, true), (0, true)])
    } else {
        path(&[(44, true), (0, true), (0, true)])
    };
    AccountDescriptor {
        id: account,
        wallet,
        kind: AccountKind::Hd,
        root,
    }
}

fn key_target(account: AccountId, selector: u8, hardened: bool) -> KeyTarget {
    KeyTarget {
        account,
        path: path(&[(u32::from(selector & 3), hardened)]),
        purpose: KeyPurpose::ExternalAddress,
    }
}

fn path(children: &[(u32, bool)]) -> DerivationPath {
    let mut output = DerivationPath::new();
    for &(index, hardened) in children {
        if let Ok(child) = ChildNumber::new(index, hardened) {
            let _ = output.push(child);
        }
    }
    output
}
