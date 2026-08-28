use crate::{
    AuthId, HostId, MaintenanceId, OperationId, PairingId, PassphraseMode, SecurityPolicy,
    SessionId, SettingChange, SettingsId, SetupId, WalletContextId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningMode {
    Create,
    Recover(RecoveryFormat),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFormat {
    Mnemonic,
    Shamir,
    Other(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletOrigin {
    Generated,
    Recovered(RecoveryFormat),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupStatus {
    /// A backup was verified against the active wallet on this device.
    Verified,
    /// This wallet was restored from recovery material, but no independent
    /// backup check has been completed since restoration.
    RecoverySource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletMetadata {
    pub origin: WalletOrigin,
    pub backup: BackupStatus,
    pub passphrase: PassphraseMode,
}

/// Non-secret state that may be restored after a reboot.
///
/// Trusted-host records and PIN retry counters are intentionally not included:
/// they belong to their dedicated persistent backends. Sessions and foreground
/// flows are always transient and are never restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentState {
    pub wallet: Option<WalletMetadata>,
    pub policy: SecurityPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningStage {
    CreatingKeyMaterial,
    CapturingRecoveryMaterial,
    DerivingRecoveredKeyMaterial,
    ShowingBackup,
    VerifyingBackup,
    ConfiguringPin,
    Persisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    Empty,
    Provisioning {
        id: SetupId,
        mode: ProvisioningMode,
        passphrase: PassphraseMode,
        stage: ProvisioningStage,
    },
    Provisioned {
        metadata: WalletMetadata,
    },
    Wiping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostTrust {
    Untrusted,
    Trusted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: SessionId,
    pub host: HostId,
    pub wallet: WalletContextId,
    pub trust: HostTrust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthState {
    Unavailable,
    Locked {
        /// Last durable retry count observed from the secure auth backend.
        failed_attempts: u8,
    },
    ResolvingHost {
        id: AuthId,
        host: HostId,
        failed_attempts: u8,
    },
    VerifyingPin {
        id: AuthId,
        host: HostId,
        trust: HostTrust,
        /// Last durable retry count observed before this verification attempt.
        failed_attempts: u8,
    },
    AwaitingPassphrase {
        id: AuthId,
        host: HostId,
        trust: HostTrust,
        failed_attempts: u8,
    },
    OpeningSession {
        id: AuthId,
        host: HostId,
        trust: HostTrust,
        failed_attempts: u8,
    },
    Unlocked(Session),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewAssurance {
    Full,
    Limited,
    Blind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interaction {
    Silent,
    Display,
    Confirm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    ShowAddress,
    ExportPublicKey,
    CreateAccount,
    SignTransaction,
    SignMessage,
    SignTypedData,
    SignArbitraryData,
    Custom(u16),
}

impl OperationKind {
    #[must_use]
    pub const fn uses_private_key(self) -> bool {
        matches!(
            self,
            Self::SignTransaction
                | Self::SignMessage
                | Self::SignTypedData
                | Self::SignArbitraryData
        )
    }

    #[must_use]
    pub const fn requires_confirmation(self) -> bool {
        matches!(
            self,
            Self::ExportPublicKey
                | Self::SignTransaction
                | Self::SignMessage
                | Self::SignTypedData
                | Self::SignArbitraryData
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewPlan {
    pub kind: OperationKind,
    pub uses_private_key: bool,
    pub assurance: ReviewAssurance,
    pub interaction: Interaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStage {
    PreparingReview,
    Reviewing { plan: ReviewPlan },
    Displaying { plan: ReviewPlan },
    Executing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingOperation {
    pub id: OperationId,
    pub host: HostId,
    pub wallet: WalletContextId,
    pub kind: Option<OperationKind>,
    pub stage: OperationStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceKind {
    ChangePin,
    VerifyBackup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsStage {
    Reviewing,
    Persisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowState {
    Idle,
    Operation(PendingOperation),
    Pairing {
        id: PairingId,
        host: HostId,
        persisted: bool,
    },
    Maintenance {
        id: MaintenanceId,
        kind: MaintenanceKind,
    },
    Settings {
        id: SettingsId,
        host: HostId,
        change: SettingChange,
        stage: SettingsStage,
    },
    FactoryReset {
        id: MaintenanceId,
        host: HostId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    lifecycle: Lifecycle,
    auth: AuthState,
    flow: FlowState,
    policy: SecurityPolicy,
}

impl State {
    #[must_use]
    pub const fn new(policy: SecurityPolicy) -> Self {
        Self {
            lifecycle: Lifecycle::Empty,
            auth: AuthState::Unavailable,
            flow: FlowState::Idle,
            policy,
        }
    }

    /// Restore the non-secret wallet state after a reboot.
    ///
    /// Sessions, wallet-context handles and foreground flows are deliberately
    /// discarded. A provisioned wallet always comes back locked. PIN retry
    /// state is re-established by the secure authentication backend on the
    /// next attempt rather than trusted from RAM.
    #[must_use]
    pub const fn restore(persistent: PersistentState) -> Self {
        match persistent.wallet {
            Some(metadata) => Self {
                lifecycle: Lifecycle::Provisioned { metadata },
                auth: AuthState::Locked { failed_attempts: 0 },
                flow: FlowState::Idle,
                policy: persistent.policy,
            },
            None => Self {
                lifecycle: Lifecycle::Empty,
                auth: AuthState::Unavailable,
                flow: FlowState::Idle,
                policy: persistent.policy,
            },
        }
    }

    #[must_use]
    pub const fn lifecycle(self) -> Lifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn wallet_metadata(self) -> Option<WalletMetadata> {
        match self.lifecycle {
            Lifecycle::Provisioned { metadata } => Some(metadata),
            _ => None,
        }
    }

    /// Return a stable non-secret snapshot suitable for persistent storage.
    ///
    /// Provisioning and wiping are intentionally not snapshot-able because
    /// their crash-consistency protocol belongs to the persistence runtime.
    #[must_use]
    pub const fn persistent_snapshot(self) -> Option<PersistentState> {
        match self.lifecycle {
            Lifecycle::Empty => Some(PersistentState {
                wallet: None,
                policy: self.policy,
            }),
            Lifecycle::Provisioned { metadata } => Some(PersistentState {
                wallet: Some(metadata),
                policy: self.policy,
            }),
            Lifecycle::Provisioning { .. } | Lifecycle::Wiping => None,
        }
    }

    #[must_use]
    pub const fn auth(self) -> AuthState {
        self.auth
    }

    #[must_use]
    pub const fn flow(self) -> FlowState {
        self.flow
    }

    #[must_use]
    pub const fn policy(self) -> SecurityPolicy {
        self.policy
    }

    #[must_use]
    pub const fn is_unlocked(self) -> bool {
        matches!(self.auth, AuthState::Unlocked(_))
    }

    pub(crate) const fn with_lifecycle(mut self, lifecycle: Lifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    pub(crate) const fn with_auth(mut self, auth: AuthState) -> Self {
        self.auth = auth;
        self
    }

    pub(crate) const fn with_flow(mut self, flow: FlowState) -> Self {
        self.flow = flow;
        self
    }

    pub(crate) const fn with_policy(mut self, policy: SecurityPolicy) -> Self {
        self.policy = policy;
        self
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(SecurityPolicy::default())
    }
}
