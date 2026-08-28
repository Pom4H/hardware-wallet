use crate::{
    AuthId, HostId, MaintenanceId, OperationId, PairingId, RecoveryFormat, SettingChange,
    SettingsId, SetupId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    NotProvisioned,
    AlreadyProvisioned,
    Locked,
    Busy,
    WrongHost,
    UntrustedHost,
    CorrelationMismatch,
    BlindSigningDisabled,
    InvalidState,
    BackupVerificationFailed,
    UserRejected,
    ExecutionFailed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    None,

    GenerateKeyMaterial(SetupId),
    CaptureRecoveryMaterial {
        id: SetupId,
        format: RecoveryFormat,
    },
    DeriveRecoveredKeyMaterial(SetupId),
    ShowBackup(SetupId),
    ChallengeBackup(SetupId),
    ConfigurePin(SetupId),
    PersistProvisioning(SetupId),
    ProvisioningComplete(SetupId),

    ResolveHostTrust {
        id: AuthId,
        host: HostId,
    },
    VerifyPin {
        id: AuthId,
        host: HostId,
    },
    RequestPassphrase(AuthId),
    OpenSession {
        id: AuthId,
        host: HostId,
    },
    AuthenticationFailed {
        remaining_attempts: u8,
    },
    SessionReady,
    ClearSensitiveState,

    RenderPairing {
        id: PairingId,
        host: HostId,
    },
    PersistTrustedHost {
        id: PairingId,
        host: HostId,
    },
    PairingComplete(PairingId),
    PairingRejected(PairingId),

    PrepareOperationReview(OperationId),
    RenderOperationReview(OperationId),
    ExecuteOperation(OperationId),
    CompleteOperation(OperationId),
    RejectOperation {
        id: OperationId,
        reason: RejectReason,
    },
    AbortOperation(OperationId),

    RenderSettingChange {
        id: SettingsId,
        change: SettingChange,
    },
    PersistSettingChange {
        id: SettingsId,
        change: SettingChange,
    },
    SettingChangeComplete(SettingsId),
    SettingChangeRejected(SettingsId),

    ChangePin(MaintenanceId),
    MaintenanceComplete(MaintenanceId),
    VerifyBackup(MaintenanceId),
    ReportBackupInvalid(MaintenanceId),
    RenderFactoryResetWarning(MaintenanceId),
    FactoryResetRejected(MaintenanceId),
    WipeWallet,
    WalletWiped,

    Reject(RejectReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    pub state: crate::State,
    pub effect: Effect,
}

impl Transition {
    #[must_use]
    pub const fn new(state: crate::State, effect: Effect) -> Self {
        Self { state, effect }
    }
}
