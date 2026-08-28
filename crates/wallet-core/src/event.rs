use crate::{
    AuthId, HostId, HostTrust, MaintenanceId, OperationId, PairingId, PassphraseMode,
    RecoveryFormat, ReviewPlan, SessionId, SetupId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    StartCreate {
        id: SetupId,
        passphrase: PassphraseMode,
    },
    StartRecovery {
        id: SetupId,
        format: RecoveryFormat,
        passphrase: PassphraseMode,
    },
    RecoveryMaterialCaptured(SetupId),
    KeyMaterialReady(SetupId),
    BackupShown(SetupId),
    BackupVerified(SetupId),
    PinConfigured(SetupId),
    ProvisioningPersisted(SetupId),

    UnlockRequested {
        id: AuthId,
        host: HostId,
        trust: HostTrust,
    },
    PinVerified(AuthId),
    PinRejected(AuthId),
    PassphraseProvided(AuthId),
    PassphraseSkipped(AuthId),
    SessionOpened {
        auth: AuthId,
        session: SessionId,
    },
    LockRequested,
    SessionExpired(SessionId),
    HostDisconnected(HostId),

    PairingRequested {
        id: PairingId,
        host: HostId,
    },
    PairingConfirmed(PairingId),
    PairingRejected(PairingId),
    TrustedHostPersisted(PairingId),

    OperationRequested {
        id: OperationId,
        host: HostId,
    },
    ReviewPrepared {
        id: OperationId,
        plan: ReviewPlan,
    },
    ReviewDisplayed(OperationId),
    OperationConfirmed(OperationId),
    OperationRejected(OperationId),
    OperationCompleted(OperationId),
    OperationFailed(OperationId),
    OperationCancelled(OperationId),

    ChangePinRequested {
        id: MaintenanceId,
        host: HostId,
    },
    PinChanged(MaintenanceId),
    BackupCheckRequested {
        id: MaintenanceId,
        host: HostId,
    },
    BackupCheckCompleted {
        id: MaintenanceId,
        valid: bool,
    },
    FactoryResetRequested {
        id: MaintenanceId,
        host: HostId,
    },
    FactoryResetConfirmed(MaintenanceId),
    FactoryResetRejected(MaintenanceId),
    WipeCompleted,

    RuntimeFailure,
    TamperDetected,
}
