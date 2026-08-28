#![no_std]

mod effect;
mod event;
mod ids;
mod policy;
mod reducer;
mod state;

pub use effect::{Effect, RejectReason, Transition};
pub use event::Event;
pub use ids::{
    AuthId, HostId, MaintenanceId, OperationId, PairingId, SessionId, SettingsId, SetupId,
    WalletContextId,
};
pub use policy::{
    BlindSigningPolicy, DisconnectPolicy, PassphraseMode, PinExhaustion, SecurityPolicy,
    SecuritySetting, SettingChange, SigningHostPolicy,
};
pub use reducer::update;
pub use state::{
    AuthState, BackupStatus, FlowState, HostTrust, Interaction, Lifecycle, MaintenanceKind,
    OperationKind, OperationStage, PendingOperation, ProvisioningMode, ProvisioningStage,
    RecoveryFormat, ReviewAssurance, ReviewPlan, Session, SettingsStage, State, WalletMetadata,
    WalletOrigin,
};

#[cfg(test)]
mod tests;
