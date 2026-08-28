#![no_std]

mod effect;
mod event;
mod ids;
mod policy;
mod reducer;
mod state;

pub use effect::{Effect, RejectReason, Transition};
pub use event::Event;
pub use ids::{AuthId, HostId, MaintenanceId, OperationId, PairingId, SessionId, SetupId};
pub use policy::{PassphraseMode, SecurityPolicy};
pub use reducer::update;
pub use state::{
    AuthState, FlowState, HostTrust, Interaction, Lifecycle, MaintenanceKind, OperationKind,
    OperationStage, PendingOperation, ProvisioningMode, ProvisioningStage, RecoveryFormat,
    ReviewAssurance, ReviewPlan, Session, State,
};

#[cfg(test)]
mod tests;
