#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub u32);

/// Opaque identifier for the active key context.
///
/// A base seed and each passphrase-derived hidden wallet are distinct contexts.
/// The identifier is a handle only; secret material never enters domain state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletContextId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsId(pub u32);
