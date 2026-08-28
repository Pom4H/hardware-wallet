#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceId(pub u32);
