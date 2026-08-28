#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityPolicy {
    pub max_pin_attempts: u8,
    pub wipe_on_max_pin_attempts: bool,
    pub lock_on_host_disconnect: bool,
    pub require_trusted_host_for_signing: bool,
    pub allow_blind_signing: bool,
}

impl SecurityPolicy {
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_pin_attempts: 10,
            wipe_on_max_pin_attempts: true,
            lock_on_host_disconnect: true,
            require_trusted_host_for_signing: false,
            allow_blind_signing: false,
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassphraseMode {
    Disabled,
    Optional,
    Required,
}
