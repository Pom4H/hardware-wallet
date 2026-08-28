#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinExhaustion {
    Lock,
    Wipe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectPolicy {
    KeepSession,
    Lock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningHostPolicy {
    AnySessionHost,
    TrustedOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlindSigningPolicy {
    Deny,
    Allow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityPolicy {
    pub max_pin_attempts: u8,
    pub pin_exhaustion: PinExhaustion,
    pub disconnect: DisconnectPolicy,
    pub signing_hosts: SigningHostPolicy,
    pub blind_signing: BlindSigningPolicy,
}

impl SecurityPolicy {
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_pin_attempts: 10,
            pin_exhaustion: PinExhaustion::Wipe,
            disconnect: DisconnectPolicy::Lock,
            signing_hosts: SigningHostPolicy::AnySessionHost,
            blind_signing: BlindSigningPolicy::Deny,
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
