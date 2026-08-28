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
pub enum SecuritySetting {
    PinExhaustion(PinExhaustion),
    Disconnect(DisconnectPolicy),
    SigningHosts(SigningHostPolicy),
    BlindSigning(BlindSigningPolicy),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingChange {
    Security(SecuritySetting),
    Passphrase(PassphraseMode),
    RevokeHost(crate::HostId),
    RevokeAllHosts,
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

    #[must_use]
    pub const fn apply(self, setting: SecuritySetting) -> Self {
        match setting {
            SecuritySetting::PinExhaustion(pin_exhaustion) => Self {
                pin_exhaustion,
                ..self
            },
            SecuritySetting::Disconnect(disconnect) => Self { disconnect, ..self },
            SecuritySetting::SigningHosts(signing_hosts) => Self {
                signing_hosts,
                ..self
            },
            SecuritySetting::BlindSigning(blind_signing) => Self {
                blind_signing,
                ..self
            },
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
