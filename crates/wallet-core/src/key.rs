use crate::WalletContextId;

pub const MAX_DERIVATION_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountKind {
    Hd,
    Imported,
    MultisigParticipant,
    SmartAccountController,
    Custom(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    Account,
    ExternalAddress,
    ChangeAddress,
    Authentication,
    Staking,
    Encryption,
    Custom(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivationError {
    IndexOutOfRange,
    TooDeep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildNumber {
    index: u32,
    hardened: bool,
}

impl ChildNumber {
    pub const MAX_INDEX: u32 = 0x7fff_ffff;

    pub const fn new(index: u32, hardened: bool) -> Result<Self, DerivationError> {
        if index > Self::MAX_INDEX {
            Err(DerivationError::IndexOutOfRange)
        } else {
            Ok(Self { index, hardened })
        }
    }

    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn is_hardened(self) -> bool {
        self.hardened
    }
}

const EMPTY_CHILD: ChildNumber = ChildNumber {
    index: 0,
    hardened: false,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivationPath {
    components: [ChildNumber; MAX_DERIVATION_DEPTH],
    len: u8,
}

impl DerivationPath {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            components: [EMPTY_CHILD; MAX_DERIVATION_DEPTH],
            len: 0,
        }
    }

    pub fn push(&mut self, child: ChildNumber) -> Result<(), DerivationError> {
        let index = usize::from(self.len);
        if index == MAX_DERIVATION_DEPTH {
            return Err(DerivationError::TooDeep);
        }
        self.components[index] = child;
        self.len += 1;
        Ok(())
    }

    #[must_use]
    pub const fn depth(self) -> u8 {
        self.len
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ChildNumber] {
        &self.components[..usize::from(self.len)]
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDescriptor {
    pub id: AccountId,
    pub wallet: WalletContextId,
    pub kind: AccountKind,
    pub root: DerivationPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyLocator {
    pub wallet: WalletContextId,
    pub account: AccountId,
    pub path: DerivationPath,
    pub purpose: KeyPurpose,
}
