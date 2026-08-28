#![no_std]

pub use hardware_wallet_core::{
    AccountDescriptor, AccountId, AccountKind, CryptoOperation, Curve, DerivationError,
    DerivationPath, ExecutionContext, HashAlgorithm, Interaction, KeyLocator, KeyPurpose,
    KeyTarget, OperationKind, PayloadId, PublicKeyFormat, ReviewAssurance, ReviewPlan,
    SignatureScheme, WalletContextId,
};

/// Stable identifier for a chain implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainId(pub &'static str);

/// Error returned by a fixed-capacity byte buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    TooLong,
}

/// Heap-free byte storage shared by chain adapters and execution sessions.
///
/// This intentionally lives in the chain boundary rather than `wallet-core`:
/// raw transactions, messages, public keys and signatures never become part of
/// the wallet domain state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> BoundedBytes<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// Copies bytes into a fixed-capacity buffer.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError::TooLong`] when `value` exceeds `N` bytes.
    pub fn from_slice(value: &[u8]) -> Result<Self, CapacityError> {
        if value.len() > N {
            return Err(CapacityError::TooLong);
        }
        let mut output = Self::new();
        output.bytes[..value.len()].copy_from_slice(value);
        output.len = value.len();
        Ok(output)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends one byte.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError::TooLong`] when the buffer is full.
    pub fn push(&mut self, value: u8) -> Result<(), CapacityError> {
        if self.len == N {
            return Err(CapacityError::TooLong);
        }
        self.bytes[self.len] = value;
        self.len += 1;
        Ok(())
    }

    /// Appends a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityError::TooLong`] when the combined length exceeds `N`.
    pub fn extend_from_slice(&mut self, value: &[u8]) -> Result<(), CapacityError> {
        let Some(end) = self.len.checked_add(value.len()) else {
            return Err(CapacityError::TooLong);
        };
        if end > N {
            return Err(CapacityError::TooLong);
        }
        self.bytes[self.len..end].copy_from_slice(value);
        self.len = end;
        Ok(())
    }
}

impl<const N: usize> Default for BoundedBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub const MAX_PUBLIC_KEY_BYTES: usize = 65;
pub const MAX_SIGNATURE_BYTES: usize = 96;

/// Result returned by the isolated crypto/key runtime to a chain execution.
///
/// Public keys and signatures are transient non-secret outputs. They are kept
/// outside `wallet-core::State` and are consumed immediately by the active
/// chain execution state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoOutput {
    PublicKey {
        format: PublicKeyFormat,
        bytes: BoundedBytes<MAX_PUBLIC_KEY_BYTES>,
    },
    Signature {
        scheme: SignatureScheme,
        bytes: BoundedBytes<MAX_SIGNATURE_BYTES>,
        recovery_id: Option<u8>,
    },
}

/// One step in an approved chain execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStep<R> {
    Crypto(CryptoOperation),
    Complete(R),
}

/// Stateful execution that runs only after wallet-core approved an operation.
///
/// A chain may require several crypto steps. For example Bitcoin can derive a
/// public key, validate it against the input script, and only then request a
/// signature. Solana can similarly prove that the selected wallet key is the
/// transaction's required signer before signing the message.
pub trait ChainExecution {
    type Response;
    type Error;

    /// Advances execution by one step.
    ///
    /// The first invocation receives `None`. Every later invocation receives
    /// the output of the previously requested [`CryptoOperation`].
    ///
    /// # Errors
    ///
    /// Returns a chain-specific error for an unexpected crypto result or when
    /// an invariant required for signing is not satisfied.
    fn next(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Self::Response>, Self::Error>;

    /// Resolves an opaque payload handle requested by [`CryptoOperation::Sign`].
    ///
    /// Payload bytes remain owned by the chain execution and never enter the
    /// generic wallet state machine.
    fn payload(&self, id: PayloadId) -> Option<&[u8]>;
}

/// A chain module owns every chain-specific security decision: parsing the raw
/// request, deriving the exact human review, and constructing an execution that
/// can validate key identity before signing.
pub trait ChainModule {
    type Request;
    type Review;
    type Execution: ChainExecution<Response = Self::Response, Error = Self::Error>;
    type Response;
    type Error;

    const ID: ChainId;

    /// Parse and validate an untrusted host request and build the device-owned
    /// representation that will be shown to the user.
    ///
    /// # Errors
    ///
    /// Returns a chain-specific error when parsing or validation fails.
    fn prepare_review(request: &Self::Request) -> Result<Self::Review, Self::Error>;

    /// Describe the security properties of a prepared review to wallet-core.
    fn review_plan(review: &Self::Review) -> ReviewPlan;

    /// Start the approved execution using a capability obtained only from an
    /// unlocked wallet state.
    ///
    /// # Errors
    ///
    /// Returns a chain-specific error when the reviewed request cannot be
    /// converted into a safe execution session.
    fn prepare_execution(
        review: &Self::Review,
        context: ExecutionContext,
    ) -> Result<Self::Execution, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_bytes_fail_closed_on_overflow() {
        let mut bytes = BoundedBytes::<3>::from_slice(&[1, 2]).expect("fits");
        bytes.push(3).expect("last byte fits");
        assert_eq!(bytes.as_slice(), &[1, 2, 3]);
        assert_eq!(bytes.push(4), Err(CapacityError::TooLong));
        assert_eq!(
            BoundedBytes::<2>::from_slice(&[1, 2, 3]),
            Err(CapacityError::TooLong)
        );
    }
}
