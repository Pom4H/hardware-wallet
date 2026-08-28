#![no_std]

pub use hardware_wallet_core::{
    AccountDescriptor, AccountId, AccountKind, CryptoOperation, Curve, DerivationError,
    DerivationPath, HashAlgorithm, Interaction, KeyLocator, KeyPurpose, OperationKind, PayloadId,
    PublicKeyFormat, ReviewAssurance, ReviewPlan, SignatureScheme, WalletContextId,
};

/// Stable identifier for a chain implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainId(pub &'static str);

/// A chain module owns every chain-specific security decision: parsing the raw
/// request, deriving the exact human review, and preparing the exact operation
/// to execute after approval.
///
/// `hardware-wallet-core` deliberately does not know transaction formats,
/// address formats, hashing rules, derivation policies, signature encodings or
/// smart-contract semantics.
pub trait ChainModule {
    type Request;
    type Review;
    type Execution;
    type ExecutionResult;
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

    /// Describe the security properties of a prepared review to the wallet
    /// core. This metadata never replaces the actual human-readable review.
    fn review_plan(review: &Self::Review) -> ReviewPlan;

    /// Produce the exact public-key/signing execution only after the core has
    /// accepted the review and, where required, obtained user approval.
    ///
    /// Implementations should express cryptographic work with the generic
    /// `CryptoOperation` primitives where possible. Chain-specific execution
    /// types remain allowed for streaming, multi-step and protocol-specific
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns a chain-specific error when the reviewed request cannot be
    /// converted into a safe execution request.
    fn prepare_execution(review: &Self::Review) -> Result<Self::Execution, Self::Error>;

    /// Convert the low-level execution result into the chain-specific response
    /// returned to the host.
    ///
    /// # Errors
    ///
    /// Returns a chain-specific error when the execution result is invalid or
    /// cannot be encoded into a response.
    fn finalize(
        review: &Self::Review,
        result: &Self::ExecutionResult,
    ) -> Result<Self::Response, Self::Error>;
}
