#![no_std]

/// Stable identifier for a chain implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainId(pub &'static str);

/// What a chain request ultimately asks the wallet to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    ShowAddress,
    ExportPublicKey,
    CreateAccount,
    SignTransaction,
    SignMessage,
    SignTypedData,
    SignArbitraryData,
    Custom(u16),
}

/// How completely the device can explain the request to a human.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewAssurance {
    /// All security-relevant fields are decoded and displayed by the device.
    Full,
    /// The device can explain the request, but some opaque data remains.
    Limited,
    /// The device cannot meaningfully explain what will be signed.
    Blind,
}

/// Minimum interaction requested by the chain module.
///
/// The wallet core may always strengthen this requirement. For example, a
/// signing operation is never allowed to become `Silent` even if a buggy chain
/// module asks for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interaction {
    Silent,
    Display,
    Confirm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewPlan {
    pub kind: OperationKind,
    pub uses_private_key: bool,
    pub assurance: ReviewAssurance,
    pub interaction: Interaction,
}

/// A chain module owns every chain-specific security decision: parsing the raw
/// request, deriving the exact human review, and preparing the exact operation
/// to execute after approval.
///
/// `hardware-wallet-core` deliberately does not know transaction formats,
/// address formats, hashing rules, derivation paths, signature encodings or
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

    /// Produce the exact cryptographic/public-key operation only after the core
    /// has accepted the review and, where required, obtained user approval.
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
