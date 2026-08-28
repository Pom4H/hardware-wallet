#![no_std]

/// Stable identifier for a chain module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainId(pub &'static str);

/// A chain module translates opaque host requests into something a human can
/// review, then into the exact signing operation required by that chain.
///
/// The wallet core deliberately does not know transaction formats, address
/// formats, hashing rules or signature encodings.
pub trait ChainModule {
    type Request;
    type Review;
    type SigningRequest;
    type Error;

    const ID: ChainId;

    fn prepare_review(request: &Self::Request) -> Result<Self::Review, Self::Error>;

    fn prepare_signing(
        review: &Self::Review,
    ) -> Result<Self::SigningRequest, Self::Error>;
}
