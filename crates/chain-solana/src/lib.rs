#![no_std]

use hardware_wallet_chain_api::{
    ChainId, ChainModule, CryptoOperation, ExecutionContext, Interaction, KeyTarget, OperationKind,
    PublicKeyFormat, ReviewAssurance, ReviewPlan,
};

pub struct Solana;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    ShowAddress(KeyTarget),
    ExportPublicKey(KeyTarget),
    SignMessage,
    SignTransaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Review {
    kind: OperationKind,
    key: Option<KeyTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Execution {
    Crypto(CryptoOperation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ParserNotImplemented,
    MissingKey,
}

impl ChainModule for Solana {
    type Request = Request;
    type Review = Review;
    type Execution = Execution;
    type ExecutionResult = ExecutionResult;
    type Response = Response;
    type Error = Error;

    const ID: ChainId = ChainId("solana");

    fn prepare_review(request: &Self::Request) -> Result<Self::Review, Self::Error> {
        match request {
            Request::ShowAddress(key) => Ok(Review {
                kind: OperationKind::ShowAddress,
                key: Some(*key),
            }),
            Request::ExportPublicKey(key) => Ok(Review {
                kind: OperationKind::ExportPublicKey,
                key: Some(*key),
            }),
            Request::SignMessage | Request::SignTransaction => Err(Error::ParserNotImplemented),
        }
    }

    fn review_plan(review: &Self::Review) -> ReviewPlan {
        ReviewPlan {
            kind: review.kind,
            uses_private_key: review.kind.uses_private_key(),
            assurance: ReviewAssurance::Full,
            interaction: match review.kind {
                OperationKind::ShowAddress => Interaction::Display,
                _ => Interaction::Confirm,
            },
        }
    }

    fn prepare_execution(
        review: &Self::Review,
        context: ExecutionContext,
    ) -> Result<Self::Execution, Self::Error> {
        let target = review.key.ok_or(Error::MissingKey)?;
        Ok(Execution::Crypto(CryptoOperation::DerivePublicKey {
            key: context.bind_key(target),
            format: PublicKeyFormat::Raw,
        }))
    }

    fn finalize(
        _review: &Self::Review,
        _result: &Self::ExecutionResult,
    ) -> Result<Self::Response, Self::Error> {
        Ok(Response)
    }
}
