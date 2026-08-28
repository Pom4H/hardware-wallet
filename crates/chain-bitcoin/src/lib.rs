#![no_std]

use hardware_wallet_chain_api::{
    BoundedBytes, ChainExecution, ChainId, ChainModule, CryptoOperation, CryptoOutput,
    ExecutionContext, ExecutionStep, Interaction, KeyTarget, OperationKind, PublicKeyFormat,
    ReviewAssurance, ReviewPlan, MAX_PUBLIC_KEY_BYTES,
};

pub struct Bitcoin;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    ShowAddress(KeyTarget),
    ExportPublicKey(KeyTarget),
    SignPsbt,
    SignMessage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Review {
    kind: OperationKind,
    key: Option<KeyTarget>,
}

pub struct Execution {
    key: hardware_wallet_chain_api::KeyLocator,
    requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    PublicKey(BoundedBytes<MAX_PUBLIC_KEY_BYTES>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ParserNotImplemented,
    MissingKey,
    UnexpectedCryptoResult,
}

impl ChainExecution for Execution {
    type Response = Response;
    type Error = Error;

    fn next(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Self::Response>, Self::Error> {
        if !self.requested {
            if result.is_some() {
                return Err(Error::UnexpectedCryptoResult);
            }
            self.requested = true;
            return Ok(ExecutionStep::Crypto(CryptoOperation::DerivePublicKey {
                key: self.key,
                format: PublicKeyFormat::Compressed,
            }));
        }

        let Some(CryptoOutput::PublicKey { bytes, .. }) = result else {
            return Err(Error::UnexpectedCryptoResult);
        };
        Ok(ExecutionStep::Complete(Response::PublicKey(bytes.clone())))
    }

    fn payload(&self, _id: hardware_wallet_chain_api::PayloadId) -> Option<&[u8]> {
        None
    }
}

impl ChainModule for Bitcoin {
    type Request = Request;
    type Review = Review;
    type Execution = Execution;
    type Response = Response;
    type Error = Error;

    const ID: ChainId = ChainId("bitcoin");

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
            Request::SignPsbt | Request::SignMessage => Err(Error::ParserNotImplemented),
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
        let key = review.key.ok_or(Error::MissingKey)?;
        Ok(Execution {
            key: context.bind_key(key),
            requested: false,
        })
    }
}
