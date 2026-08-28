#![no_std]

use hardware_wallet_chain_api::{
    ChainId, ChainModule, ExecutionContext, Interaction, OperationKind, ReviewAssurance, ReviewPlan,
};

pub struct Bitcoin;

/// Temporary request boundary until the Bitcoin parser is implemented.
///
/// Raw PSBT/transaction bytes must eventually be parsed on-device. The host is
/// never allowed to supply pre-decoded amounts or destinations as trusted data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    ShowAddress,
    ExportPublicKey,
    SignPsbt,
    SignMessage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Review {
    kind: OperationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Execution {
    kind: OperationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ParserNotImplemented,
}

impl ChainModule for Bitcoin {
    type Request = Request;
    type Review = Review;
    type Execution = Execution;
    type ExecutionResult = ExecutionResult;
    type Response = Response;
    type Error = Error;

    const ID: ChainId = ChainId("bitcoin");

    fn prepare_review(request: &Self::Request) -> Result<Self::Review, Self::Error> {
        let kind = match request {
            Request::ShowAddress => OperationKind::ShowAddress,
            Request::ExportPublicKey => OperationKind::ExportPublicKey,
            Request::SignPsbt | Request::SignMessage => return Err(Error::ParserNotImplemented),
        };
        Ok(Review { kind })
    }

    fn review_plan(review: &Self::Review) -> ReviewPlan {
        ReviewPlan {
            kind: review.kind,
            uses_private_key: matches!(
                review.kind,
                OperationKind::SignTransaction
                    | OperationKind::SignMessage
                    | OperationKind::SignTypedData
                    | OperationKind::SignArbitraryData
            ),
            assurance: ReviewAssurance::Full,
            interaction: match review.kind {
                OperationKind::ShowAddress => Interaction::Display,
                _ => Interaction::Confirm,
            },
        }
    }

    fn prepare_execution(
        review: &Self::Review,
        _context: ExecutionContext,
    ) -> Result<Self::Execution, Self::Error> {
        Ok(Execution { kind: review.kind })
    }

    fn finalize(
        _review: &Self::Review,
        _result: &Self::ExecutionResult,
    ) -> Result<Self::Response, Self::Error> {
        Ok(Response)
    }
}
