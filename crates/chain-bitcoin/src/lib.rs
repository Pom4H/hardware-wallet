#![no_std]

use hardware_wallet_chain_api::{ChainId, ChainModule};

pub struct Bitcoin;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Review;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
}

impl ChainModule for Bitcoin {
    type Request = Request;
    type Review = Review;
    type SigningRequest = SigningRequest;
    type Error = Error;

    const ID: ChainId = ChainId("bitcoin");

    fn prepare_review(_request: &Self::Request) -> Result<Self::Review, Self::Error> {
        Err(Error::NotImplemented)
    }

    fn prepare_signing(
        _review: &Self::Review,
    ) -> Result<Self::SigningRequest, Self::Error> {
        Err(Error::NotImplemented)
    }
}
