#![no_std]

use hardware_wallet_chain_api::{
    BoundedBytes, CapacityError, ChainExecution, ChainId, ChainModule, CryptoOperation,
    CryptoOutput, Curve, ExecutionContext, ExecutionStep, HashAlgorithm, Interaction, KeyTarget,
    MAX_PUBLIC_KEY_BYTES, OperationKind, PayloadId, PublicKeyFormat, ReviewAssurance, ReviewPlan,
    SignatureScheme,
};

pub struct Ethereum;

pub const MAX_UNSIGNED_TX_BYTES: usize = 512;
pub const MAX_SIGNED_TX_BYTES: usize = 640;
const EIP1559_PAYLOAD: PayloadId = PayloadId(0x4554_0001);
const EIP1559_TYPE: u8 = 0x02;
const EIP1559_UNSIGNED_FIELDS: usize = 9;
const EIP1559_SIGNED_FIELDS: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    ShowAddress(KeyTarget),
    ExportPublicKey(KeyTarget),
    SignEip1559 {
        key: KeyTarget,
        unsigned: BoundedBytes<MAX_UNSIGNED_TX_BYTES>,
    },
    SignPersonalMessage,
    SignTypedData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uint256 {
    bytes: [u8; 32],
    len: u8,
}

impl Uint256 {
    const ZERO: Self = Self {
        bytes: [0; 32],
        len: 0,
    };

    fn from_rlp_scalar(value: &[u8]) -> Result<Self, Error> {
        if value.len() > 32 {
            return Err(Error::IntegerTooLarge);
        }
        if value.first() == Some(&0) {
            return Err(Error::NonCanonicalRlp);
        }
        if value.is_empty() {
            return Ok(Self::ZERO);
        }

        let mut bytes = [0; 32];
        let start = 32 - value.len();
        bytes[start..].copy_from_slice(value);
        Ok(Self {
            bytes,
            len: u8::try_from(value.len()).map_err(|_| Error::IntegerTooLarge)?,
        })
    }

    #[must_use]
    pub fn as_be_bytes(&self) -> &[u8] {
        &self.bytes[32 - usize::from(self.len)..]
    }

    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        if self.len > 8 {
            return None;
        }
        let mut output = 0_u64;
        for byte in self.as_be_bytes() {
            output = (output << 8) | u64::from(*byte);
        }
        Some(output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip1559Review {
    pub key: KeyTarget,
    pub chain_id: Uint256,
    pub nonce: Uint256,
    pub max_priority_fee_per_gas: Uint256,
    pub max_fee_per_gas: Uint256,
    pub gas_limit: Uint256,
    pub destination: [u8; 20],
    pub value: Uint256,
    unsigned: BoundedBytes<MAX_UNSIGNED_TX_BYTES>,
}

impl Eip1559Review {
    #[must_use]
    pub fn unsigned_bytes(&self) -> &[u8] {
        self.unsigned.as_slice()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Review {
    PublicKey { kind: OperationKind, key: KeyTarget },
    Eip1559(Eip1559Review),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    PublicKey(BoundedBytes<MAX_PUBLIC_KEY_BYTES>),
    SignedTransaction(BoundedBytes<MAX_SIGNED_TX_BYTES>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Eip1559Signature {
    pub compact: [u8; 64],
    pub y_parity: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ParserNotImplemented,
    MissingKey,
    InvalidEnvelope,
    InvalidRlp,
    NonCanonicalRlp,
    WrongFieldCount,
    IntegerTooLarge,
    ContractCreationUnsupported,
    CalldataUnsupported,
    AccessListUnsupported,
    UnexpectedCryptoResult,
    InvalidSignature,
    CapacityExceeded,
    ExecutionFinished,
}

impl From<CapacityError> for Error {
    fn from(_: CapacityError) -> Self {
        Self::CapacityExceeded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionStage {
    Ready,
    AwaitingCrypto,
    Finished,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExecutionKind {
    PublicKey {
        key: hardware_wallet_chain_api::KeyLocator,
        format: PublicKeyFormat,
    },
    Eip1559 {
        key: hardware_wallet_chain_api::KeyLocator,
        unsigned: BoundedBytes<MAX_UNSIGNED_TX_BYTES>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Execution {
    kind: ExecutionKind,
    stage: ExecutionStage,
}

impl ChainExecution for Execution {
    type Response = Response;
    type Error = Error;

    fn next(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Self::Response>, Self::Error> {
        match self.stage {
            ExecutionStage::Ready => {
                if result.is_some() {
                    return Err(Error::UnexpectedCryptoResult);
                }
                self.stage = ExecutionStage::AwaitingCrypto;
                match &self.kind {
                    ExecutionKind::PublicKey { key, format } => {
                        Ok(ExecutionStep::Crypto(CryptoOperation::DerivePublicKey {
                            key: *key,
                            format: *format,
                        }))
                    }
                    ExecutionKind::Eip1559 { key, .. } => {
                        Ok(ExecutionStep::Crypto(CryptoOperation::Sign {
                            key: *key,
                            scheme: SignatureScheme::Ecdsa {
                                curve: Curve::Secp256k1,
                                recoverable: true,
                            },
                            prehash: HashAlgorithm::Keccak256,
                            payload: EIP1559_PAYLOAD,
                        }))
                    }
                }
            }
            ExecutionStage::AwaitingCrypto => {
                let response = match &self.kind {
                    ExecutionKind::PublicKey { format, .. } => {
                        let Some(CryptoOutput::PublicKey {
                            format: actual_format,
                            bytes,
                        }) = result
                        else {
                            return Err(Error::UnexpectedCryptoResult);
                        };
                        if actual_format != format {
                            return Err(Error::UnexpectedCryptoResult);
                        }
                        Response::PublicKey(bytes.clone())
                    }
                    ExecutionKind::Eip1559 { unsigned, .. } => {
                        let signature = crypto_signature(result)?;
                        Response::SignedTransaction(finalize_eip1559(unsigned, signature)?)
                    }
                };
                self.stage = ExecutionStage::Finished;
                Ok(ExecutionStep::Complete(response))
            }
            ExecutionStage::Finished => Err(Error::ExecutionFinished),
        }
    }

    fn payload(&self, id: PayloadId) -> Option<&[u8]> {
        match &self.kind {
            ExecutionKind::Eip1559 { unsigned, .. } if id == EIP1559_PAYLOAD => {
                Some(unsigned.as_slice())
            }
            ExecutionKind::PublicKey { .. } | ExecutionKind::Eip1559 { .. } => None,
        }
    }
}

impl ChainModule for Ethereum {
    type Request = Request;
    type Review = Review;
    type Execution = Execution;
    type Response = Response;
    type Error = Error;

    const ID: ChainId = ChainId("ethereum");

    fn prepare_review(request: &Self::Request) -> Result<Self::Review, Self::Error> {
        match request {
            Request::ShowAddress(key) => Ok(Review::PublicKey {
                kind: OperationKind::ShowAddress,
                key: *key,
            }),
            Request::ExportPublicKey(key) => Ok(Review::PublicKey {
                kind: OperationKind::ExportPublicKey,
                key: *key,
            }),
            Request::SignEip1559 { key, unsigned } => {
                Ok(Review::Eip1559(parse_eip1559(*key, unsigned)?))
            }
            Request::SignPersonalMessage | Request::SignTypedData => {
                Err(Error::ParserNotImplemented)
            }
        }
    }

    fn review_plan(review: &Self::Review) -> ReviewPlan {
        match review {
            Review::PublicKey { kind, .. } => ReviewPlan {
                kind: *kind,
                uses_private_key: false,
                assurance: ReviewAssurance::Full,
                interaction: match kind {
                    OperationKind::ShowAddress => Interaction::Display,
                    _ => Interaction::Confirm,
                },
            },
            Review::Eip1559(_) => ReviewPlan {
                kind: OperationKind::SignTransaction,
                uses_private_key: true,
                assurance: ReviewAssurance::Full,
                interaction: Interaction::Confirm,
            },
        }
    }

    fn prepare_execution(
        review: &Self::Review,
        context: ExecutionContext,
    ) -> Result<Self::Execution, Self::Error> {
        let kind = match review {
            Review::PublicKey { kind, key } => ExecutionKind::PublicKey {
                key: context.bind_key(*key),
                format: match kind {
                    OperationKind::ShowAddress | OperationKind::ExportPublicKey => {
                        PublicKeyFormat::Uncompressed
                    }
                    _ => return Err(Error::MissingKey),
                },
            },
            Review::Eip1559(transaction) => ExecutionKind::Eip1559 {
                key: context.bind_key(transaction.key),
                unsigned: transaction.unsigned.clone(),
            },
        };
        Ok(Execution {
            kind,
            stage: ExecutionStage::Ready,
        })
    }
}

/// Encodes the supported EIP-1559 native-transfer subset.
///
/// This helper is useful for deterministic tests and host tooling. The signer
/// still reparses the returned bytes as untrusted input.
///
/// # Errors
///
/// Returns [`Error::CapacityExceeded`] if the encoded transaction exceeds the
/// fixed firmware budget.
pub fn encode_native_transfer(
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas_limit: u64,
    destination: [u8; 20],
    value: u64,
) -> Result<BoundedBytes<MAX_UNSIGNED_TX_BYTES>, Error> {
    let mut body = BoundedBytes::<MAX_UNSIGNED_TX_BYTES>::new();
    rlp_push_u64(&mut body, chain_id)?;
    rlp_push_u64(&mut body, nonce)?;
    rlp_push_u64(&mut body, max_priority_fee_per_gas)?;
    rlp_push_u64(&mut body, max_fee_per_gas)?;
    rlp_push_u64(&mut body, gas_limit)?;
    rlp_push_bytes(&mut body, &destination)?;
    rlp_push_u64(&mut body, value)?;
    rlp_push_bytes(&mut body, &[])?;
    body.push(0xc0)?;

    let mut output = BoundedBytes::<MAX_UNSIGNED_TX_BYTES>::new();
    output.push(EIP1559_TYPE)?;
    rlp_push_list_prefix(&mut output, body.len())?;
    output.extend_from_slice(body.as_slice())?;
    Ok(output)
}

/// Extracts the compact ECDSA signature from a signed EIP-1559 envelope.
///
/// This is used by compatibility tests against external Ethereum nodes. It is
/// also a strict parser: malformed or non-canonical envelopes are rejected.
///
/// # Errors
///
/// Returns an [`Error`] when the envelope is malformed or does not contain a
/// canonical 64-byte `(r,s)` signature plus parity.
pub fn signature_from_signed_eip1559(raw: &[u8]) -> Result<Eip1559Signature, Error> {
    let fields = parse_typed_list::<EIP1559_SIGNED_FIELDS>(raw)?;
    let parity = Uint256::from_rlp_scalar(fields[9].payload)?
        .as_u64()
        .ok_or(Error::InvalidSignature)?;
    let y_parity = u8::try_from(parity).map_err(|_| Error::InvalidSignature)?;
    if y_parity > 1 {
        return Err(Error::InvalidSignature);
    }

    let r = Uint256::from_rlp_scalar(fields[10].payload)?;
    let s = Uint256::from_rlp_scalar(fields[11].payload)?;
    if r.as_be_bytes().is_empty() || s.as_be_bytes().is_empty() {
        return Err(Error::InvalidSignature);
    }

    let mut compact = [0_u8; 64];
    let r_bytes = r.as_be_bytes();
    let s_bytes = s.as_be_bytes();
    compact[32 - r_bytes.len()..32].copy_from_slice(r_bytes);
    compact[64 - s_bytes.len()..].copy_from_slice(s_bytes);
    Ok(Eip1559Signature { compact, y_parity })
}

fn parse_eip1559(
    key: KeyTarget,
    unsigned: &BoundedBytes<MAX_UNSIGNED_TX_BYTES>,
) -> Result<Eip1559Review, Error> {
    let fields = parse_typed_list::<EIP1559_UNSIGNED_FIELDS>(unsigned.as_slice())?;
    let destination_payload = fields[5].bytes_payload()?;
    if destination_payload.is_empty() {
        return Err(Error::ContractCreationUnsupported);
    }
    if destination_payload.len() != 20 {
        return Err(Error::InvalidEnvelope);
    }
    let mut destination = [0_u8; 20];
    destination.copy_from_slice(destination_payload);

    if !fields[7].bytes_payload()?.is_empty() {
        return Err(Error::CalldataUnsupported);
    }
    if !fields[8].is_list || !fields[8].payload.is_empty() {
        return Err(Error::AccessListUnsupported);
    }

    Ok(Eip1559Review {
        key,
        chain_id: fields[0].uint()?,
        nonce: fields[1].uint()?,
        max_priority_fee_per_gas: fields[2].uint()?,
        max_fee_per_gas: fields[3].uint()?,
        gas_limit: fields[4].uint()?,
        destination,
        value: fields[6].uint()?,
        unsigned: unsigned.clone(),
    })
}

fn crypto_signature(result: Option<&CryptoOutput>) -> Result<Eip1559Signature, Error> {
    let Some(CryptoOutput::Signature {
        scheme,
        bytes,
        recovery_id,
    }) = result
    else {
        return Err(Error::UnexpectedCryptoResult);
    };
    if *scheme
        != (SignatureScheme::Ecdsa {
            curve: Curve::Secp256k1,
            recoverable: true,
        })
        || bytes.len() != 64
    {
        return Err(Error::UnexpectedCryptoResult);
    }
    let y_parity = recovery_id.ok_or(Error::InvalidSignature)?;
    if y_parity > 1 {
        return Err(Error::InvalidSignature);
    }
    let mut compact = [0_u8; 64];
    compact.copy_from_slice(bytes.as_slice());
    Ok(Eip1559Signature { compact, y_parity })
}

fn finalize_eip1559(
    unsigned: &BoundedBytes<MAX_UNSIGNED_TX_BYTES>,
    signature: Eip1559Signature,
) -> Result<BoundedBytes<MAX_SIGNED_TX_BYTES>, Error> {
    let fields = parse_typed_list::<EIP1559_UNSIGNED_FIELDS>(unsigned.as_slice())?;
    let mut body = BoundedBytes::<MAX_SIGNED_TX_BYTES>::new();
    for field in fields {
        body.extend_from_slice(field.encoded)?;
    }
    rlp_push_u64(&mut body, u64::from(signature.y_parity))?;
    rlp_push_integer_bytes(&mut body, &signature.compact[..32])?;
    rlp_push_integer_bytes(&mut body, &signature.compact[32..])?;

    let mut output = BoundedBytes::<MAX_SIGNED_TX_BYTES>::new();
    output.push(EIP1559_TYPE)?;
    rlp_push_list_prefix(&mut output, body.len())?;
    output.extend_from_slice(body.as_slice())?;
    Ok(output)
}

#[derive(Clone, Copy, Debug)]
struct RlpItem<'a> {
    encoded: &'a [u8],
    payload: &'a [u8],
    is_list: bool,
}

impl<'a> RlpItem<'a> {
    fn bytes_payload(self) -> Result<&'a [u8], Error> {
        if self.is_list {
            Err(Error::InvalidRlp)
        } else {
            Ok(self.payload)
        }
    }

    fn uint(self) -> Result<Uint256, Error> {
        Uint256::from_rlp_scalar(self.bytes_payload()?)
    }
}

fn parse_typed_list<const N: usize>(raw: &[u8]) -> Result<[RlpItem<'_>; N], Error> {
    if raw.first() != Some(&EIP1559_TYPE) {
        return Err(Error::InvalidEnvelope);
    }
    let (top, consumed) = parse_rlp_item(&raw[1..])?;
    if !top.is_list || consumed + 1 != raw.len() {
        return Err(Error::InvalidEnvelope);
    }

    let mut rest = top.payload;
    let empty = RlpItem {
        encoded: &[],
        payload: &[],
        is_list: false,
    };
    let mut fields = [empty; N];
    let mut index = 0_usize;
    while !rest.is_empty() {
        if index == N {
            return Err(Error::WrongFieldCount);
        }
        let (item, used) = parse_rlp_item(rest)?;
        fields[index] = item;
        rest = &rest[used..];
        index += 1;
    }
    if index != N {
        return Err(Error::WrongFieldCount);
    }
    Ok(fields)
}

fn parse_rlp_item(input: &[u8]) -> Result<(RlpItem<'_>, usize), Error> {
    let Some(&prefix) = input.first() else {
        return Err(Error::InvalidRlp);
    };

    match prefix {
        0x00..=0x7f => Ok((
            RlpItem {
                encoded: &input[..1],
                payload: &input[..1],
                is_list: false,
            },
            1,
        )),
        0x80..=0xb7 => {
            let len = usize::from(prefix - 0x80);
            let end = 1_usize.checked_add(len).ok_or(Error::InvalidRlp)?;
            if input.len() < end {
                return Err(Error::InvalidRlp);
            }
            let payload = &input[1..end];
            if len == 1 && payload[0] < 0x80 {
                return Err(Error::NonCanonicalRlp);
            }
            Ok((
                RlpItem {
                    encoded: &input[..end],
                    payload,
                    is_list: false,
                },
                end,
            ))
        }
        0xb8..=0xbf => parse_long_item(input, prefix - 0xb7, false),
        0xc0..=0xf7 => {
            let len = usize::from(prefix - 0xc0);
            let end = 1_usize.checked_add(len).ok_or(Error::InvalidRlp)?;
            if input.len() < end {
                return Err(Error::InvalidRlp);
            }
            Ok((
                RlpItem {
                    encoded: &input[..end],
                    payload: &input[1..end],
                    is_list: true,
                },
                end,
            ))
        }
        0xf8..=0xff => parse_long_item(input, prefix - 0xf7, true),
    }
}

fn parse_long_item(
    input: &[u8],
    length_of_length: u8,
    is_list: bool,
) -> Result<(RlpItem<'_>, usize), Error> {
    let length_bytes = usize::from(length_of_length);
    let header_end = 1_usize.checked_add(length_bytes).ok_or(Error::InvalidRlp)?;
    if input.len() < header_end || length_bytes == 0 || input[1] == 0 {
        return Err(Error::NonCanonicalRlp);
    }
    let mut len = 0_usize;
    for byte in &input[1..header_end] {
        len = len
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(Error::InvalidRlp)?;
    }
    if len < 56 {
        return Err(Error::NonCanonicalRlp);
    }
    let end = header_end.checked_add(len).ok_or(Error::InvalidRlp)?;
    if input.len() < end {
        return Err(Error::InvalidRlp);
    }
    Ok((
        RlpItem {
            encoded: &input[..end],
            payload: &input[header_end..end],
            is_list,
        },
        end,
    ))
}

fn rlp_push_u64<const N: usize>(output: &mut BoundedBytes<N>, value: u64) -> Result<(), Error> {
    if value == 0 {
        return rlp_push_bytes(output, &[]);
    }
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::InvalidEnvelope)?;
    rlp_push_bytes(output, &bytes[first..])
}

fn rlp_push_integer_bytes<const N: usize>(
    output: &mut BoundedBytes<N>,
    value: &[u8],
) -> Result<(), Error> {
    let first = value.iter().position(|byte| *byte != 0);
    match first {
        Some(index) => rlp_push_bytes(output, &value[index..]),
        None => rlp_push_bytes(output, &[]),
    }
}

fn rlp_push_bytes<const N: usize>(output: &mut BoundedBytes<N>, value: &[u8]) -> Result<(), Error> {
    if value.len() == 1 && value[0] < 0x80 {
        output.push(value[0])?;
        return Ok(());
    }
    rlp_push_length(output, 0x80, 0xb7, value.len())?;
    output.extend_from_slice(value)?;
    Ok(())
}

fn rlp_push_list_prefix<const N: usize>(
    output: &mut BoundedBytes<N>,
    len: usize,
) -> Result<(), Error> {
    rlp_push_length(output, 0xc0, 0xf7, len)
}

fn rlp_push_length<const N: usize>(
    output: &mut BoundedBytes<N>,
    short_base: u8,
    long_base: u8,
    len: usize,
) -> Result<(), Error> {
    if len < 56 {
        let short_len = u8::try_from(len).map_err(|_| Error::CapacityExceeded)?;
        output.push(short_base + short_len)?;
        return Ok(());
    }

    let raw = len.to_be_bytes();
    let first = raw
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::CapacityExceeded)?;
    let length_bytes = &raw[first..];
    let encoded_len = u8::try_from(length_bytes.len()).map_err(|_| Error::CapacityExceeded)?;
    output.push(long_base + encoded_len)?;
    output.extend_from_slice(length_bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardware_wallet_chain_api::{AccountId, DerivationPath, KeyPurpose};

    fn key() -> KeyTarget {
        KeyTarget {
            account: AccountId(0),
            path: DerivationPath::new(),
            purpose: KeyPurpose::ExternalAddress,
        }
    }

    fn fixture() -> BoundedBytes<MAX_UNSIGNED_TX_BYTES> {
        encode_native_transfer(
            31_337,
            0,
            1_000_000_000,
            2_000_000_000,
            21_000,
            [0x11; 20],
            1,
        )
        .expect("fixture fits")
    }

    #[test]
    fn parses_canonical_native_transfer() {
        let request = Request::SignEip1559 {
            key: key(),
            unsigned: fixture(),
        };
        let Review::Eip1559(review) = Ethereum::prepare_review(&request).expect("valid transfer")
        else {
            panic!("wrong review")
        };
        assert_eq!(review.chain_id.as_u64(), Some(31_337));
        assert_eq!(review.gas_limit.as_u64(), Some(21_000));
        assert_eq!(review.destination, [0x11; 20]);
        assert_eq!(review.value.as_u64(), Some(1));
        assert_eq!(
            Ethereum::review_plan(&Review::Eip1559(review)).interaction,
            Interaction::Confirm
        );
    }

    #[test]
    fn rejects_contract_calls_until_calldata_review_exists() {
        let mut raw = fixture();
        let bytes = raw.as_slice();
        let fields = parse_typed_list::<EIP1559_UNSIGNED_FIELDS>(bytes).expect("fixture parses");
        let mut body = BoundedBytes::<MAX_UNSIGNED_TX_BYTES>::new();
        for (index, field) in fields.iter().enumerate() {
            if index == 7 {
                rlp_push_bytes(&mut body, &[0xde, 0xad]).expect("fits");
            } else {
                body.extend_from_slice(field.encoded).expect("fits");
            }
        }
        let mut changed = BoundedBytes::<MAX_UNSIGNED_TX_BYTES>::new();
        changed.push(EIP1559_TYPE).expect("fits");
        rlp_push_list_prefix(&mut changed, body.len()).expect("fits");
        changed.extend_from_slice(body.as_slice()).expect("fits");
        raw = changed;

        let request = Request::SignEip1559 {
            key: key(),
            unsigned: raw,
        };
        assert_eq!(
            Ethereum::prepare_review(&request),
            Err(Error::CalldataUnsupported)
        );
    }

    #[test]
    fn finalizer_appends_canonical_signature_fields() {
        let unsigned = fixture();
        let mut compact = [0_u8; 64];
        compact[31] = 1;
        compact[63] = 2;
        let signed = finalize_eip1559(
            &unsigned,
            Eip1559Signature {
                compact,
                y_parity: 1,
            },
        )
        .expect("valid signature");
        let parsed = signature_from_signed_eip1559(signed.as_slice()).expect("signed parses");
        assert_eq!(parsed.compact, compact);
        assert_eq!(parsed.y_parity, 1);
    }

    #[test]
    fn rejects_non_canonical_integer() {
        assert_eq!(Uint256::from_rlp_scalar(&[0]), Err(Error::NonCanonicalRlp));
    }
}
