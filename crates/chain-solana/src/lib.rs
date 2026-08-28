#![no_std]

use hardware_wallet_chain_api::{
    BoundedBytes, CapacityError, ChainExecution, ChainId, ChainModule, CryptoOperation,
    CryptoOutput, ExecutionContext, ExecutionStep, HashAlgorithm, Interaction, KeyTarget,
    MAX_PUBLIC_KEY_BYTES, OperationKind, PayloadId, PublicKeyFormat, ReviewAssurance, ReviewPlan,
    SignatureScheme,
};

pub struct Solana;

pub const MAX_MESSAGE_BYTES: usize = 512;
pub const MAX_SIGNED_TX_BYTES: usize = 640;
const TRANSFER_PAYLOAD: PayloadId = PayloadId(0x534f_0001);
const SYSTEM_PROGRAM: [u8; 32] = [0; 32];
const SYSTEM_TRANSFER_INSTRUCTION: u32 = 2;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    ShowAddress(KeyTarget),
    ExportPublicKey(KeyTarget),
    SignSystemTransfer {
        key: KeyTarget,
        message: BoundedBytes<MAX_MESSAGE_BYTES>,
    },
    SignMessage,
    SignTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReview {
    pub key: KeyTarget,
    pub signer: [u8; 32],
    pub recipient: [u8; 32],
    pub recent_blockhash: [u8; 32],
    pub lamports: u64,
    message: BoundedBytes<MAX_MESSAGE_BYTES>,
}

impl TransferReview {
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.message.as_slice()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Review {
    PublicKey { kind: OperationKind, key: KeyTarget },
    SystemTransfer(TransferReview),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    PublicKey(BoundedBytes<MAX_PUBLIC_KEY_BYTES>),
    SignedTransaction(BoundedBytes<MAX_SIGNED_TX_BYTES>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ParserNotImplemented,
    MissingKey,
    InvalidMessage,
    UnsupportedHeader,
    UnsupportedAccounts,
    UnsupportedProgram,
    UnsupportedInstruction,
    NonCanonicalShortVec,
    ShortVecOverflow,
    TrailingBytes,
    SignerMismatch,
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
    AwaitingPublicKey,
    AwaitingSignature,
    Finished,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ExecutionKind {
    PublicKey {
        key: hardware_wallet_chain_api::KeyLocator,
        format: PublicKeyFormat,
    },
    SystemTransfer {
        key: hardware_wallet_chain_api::KeyLocator,
        signer: [u8; 32],
        message: BoundedBytes<MAX_MESSAGE_BYTES>,
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
                self.stage = ExecutionStage::AwaitingPublicKey;
                match &self.kind {
                    ExecutionKind::PublicKey { key, format } => {
                        Ok(ExecutionStep::Crypto(CryptoOperation::DerivePublicKey {
                            key: *key,
                            format: *format,
                        }))
                    }
                    ExecutionKind::SystemTransfer { key, .. } => {
                        Ok(ExecutionStep::Crypto(CryptoOperation::DerivePublicKey {
                            key: *key,
                            format: PublicKeyFormat::Raw,
                        }))
                    }
                }
            }
            ExecutionStage::AwaitingPublicKey => match &self.kind {
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
                    self.stage = ExecutionStage::Finished;
                    Ok(ExecutionStep::Complete(Response::PublicKey(bytes.clone())))
                }
                ExecutionKind::SystemTransfer { key, signer, .. } => {
                    let Some(CryptoOutput::PublicKey { format, bytes }) = result else {
                        return Err(Error::UnexpectedCryptoResult);
                    };
                    if *format != PublicKeyFormat::Raw || bytes.as_slice() != signer {
                        return Err(Error::SignerMismatch);
                    }
                    self.stage = ExecutionStage::AwaitingSignature;
                    Ok(ExecutionStep::Crypto(CryptoOperation::Sign {
                        key: *key,
                        scheme: SignatureScheme::Ed25519,
                        prehash: HashAlgorithm::None,
                        payload: TRANSFER_PAYLOAD,
                    }))
                }
            },
            ExecutionStage::AwaitingSignature => {
                let ExecutionKind::SystemTransfer { message, .. } = &self.kind else {
                    return Err(Error::UnexpectedCryptoResult);
                };
                let Some(CryptoOutput::Signature {
                    scheme,
                    bytes,
                    recovery_id,
                }) = result
                else {
                    return Err(Error::UnexpectedCryptoResult);
                };
                if *scheme != SignatureScheme::Ed25519 || bytes.len() != 64 || recovery_id.is_some()
                {
                    return Err(Error::InvalidSignature);
                }

                let mut transaction = BoundedBytes::<MAX_SIGNED_TX_BYTES>::new();
                push_shortvec(&mut transaction, 1)?;
                transaction.extend_from_slice(bytes.as_slice())?;
                transaction.extend_from_slice(message.as_slice())?;
                self.stage = ExecutionStage::Finished;
                Ok(ExecutionStep::Complete(Response::SignedTransaction(
                    transaction,
                )))
            }
            ExecutionStage::Finished => Err(Error::ExecutionFinished),
        }
    }

    fn payload(&self, id: PayloadId) -> Option<&[u8]> {
        match &self.kind {
            ExecutionKind::SystemTransfer { message, .. } if id == TRANSFER_PAYLOAD => {
                Some(message.as_slice())
            }
            ExecutionKind::PublicKey { .. } | ExecutionKind::SystemTransfer { .. } => None,
        }
    }
}

impl ChainModule for Solana {
    type Request = Request;
    type Review = Review;
    type Execution = Execution;
    type Response = Response;
    type Error = Error;

    const ID: ChainId = ChainId("solana");

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
            Request::SignSystemTransfer { key, message } => Ok(Review::SystemTransfer(
                parse_system_transfer(*key, message)?,
            )),
            Request::SignMessage | Request::SignTransaction => Err(Error::ParserNotImplemented),
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
            Review::SystemTransfer(_) => ReviewPlan {
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
                        PublicKeyFormat::Raw
                    }
                    _ => return Err(Error::MissingKey),
                },
            },
            Review::SystemTransfer(transfer) => ExecutionKind::SystemTransfer {
                key: context.bind_key(transfer.key),
                signer: transfer.signer,
                message: transfer.message.clone(),
            },
        };
        Ok(Execution {
            kind,
            stage: ExecutionStage::Ready,
        })
    }
}

/// Encodes the supported one-signer System Program transfer message.
///
/// The resulting bytes are still treated as untrusted input by
/// [`Solana::prepare_review`].
///
/// # Errors
///
/// Returns [`Error::CapacityExceeded`] if the fixed message budget is exceeded.
pub fn encode_system_transfer(
    signer: [u8; 32],
    recipient: [u8; 32],
    recent_blockhash: [u8; 32],
    lamports: u64,
) -> Result<BoundedBytes<MAX_MESSAGE_BYTES>, Error> {
    let mut output = BoundedBytes::<MAX_MESSAGE_BYTES>::new();
    output.extend_from_slice(&[1, 0, 1])?;
    push_shortvec(&mut output, 3)?;
    output.extend_from_slice(&signer)?;
    output.extend_from_slice(&recipient)?;
    output.extend_from_slice(&SYSTEM_PROGRAM)?;
    output.extend_from_slice(&recent_blockhash)?;
    push_shortvec(&mut output, 1)?;
    output.push(2)?;
    push_shortvec(&mut output, 2)?;
    output.extend_from_slice(&[0, 1])?;
    push_shortvec(&mut output, 12)?;
    output.extend_from_slice(&SYSTEM_TRANSFER_INSTRUCTION.to_le_bytes())?;
    output.extend_from_slice(&lamports.to_le_bytes())?;
    Ok(output)
}

fn parse_system_transfer(
    key: KeyTarget,
    message: &BoundedBytes<MAX_MESSAGE_BYTES>,
) -> Result<TransferReview, Error> {
    let mut cursor = Cursor::new(message.as_slice());
    if cursor.read_u8()? != 1 || cursor.read_u8()? != 0 || cursor.read_u8()? != 1 {
        return Err(Error::UnsupportedHeader);
    }
    if cursor.read_shortvec()? != 3 {
        return Err(Error::UnsupportedAccounts);
    }

    let signer = cursor.read_array::<32>()?;
    let recipient = cursor.read_array::<32>()?;
    let program = cursor.read_array::<32>()?;
    if program != SYSTEM_PROGRAM {
        return Err(Error::UnsupportedProgram);
    }
    let recent_blockhash = cursor.read_array::<32>()?;

    if cursor.read_shortvec()? != 1 {
        return Err(Error::UnsupportedInstruction);
    }
    if cursor.read_u8()? != 2 {
        return Err(Error::UnsupportedProgram);
    }
    if cursor.read_shortvec()? != 2 {
        return Err(Error::UnsupportedInstruction);
    }
    if cursor.read_u8()? != 0 || cursor.read_u8()? != 1 {
        return Err(Error::UnsupportedInstruction);
    }
    if cursor.read_shortvec()? != 12 {
        return Err(Error::UnsupportedInstruction);
    }
    let instruction = u32::from_le_bytes(cursor.read_array::<4>()?);
    if instruction != SYSTEM_TRANSFER_INSTRUCTION {
        return Err(Error::UnsupportedInstruction);
    }
    let lamports = u64::from_le_bytes(cursor.read_array::<8>()?);
    if !cursor.is_finished() {
        return Err(Error::TrailingBytes);
    }

    Ok(TransferReview {
        key,
        signer,
        recipient,
        recent_blockhash,
        lamports,
        message: message.clone(),
    })
}

fn push_shortvec<const N: usize>(output: &mut BoundedBytes<N>, value: usize) -> Result<(), Error> {
    let mut remaining = u16::try_from(value).map_err(|_| Error::ShortVecOverflow)?;
    loop {
        let mut byte = u8::try_from(remaining & 0x7f).map_err(|_| Error::ShortVecOverflow)?;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        output.push(byte)?;
        if remaining == 0 {
            return Ok(());
        }
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let value = *self.input.get(self.offset).ok_or(Error::InvalidMessage)?;
        self.offset += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::InvalidMessage)?;
        let slice = self
            .input
            .get(self.offset..end)
            .ok_or(Error::InvalidMessage)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(slice);
        self.offset = end;
        Ok(output)
    }

    fn read_shortvec(&mut self) -> Result<usize, Error> {
        let mut value = 0_u32;
        let mut shift = 0_u32;
        for index in 0..3 {
            let byte = self.read_u8()?;
            let chunk = u32::from(byte & 0x7f);
            if shift == 14 && chunk > 3 {
                return Err(Error::ShortVecOverflow);
            }
            value |= chunk << shift;
            if byte & 0x80 == 0 {
                if index > 0 && chunk == 0 {
                    return Err(Error::NonCanonicalShortVec);
                }
                return usize::try_from(value).map_err(|_| Error::ShortVecOverflow);
            }
            shift += 7;
        }
        Err(Error::ShortVecOverflow)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }
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

    fn fixture() -> BoundedBytes<MAX_MESSAGE_BYTES> {
        encode_system_transfer([1; 32], [2; 32], [3; 32], 42).expect("fixture fits")
    }

    #[test]
    fn parses_one_signer_system_transfer() {
        let request = Request::SignSystemTransfer {
            key: key(),
            message: fixture(),
        };
        let Review::SystemTransfer(review) =
            Solana::prepare_review(&request).expect("valid transfer")
        else {
            panic!("wrong review")
        };
        assert_eq!(review.signer, [1; 32]);
        assert_eq!(review.recipient, [2; 32]);
        assert_eq!(review.recent_blockhash, [3; 32]);
        assert_eq!(review.lamports, 42);
        assert_eq!(
            Solana::review_plan(&Review::SystemTransfer(review)).interaction,
            Interaction::Confirm
        );
    }

    #[test]
    fn rejects_arbitrary_program_instruction() {
        let mut raw = fixture();
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        bytes[..raw.len()].copy_from_slice(raw.as_slice());
        let program_index_offset = 3 + 1 + (32 * 3) + 32 + 1;
        bytes[program_index_offset] = 1;
        raw = BoundedBytes::from_slice(&bytes[..raw.len()]).expect("same length");
        let request = Request::SignSystemTransfer {
            key: key(),
            message: raw,
        };
        assert_eq!(
            Solana::prepare_review(&request),
            Err(Error::UnsupportedProgram)
        );
    }

    #[test]
    fn signing_waits_for_matching_derived_pubkey() {
        let request = Request::SignSystemTransfer {
            key: key(),
            message: fixture(),
        };
        let review = Solana::prepare_review(&request).expect("review");
        let state = crate_test_unlocked_state();
        let mut execution =
            Solana::prepare_execution(&review, state.execution_context().expect("unlocked"))
                .expect("execution");
        assert!(matches!(
            execution.next(None).expect("derive step"),
            ExecutionStep::Crypto(CryptoOperation::DerivePublicKey { .. })
        ));
        let wrong = CryptoOutput::PublicKey {
            format: PublicKeyFormat::Raw,
            bytes: BoundedBytes::from_slice(&[9; 32]).expect("fits"),
        };
        assert_eq!(execution.next(Some(&wrong)), Err(Error::SignerMismatch));
    }

    fn crate_test_unlocked_state() -> hardware_wallet_core::State {
        use hardware_wallet_core::{
            AuthId, Event, HostId, HostTrust, PassphraseMode, SessionId, SetupId, State,
            WalletContextId, update,
        };
        let setup = SetupId(1);
        let auth = AuthId(2);
        let host = HostId(3);
        let mut state = State::default();
        state = update(
            state,
            Event::StartCreate {
                id: setup,
                passphrase: PassphraseMode::Disabled,
            },
        )
        .state;
        state = update(state, Event::KeyMaterialReady(setup)).state;
        state = update(state, Event::BackupShown(setup)).state;
        state = update(state, Event::BackupVerified(setup)).state;
        state = update(state, Event::PinConfigured(setup)).state;
        state = update(state, Event::ProvisioningPersisted(setup)).state;
        state = update(state, Event::UnlockRequested { id: auth, host }).state;
        state = update(
            state,
            Event::HostTrustResolved {
                id: auth,
                trust: HostTrust::Trusted,
            },
        )
        .state;
        state = update(state, Event::PinVerified(auth)).state;
        update(
            state,
            Event::SessionOpened {
                auth,
                session: SessionId(4),
                wallet: WalletContextId(5),
            },
        )
        .state
    }
}
