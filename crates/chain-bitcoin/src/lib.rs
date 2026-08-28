#![no_std]

use hardware_wallet_chain_api::{
    BoundedBytes, CapacityError, ChainExecution, ChainId, ChainModule, CryptoOperation,
    CryptoOutput, Curve, ExecutionContext, ExecutionStep, HashAlgorithm, Interaction, KeyTarget,
    OperationKind, PayloadId, PublicKeyFormat, ReviewAssurance, ReviewPlan, SignatureScheme,
    MAX_PUBLIC_KEY_BYTES,
};

pub struct Bitcoin;

pub const MAX_PSBT_BYTES: usize = 2048;
pub const MAX_UNSIGNED_TX_BYTES: usize = 512;
pub const MAX_SIGNED_TX_BYTES: usize = 640;
const MAX_HASH_OUTPUT_PAYLOAD_BYTES: usize = 64;
const MAX_BIP143_PREIMAGE_BYTES: usize = 256;
const PUBKEY_HASH_PAYLOAD: PayloadId = PayloadId(0x4254_0001);
const PREVOUTS_PAYLOAD: PayloadId = PayloadId(0x4254_0002);
const SEQUENCE_PAYLOAD: PayloadId = PayloadId(0x4254_0003);
const OUTPUTS_PAYLOAD: PayloadId = PayloadId(0x4254_0004);
const BIP143_PAYLOAD: PayloadId = PayloadId(0x4254_0005);
const SIGHASH_ALL: u32 = 1;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    ShowAddress(KeyTarget),
    ExportPublicKey(KeyTarget),
    SignPsbt {
        key: KeyTarget,
        psbt: BoundedBytes<MAX_PSBT_BYTES>,
    },
    SignMessage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedTransaction {
    version: [u8; 4],
    prev_txid: [u8; 32],
    prev_vout: [u8; 4],
    sequence: [u8; 4],
    output_value: [u8; 8],
    output_program: [u8; 20],
    lock_time: [u8; 4],
}

impl ParsedTransaction {
    fn output_amount(self) -> u64 {
        u64::from_le_bytes(self.output_value)
    }

    fn prevout(self) -> [u8; 36] {
        let mut output = [0_u8; 36];
        output[..32].copy_from_slice(&self.prev_txid);
        output[32..].copy_from_slice(&self.prev_vout);
        output
    }

    fn serialized_output(self) -> Result<BoundedBytes<MAX_HASH_OUTPUT_PAYLOAD_BYTES>, Error> {
        let mut output = BoundedBytes::new();
        output.extend_from_slice(&self.output_value)?;
        output.push(22)?;
        output.extend_from_slice(&[0x00, 0x14])?;
        output.extend_from_slice(&self.output_program)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2wpkhReview {
    pub key: KeyTarget,
    pub input_amount: u64,
    pub output_amount: u64,
    pub fee: u64,
    pub input_program: [u8; 20],
    pub output_program: [u8; 20],
    tx: ParsedTransaction,
    psbt_pubkey: Option<[u8; 33]>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Review {
    PublicKey {
        kind: OperationKind,
        key: KeyTarget,
    },
    P2wpkh(P2wpkhReview),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    PublicKey(BoundedBytes<MAX_PUBLIC_KEY_BYTES>),
    SignedTransaction(BoundedBytes<MAX_SIGNED_TX_BYTES>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P2wpkhWitness {
    pub compact_signature: [u8; 64],
    pub public_key: [u8; 33],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ParserNotImplemented,
    MissingKey,
    InvalidPsbt,
    InvalidCompactSize,
    NonCanonicalCompactSize,
    UnsupportedGlobal,
    UnsupportedInput,
    UnsupportedOutput,
    DuplicateField,
    InvalidUnsignedTransaction,
    UnsupportedInputCount,
    UnsupportedOutputCount,
    NonEmptyScriptSig,
    UnsupportedScript,
    MissingWitnessUtxo,
    UnsupportedSighash,
    FeeUnderflow,
    UnexpectedCryptoResult,
    PublicKeyMismatch,
    WitnessProgramMismatch,
    InvalidDigest,
    InvalidSignature,
    CapacityExceeded,
    ExecutionFinished,
    TrailingBytes,
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
    AwaitingPubkeyHash,
    AwaitingPrevoutsHash,
    AwaitingSequenceHash,
    AwaitingOutputsHash,
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
    P2wpkh {
        key: hardware_wallet_chain_api::KeyLocator,
        tx: ParsedTransaction,
        input_amount: u64,
        input_program: [u8; 20],
        expected_pubkey: Option<[u8; 33]>,
        public_key: [u8; 33],
        prevout_payload: [u8; 36],
        output_payload: BoundedBytes<MAX_HASH_OUTPUT_PAYLOAD_BYTES>,
        hash_prevouts: [u8; 32],
        hash_sequence: [u8; 32],
        hash_outputs: [u8; 32],
        preimage: BoundedBytes<MAX_BIP143_PREIMAGE_BYTES>,
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
                let (key, format) = match &self.kind {
                    ExecutionKind::PublicKey { key, format } => (*key, *format),
                    ExecutionKind::P2wpkh { key, .. } => (*key, PublicKeyFormat::Compressed),
                };
                Ok(ExecutionStep::Crypto(CryptoOperation::DerivePublicKey {
                    key,
                    format,
                }))
            }
            ExecutionStage::AwaitingPublicKey => self.accept_public_key(result),
            ExecutionStage::AwaitingPubkeyHash => self.accept_pubkey_hash(result),
            ExecutionStage::AwaitingPrevoutsHash => self.accept_component_hash(
                result,
                ComponentHash::Prevouts,
                SEQUENCE_PAYLOAD,
                ExecutionStage::AwaitingSequenceHash,
            ),
            ExecutionStage::AwaitingSequenceHash => self.accept_component_hash(
                result,
                ComponentHash::Sequence,
                OUTPUTS_PAYLOAD,
                ExecutionStage::AwaitingOutputsHash,
            ),
            ExecutionStage::AwaitingOutputsHash => self.accept_outputs_hash(result),
            ExecutionStage::AwaitingSignature => self.accept_signature(result),
            ExecutionStage::Finished => Err(Error::ExecutionFinished),
        }
    }

    fn payload(&self, id: PayloadId) -> Option<&[u8]> {
        let ExecutionKind::P2wpkh {
            tx,
            public_key,
            prevout_payload,
            output_payload,
            preimage,
            ..
        } = &self.kind
        else {
            return None;
        };
        match id {
            PUBKEY_HASH_PAYLOAD => Some(public_key),
            PREVOUTS_PAYLOAD => Some(prevout_payload),
            SEQUENCE_PAYLOAD => Some(&tx.sequence),
            OUTPUTS_PAYLOAD => Some(output_payload.as_slice()),
            BIP143_PAYLOAD => Some(preimage.as_slice()),
            _ => None,
        }
    }
}

impl Execution {
    fn accept_public_key(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Response>, Error> {
        match &mut self.kind {
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
            ExecutionKind::P2wpkh {
                expected_pubkey,
                public_key,
                ..
            } => {
                let Some(CryptoOutput::PublicKey { format, bytes }) = result else {
                    return Err(Error::UnexpectedCryptoResult);
                };
                if *format != PublicKeyFormat::Compressed || bytes.len() != 33 {
                    return Err(Error::UnexpectedCryptoResult);
                }
                public_key.copy_from_slice(bytes.as_slice());
                if expected_pubkey.is_some_and(|expected| expected != *public_key) {
                    return Err(Error::PublicKeyMismatch);
                }
                self.stage = ExecutionStage::AwaitingPubkeyHash;
                Ok(ExecutionStep::Crypto(CryptoOperation::Hash {
                    algorithm: HashAlgorithm::Hash160,
                    payload: PUBKEY_HASH_PAYLOAD,
                }))
            }
        }
    }

    fn accept_pubkey_hash(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Response>, Error> {
        let ExecutionKind::P2wpkh { input_program, .. } = &self.kind else {
            return Err(Error::UnexpectedCryptoResult);
        };
        let digest = digest_bytes(result, HashAlgorithm::Hash160, 20)?;
        if digest != input_program {
            return Err(Error::WitnessProgramMismatch);
        }
        self.stage = ExecutionStage::AwaitingPrevoutsHash;
        Ok(ExecutionStep::Crypto(CryptoOperation::Hash {
            algorithm: HashAlgorithm::DoubleSha256,
            payload: PREVOUTS_PAYLOAD,
        }))
    }

    fn accept_component_hash(
        &mut self,
        result: Option<&CryptoOutput>,
        component: ComponentHash,
        next_payload: PayloadId,
        next_stage: ExecutionStage,
    ) -> Result<ExecutionStep<Response>, Error> {
        let digest = digest32(result, HashAlgorithm::DoubleSha256)?;
        let ExecutionKind::P2wpkh {
            hash_prevouts,
            hash_sequence,
            ..
        } = &mut self.kind
        else {
            return Err(Error::UnexpectedCryptoResult);
        };
        match component {
            ComponentHash::Prevouts => *hash_prevouts = digest,
            ComponentHash::Sequence => *hash_sequence = digest,
        }
        self.stage = next_stage;
        Ok(ExecutionStep::Crypto(CryptoOperation::Hash {
            algorithm: HashAlgorithm::DoubleSha256,
            payload: next_payload,
        }))
    }

    fn accept_outputs_hash(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Response>, Error> {
        let digest = digest32(result, HashAlgorithm::DoubleSha256)?;
        let ExecutionKind::P2wpkh {
            key,
            tx,
            input_amount,
            input_program,
            prevout_payload,
            hash_prevouts,
            hash_sequence,
            hash_outputs,
            preimage,
            ..
        } = &mut self.kind
        else {
            return Err(Error::UnexpectedCryptoResult);
        };
        *hash_outputs = digest;
        *preimage = build_bip143_preimage(
            *tx,
            *input_amount,
            *input_program,
            *prevout_payload,
            *hash_prevouts,
            *hash_sequence,
            *hash_outputs,
        )?;
        self.stage = ExecutionStage::AwaitingSignature;
        Ok(ExecutionStep::Crypto(CryptoOperation::Sign {
            key: *key,
            scheme: SignatureScheme::Ecdsa {
                curve: Curve::Secp256k1,
                recoverable: false,
            },
            prehash: HashAlgorithm::DoubleSha256,
            payload: BIP143_PAYLOAD,
        }))
    }

    fn accept_signature(
        &mut self,
        result: Option<&CryptoOutput>,
    ) -> Result<ExecutionStep<Response>, Error> {
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
                recoverable: false,
            })
            || bytes.len() != 64
            || recovery_id.is_some()
        {
            return Err(Error::InvalidSignature);
        }

        let mut compact = [0_u8; 64];
        compact.copy_from_slice(bytes.as_slice());
        validate_compact_signature(compact)?;

        let ExecutionKind::P2wpkh {
            tx, public_key, ..
        } = &self.kind
        else {
            return Err(Error::UnexpectedCryptoResult);
        };
        let signed = serialize_signed_transaction(*tx, compact, *public_key)?;
        self.stage = ExecutionStage::Finished;
        Ok(ExecutionStep::Complete(Response::SignedTransaction(signed)))
    }
}

#[derive(Clone, Copy)]
enum ComponentHash {
    Prevouts,
    Sequence,
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
            Request::ShowAddress(key) => Ok(Review::PublicKey {
                kind: OperationKind::ShowAddress,
                key: *key,
            }),
            Request::ExportPublicKey(key) => Ok(Review::PublicKey {
                kind: OperationKind::ExportPublicKey,
                key: *key,
            }),
            Request::SignPsbt { key, psbt } => Ok(Review::P2wpkh(parse_psbt(*key, psbt)?)),
            Request::SignMessage => Err(Error::ParserNotImplemented),
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
            Review::P2wpkh(_) => ReviewPlan {
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
                        PublicKeyFormat::Compressed
                    }
                    _ => return Err(Error::MissingKey),
                },
            },
            Review::P2wpkh(transaction) => ExecutionKind::P2wpkh {
                key: context.bind_key(transaction.key),
                tx: transaction.tx,
                input_amount: transaction.input_amount,
                input_program: transaction.input_program,
                expected_pubkey: transaction.psbt_pubkey,
                public_key: [0; 33],
                prevout_payload: transaction.tx.prevout(),
                output_payload: transaction.tx.serialized_output()?,
                hash_prevouts: [0; 32],
                hash_sequence: [0; 32],
                hash_outputs: [0; 32],
                preimage: BoundedBytes::new(),
            },
        };
        Ok(Execution {
            kind,
            stage: ExecutionStage::Ready,
        })
    }
}

/// Extracts the compact signature and compressed public key from the supported
/// one-input/one-output signed P2WPKH transaction shape.
///
/// # Errors
///
/// Returns an [`Error`] when the transaction is not the exact supported SegWit
/// shape or when its DER signature is malformed.
pub fn extract_p2wpkh_witness(raw: &[u8]) -> Result<P2wpkhWitness, Error> {
    let mut cursor = Cursor::new(raw);
    let _version = cursor.read_array::<4>()?;
    if cursor.read_u8()? != 0 || cursor.read_u8()? != 1 {
        return Err(Error::InvalidUnsignedTransaction);
    }
    if cursor.read_compact_size()? != 1 {
        return Err(Error::UnsupportedInputCount);
    }
    let _txid = cursor.read_array::<32>()?;
    let _vout = cursor.read_array::<4>()?;
    if cursor.read_compact_size()? != 0 {
        return Err(Error::NonEmptyScriptSig);
    }
    let _sequence = cursor.read_array::<4>()?;
    if cursor.read_compact_size()? != 1 {
        return Err(Error::UnsupportedOutputCount);
    }
    let _value = cursor.read_array::<8>()?;
    let script_len = cursor.read_compact_size()?;
    cursor.skip(script_len)?;
    if cursor.read_compact_size()? != 2 {
        return Err(Error::InvalidSignature);
    }
    let signature_len = cursor.read_compact_size()?;
    let signature = cursor.read_slice(signature_len)?;
    if signature.last() != Some(&1) {
        return Err(Error::UnsupportedSighash);
    }
    let compact_signature = decode_der_signature(&signature[..signature.len() - 1])?;
    if cursor.read_compact_size()? != 33 {
        return Err(Error::InvalidSignature);
    }
    let public_key = cursor.read_array::<33>()?;
    let _lock_time = cursor.read_array::<4>()?;
    if !cursor.is_finished() {
        return Err(Error::TrailingBytes);
    }
    Ok(P2wpkhWitness {
        compact_signature,
        public_key,
    })
}

fn parse_psbt(
    key: KeyTarget,
    psbt: &BoundedBytes<MAX_PSBT_BYTES>,
) -> Result<P2wpkhReview, Error> {
    let mut cursor = Cursor::new(psbt.as_slice());
    if cursor.read_array::<5>()? != *b"psbt\xff" {
        return Err(Error::InvalidPsbt);
    }

    let mut unsigned = None;
    loop {
        let key_len = cursor.read_compact_size()?;
        if key_len == 0 {
            break;
        }
        let map_key = cursor.read_slice(key_len)?;
        let value_len = cursor.read_compact_size()?;
        let value = cursor.read_slice(value_len)?;
        match map_key {
            [0x00] => {
                if unsigned.is_some() {
                    return Err(Error::DuplicateField);
                }
                unsigned = Some(
                    BoundedBytes::<MAX_UNSIGNED_TX_BYTES>::from_slice(value)
                        .map_err(|_| Error::InvalidUnsignedTransaction)?,
                );
            }
            [0xfb] if value == [0, 0, 0, 0] => {}
            _ => return Err(Error::UnsupportedGlobal),
        }
    }
    let unsigned = unsigned.ok_or(Error::InvalidPsbt)?;
    let tx = parse_unsigned_transaction(unsigned.as_slice())?;

    let mut witness_utxo = None;
    let mut sighash = SIGHASH_ALL;
    let mut psbt_pubkey = None;
    loop {
        let key_len = cursor.read_compact_size()?;
        if key_len == 0 {
            break;
        }
        let map_key = cursor.read_slice(key_len)?;
        let value_len = cursor.read_compact_size()?;
        let value = cursor.read_slice(value_len)?;
        let (&field_type, key_data) = map_key.split_first().ok_or(Error::InvalidPsbt)?;
        match field_type {
            0x01 if key_data.is_empty() => {
                if witness_utxo.is_some() {
                    return Err(Error::DuplicateField);
                }
                witness_utxo = Some(parse_witness_utxo(value)?);
            }
            0x03 if key_data.is_empty() => {
                if value.len() != 4 {
                    return Err(Error::UnsupportedSighash);
                }
                sighash = u32::from_le_bytes(
                    value.try_into().map_err(|_| Error::UnsupportedSighash)?,
                );
            }
            0x06 if key_data.len() == 33 => {
                if psbt_pubkey.is_some() {
                    return Err(Error::DuplicateField);
                }
                if value.len() < 4 || (value.len() - 4) % 4 != 0 {
                    return Err(Error::UnsupportedInput);
                }
                let mut public_key = [0_u8; 33];
                public_key.copy_from_slice(key_data);
                psbt_pubkey = Some(public_key);
            }
            _ => return Err(Error::UnsupportedInput),
        }
    }
    if sighash != SIGHASH_ALL {
        return Err(Error::UnsupportedSighash);
    }

    if cursor.read_compact_size()? != 0 {
        return Err(Error::UnsupportedOutput);
    }
    if !cursor.is_finished() {
        return Err(Error::TrailingBytes);
    }

    let (input_amount, input_program) = witness_utxo.ok_or(Error::MissingWitnessUtxo)?;
    let output_amount = tx.output_amount();
    let fee = input_amount
        .checked_sub(output_amount)
        .ok_or(Error::FeeUnderflow)?;
    Ok(P2wpkhReview {
        key,
        input_amount,
        output_amount,
        fee,
        input_program,
        output_program: tx.output_program,
        tx,
        psbt_pubkey,
    })
}

fn parse_unsigned_transaction(raw: &[u8]) -> Result<ParsedTransaction, Error> {
    let mut cursor = Cursor::new(raw);
    let version = cursor.read_array::<4>()?;
    if cursor.read_compact_size()? != 1 {
        return Err(Error::UnsupportedInputCount);
    }
    let prev_txid = cursor.read_array::<32>()?;
    let prev_vout = cursor.read_array::<4>()?;
    if cursor.read_compact_size()? != 0 {
        return Err(Error::NonEmptyScriptSig);
    }
    let sequence = cursor.read_array::<4>()?;
    if cursor.read_compact_size()? != 1 {
        return Err(Error::UnsupportedOutputCount);
    }
    let output_value = cursor.read_array::<8>()?;
    if cursor.read_compact_size()? != 22 {
        return Err(Error::UnsupportedScript);
    }
    let script = cursor.read_array::<22>()?;
    if script[..2] != [0x00, 0x14] {
        return Err(Error::UnsupportedScript);
    }
    let mut output_program = [0_u8; 20];
    output_program.copy_from_slice(&script[2..]);
    let lock_time = cursor.read_array::<4>()?;
    if !cursor.is_finished() {
        return Err(Error::TrailingBytes);
    }
    Ok(ParsedTransaction {
        version,
        prev_txid,
        prev_vout,
        sequence,
        output_value,
        output_program,
        lock_time,
    })
}

fn parse_witness_utxo(raw: &[u8]) -> Result<(u64, [u8; 20]), Error> {
    let mut cursor = Cursor::new(raw);
    let amount = u64::from_le_bytes(cursor.read_array::<8>()?);
    if cursor.read_compact_size()? != 22 {
        return Err(Error::UnsupportedScript);
    }
    let script = cursor.read_array::<22>()?;
    if script[..2] != [0x00, 0x14] {
        return Err(Error::UnsupportedScript);
    }
    if !cursor.is_finished() {
        return Err(Error::TrailingBytes);
    }
    let mut program = [0_u8; 20];
    program.copy_from_slice(&script[2..]);
    Ok((amount, program))
}

fn build_bip143_preimage(
    tx: ParsedTransaction,
    input_amount: u64,
    input_program: [u8; 20],
    prevout: [u8; 36],
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
) -> Result<BoundedBytes<MAX_BIP143_PREIMAGE_BYTES>, Error> {
    let mut preimage = BoundedBytes::new();
    preimage.extend_from_slice(&tx.version)?;
    preimage.extend_from_slice(&hash_prevouts)?;
    preimage.extend_from_slice(&hash_sequence)?;
    preimage.extend_from_slice(&prevout)?;
    preimage.push(25)?;
    preimage.extend_from_slice(&[0x76, 0xa9, 0x14])?;
    preimage.extend_from_slice(&input_program)?;
    preimage.extend_from_slice(&[0x88, 0xac])?;
    preimage.extend_from_slice(&input_amount.to_le_bytes())?;
    preimage.extend_from_slice(&tx.sequence)?;
    preimage.extend_from_slice(&hash_outputs)?;
    preimage.extend_from_slice(&tx.lock_time)?;
    preimage.extend_from_slice(&SIGHASH_ALL.to_le_bytes())?;
    Ok(preimage)
}

fn serialize_signed_transaction(
    tx: ParsedTransaction,
    compact_signature: [u8; 64],
    public_key: [u8; 33],
) -> Result<BoundedBytes<MAX_SIGNED_TX_BYTES>, Error> {
    let mut der = encode_der_signature(compact_signature)?;
    der.push(1)?;

    let mut output = BoundedBytes::new();
    output.extend_from_slice(&tx.version)?;
    output.extend_from_slice(&[0x00, 0x01])?;
    push_compact_size(&mut output, 1)?;
    output.extend_from_slice(&tx.prevout())?;
    push_compact_size(&mut output, 0)?;
    output.extend_from_slice(&tx.sequence)?;
    push_compact_size(&mut output, 1)?;
    output.extend_from_slice(tx.serialized_output()?.as_slice())?;
    push_compact_size(&mut output, 2)?;
    push_compact_size(&mut output, der.len())?;
    output.extend_from_slice(der.as_slice())?;
    push_compact_size(&mut output, public_key.len())?;
    output.extend_from_slice(&public_key)?;
    output.extend_from_slice(&tx.lock_time)?;
    Ok(output)
}

fn validate_compact_signature(signature: [u8; 64]) -> Result<(), Error> {
    if signature[..32].iter().all(|byte| *byte == 0)
        || signature[32..].iter().all(|byte| *byte == 0)
    {
        return Err(Error::InvalidSignature);
    }
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
        0x68, 0x1b, 0x20, 0xa0,
    ];
    if signature[32..] > HALF_ORDER {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

fn encode_der_signature(signature: [u8; 64]) -> Result<BoundedBytes<73>, Error> {
    validate_compact_signature(signature)?;
    let r = der_integer(&signature[..32]);
    let s = der_integer(&signature[32..]);
    let body_len = 2 + r.len() + 2 + s.len();
    let mut output = BoundedBytes::new();
    output.push(0x30)?;
    output.push(u8::try_from(body_len).map_err(|_| Error::InvalidSignature)?)?;
    output.push(0x02)?;
    output.push(u8::try_from(r.len()).map_err(|_| Error::InvalidSignature)?)?;
    output.extend_from_slice(r.as_slice())?;
    output.push(0x02)?;
    output.push(u8::try_from(s.len()).map_err(|_| Error::InvalidSignature)?)?;
    output.extend_from_slice(s.as_slice())?;
    Ok(output)
}

fn der_integer(value: &[u8]) -> BoundedBytes<33> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len() - 1);
    let significant = &value[first..];
    let mut output = BoundedBytes::new();
    if significant[0] & 0x80 != 0 {
        output.push(0).expect("33-byte DER integer capacity");
    }
    output
        .extend_from_slice(significant)
        .expect("33-byte DER integer capacity");
    output
}

fn decode_der_signature(der: &[u8]) -> Result<[u8; 64], Error> {
    let mut cursor = Cursor::new(der);
    if cursor.read_u8()? != 0x30 {
        return Err(Error::InvalidSignature);
    }
    let sequence_len = usize::from(cursor.read_u8()?);
    if sequence_len + 2 != der.len() || cursor.read_u8()? != 0x02 {
        return Err(Error::InvalidSignature);
    }
    let r = cursor.read_slice(usize::from(cursor.read_u8()?))?;
    if cursor.read_u8()? != 0x02 {
        return Err(Error::InvalidSignature);
    }
    let s = cursor.read_slice(usize::from(cursor.read_u8()?))?;
    if !cursor.is_finished() {
        return Err(Error::InvalidSignature);
    }
    let mut compact = [0_u8; 64];
    decode_der_integer(r, &mut compact[..32])?;
    decode_der_integer(s, &mut compact[32..])?;
    validate_compact_signature(compact)?;
    Ok(compact)
}

fn decode_der_integer(value: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if value.is_empty() || value.len() > 33 {
        return Err(Error::InvalidSignature);
    }
    let stripped = if value.len() == 33 {
        if value[0] != 0 || value[1] & 0x80 == 0 {
            return Err(Error::InvalidSignature);
        }
        &value[1..]
    } else {
        if value[0] == 0 && value.len() > 1 && value[1] & 0x80 == 0 {
            return Err(Error::InvalidSignature);
        }
        if value[0] & 0x80 != 0 {
            return Err(Error::InvalidSignature);
        }
        value
    };
    if stripped.len() > output.len() {
        return Err(Error::InvalidSignature);
    }
    output.fill(0);
    let start = output.len() - stripped.len();
    output[start..].copy_from_slice(stripped);
    Ok(())
}

fn digest_bytes<'a>(
    result: Option<&'a CryptoOutput>,
    algorithm: HashAlgorithm,
    expected_len: usize,
) -> Result<&'a [u8], Error> {
    let Some(CryptoOutput::Digest {
        algorithm: actual,
        bytes,
    }) = result
    else {
        return Err(Error::UnexpectedCryptoResult);
    };
    if *actual != algorithm || bytes.len() != expected_len {
        return Err(Error::InvalidDigest);
    }
    Ok(bytes.as_slice())
}

fn digest32(
    result: Option<&CryptoOutput>,
    algorithm: HashAlgorithm,
) -> Result<[u8; 32], Error> {
    let bytes = digest_bytes(result, algorithm, 32)?;
    let mut output = [0_u8; 32];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn push_compact_size<const N: usize>(
    output: &mut BoundedBytes<N>,
    value: usize,
) -> Result<(), Error> {
    if value < 0xfd {
        output.push(u8::try_from(value).map_err(|_| Error::InvalidCompactSize)?)?;
    } else if value <= usize::from(u16::MAX) {
        output.push(0xfd)?;
        output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| Error::InvalidCompactSize)?
                .to_le_bytes(),
        )?;
    } else {
        let value = u32::try_from(value).map_err(|_| Error::InvalidCompactSize)?;
        output.push(0xfe)?;
        output.extend_from_slice(&value.to_le_bytes())?;
    }
    Ok(())
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
        let value = *self.input.get(self.offset).ok_or(Error::InvalidPsbt)?;
        self.offset += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let slice = self.read_slice(N)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(slice);
        Ok(output)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::InvalidPsbt)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(Error::InvalidPsbt)?;
        self.offset = end;
        Ok(value)
    }

    fn skip(&mut self, len: usize) -> Result<(), Error> {
        self.read_slice(len).map(|_| ())
    }

    fn read_compact_size(&mut self) -> Result<usize, Error> {
        match self.read_u8()? {
            value @ 0x00..=0xfc => Ok(usize::from(value)),
            0xfd => {
                let value = u16::from_le_bytes(self.read_array::<2>()?);
                if value < 0xfd {
                    return Err(Error::NonCanonicalCompactSize);
                }
                Ok(usize::from(value))
            }
            0xfe => {
                let value = u32::from_le_bytes(self.read_array::<4>()?);
                if value <= u32::from(u16::MAX) {
                    return Err(Error::NonCanonicalCompactSize);
                }
                usize::try_from(value).map_err(|_| Error::InvalidCompactSize)
            }
            0xff => {
                let value = u64::from_le_bytes(self.read_array::<8>()?);
                if value <= u64::from(u32::MAX) {
                    return Err(Error::NonCanonicalCompactSize);
                }
                usize::try_from(value).map_err(|_| Error::InvalidCompactSize)
            }
        }
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

    fn unsigned_tx() -> BoundedBytes<MAX_UNSIGNED_TX_BYTES> {
        let mut tx = BoundedBytes::new();
        tx.extend_from_slice(&2_i32.to_le_bytes()).unwrap();
        tx.push(1).unwrap();
        tx.extend_from_slice(&[1; 32]).unwrap();
        tx.extend_from_slice(&0_u32.to_le_bytes()).unwrap();
        tx.push(0).unwrap();
        tx.extend_from_slice(&u32::MAX.to_le_bytes()).unwrap();
        tx.push(1).unwrap();
        tx.extend_from_slice(&90_000_u64.to_le_bytes()).unwrap();
        tx.push(22).unwrap();
        tx.extend_from_slice(&[0x00, 0x14]).unwrap();
        tx.extend_from_slice(&[2; 20]).unwrap();
        tx.extend_from_slice(&0_u32.to_le_bytes()).unwrap();
        tx
    }

    fn fixture_psbt() -> BoundedBytes<MAX_PSBT_BYTES> {
        let tx = unsigned_tx();
        let mut psbt = BoundedBytes::new();
        psbt.extend_from_slice(b"psbt\xff").unwrap();
        psbt.push(1).unwrap();
        psbt.push(0).unwrap();
        push_compact_size(&mut psbt, tx.len()).unwrap();
        psbt.extend_from_slice(tx.as_slice()).unwrap();
        psbt.push(0).unwrap();

        psbt.push(1).unwrap();
        psbt.push(1).unwrap();
        psbt.push(31).unwrap();
        psbt.extend_from_slice(&100_000_u64.to_le_bytes()).unwrap();
        psbt.push(22).unwrap();
        psbt.extend_from_slice(&[0x00, 0x14]).unwrap();
        psbt.extend_from_slice(&[3; 20]).unwrap();
        psbt.push(0).unwrap();
        psbt.push(0).unwrap();
        psbt
    }

    #[test]
    fn parses_narrow_p2wpkh_psbt_and_computes_fee() {
        let request = Request::SignPsbt {
            key: key(),
            psbt: fixture_psbt(),
        };
        let Review::P2wpkh(review) = Bitcoin::prepare_review(&request).expect("valid PSBT") else {
            panic!("wrong review")
        };
        assert_eq!(review.input_amount, 100_000);
        assert_eq!(review.output_amount, 90_000);
        assert_eq!(review.fee, 10_000);
        assert_eq!(review.input_program, [3; 20]);
        assert_eq!(review.output_program, [2; 20]);
        assert_eq!(Bitcoin::review_plan(&Review::P2wpkh(review)).interaction, Interaction::Confirm);
    }

    #[test]
    fn rejects_non_p2wpkh_witness_utxo() {
        let mut psbt = fixture_psbt();
        let mut raw = [0_u8; MAX_PSBT_BYTES];
        raw[..psbt.len()].copy_from_slice(psbt.as_slice());
        let index = raw[..psbt.len()]
            .windows(2)
            .rposition(|window| window == [0x00, 0x14])
            .expect("witness program marker");
        raw[index] = 0x51;
        psbt = BoundedBytes::from_slice(&raw[..psbt.len()]).unwrap();
        let request = Request::SignPsbt { key: key(), psbt };
        assert_eq!(Bitcoin::prepare_review(&request), Err(Error::UnsupportedScript));
    }

    #[test]
    fn compact_der_roundtrip() {
        let mut compact = [0_u8; 64];
        compact[31] = 1;
        compact[63] = 2;
        let der = encode_der_signature(compact).expect("valid compact signature");
        assert_eq!(decode_der_signature(der.as_slice()).unwrap(), compact);
    }
}
