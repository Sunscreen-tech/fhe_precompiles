use bincode::{deserialize, serialize};
use sunscreen::{types::bfv::Signed, Ciphertext, PublicKey};

use crate::FheError;

#[allow(dead_code)]
pub fn pack_binary_operation(public_key: &PublicKey, a: &Ciphertext, b: &Ciphertext) -> Vec<u8> {
    let packed_public_key = serialize(public_key).unwrap();
    let packed_a = serialize(a).unwrap();
    let packed_b = serialize(b).unwrap();

    let arg_offset_1: u32 = packed_public_key.len().try_into().unwrap();
    let arg_offset_1 = arg_offset_1 + 8;

    let arg_offset_2: u32 = packed_a.len().try_into().unwrap();
    let arg_offset_2 = arg_offset_1 + arg_offset_2;

    let mut packed = Vec::new();
    packed.extend(arg_offset_1.to_be_bytes());
    packed.extend(arg_offset_2.to_be_bytes());
    packed.extend(packed_public_key);
    packed.extend(packed_a);
    packed.extend(packed_b);

    packed
}

pub fn unpack_binary_operation(
    input: &[u8],
) -> Result<(PublicKey, Ciphertext, Ciphertext), FheError> {
    if input.len() < 8 {
        return Err(FheError::UnexpectedEOF);
    }
    let ix_1 = &input[..4];
    let ix_2 = &input[4..8];

    // The following unwraps are safe due to length check above
    let ix_1 = u32::from_be_bytes(ix_1.try_into().unwrap());
    let ix_2 = u32::from_be_bytes(ix_2.try_into().unwrap());

    let ix_1: usize = ix_1
        .try_into()
        .map_err(|_| FheError::PlatformArchitecture)?;
    let ix_2: usize = ix_2
        .try_into()
        .map_err(|_| FheError::PlatformArchitecture)?;

    let public_key = deserialize(&input[8..ix_1]).map_err(|_| FheError::InvalidEncoding)?;
    let a = deserialize(&input[ix_1..ix_2]).map_err(|_| FheError::InvalidEncoding)?;
    let b = deserialize(&input[ix_2..]).map_err(|_| FheError::InvalidEncoding)?;

    Ok((public_key, a, b))
}

pub fn pack_binary_plain_operation(
    public_key: &PublicKey,
    encrypted_argument: &Ciphertext,
    plaintext_argument: &Signed,
) -> Vec<u8> {
    let packed_public_key = serialize(public_key).unwrap();
    let packed_encrypted_argument = serialize(encrypted_argument).unwrap();

    let arg_offset_1: u32 = packed_public_key.len().try_into().unwrap();
    let arg_offset_1 = arg_offset_1 + 4;

    let plaintext_int: i64 = (*plaintext_argument).into();

    let mut packed = Vec::new();
    packed.extend(arg_offset_1.to_be_bytes());
    packed.extend(packed_public_key);
    packed.extend(packed_encrypted_argument);
    packed.extend((plaintext_int as u64).to_be_bytes());

    packed
}

pub fn unpack_binary_plain_operation(
    input: &[u8],
) -> Result<(PublicKey, Ciphertext, Signed), FheError> {
    if input.len() < 12 {
        return Err(FheError::UnexpectedEOF);
    }
    let ix = &input[..4];
    // The following unwrap is safe due to length check above
    let ix = u32::from_be_bytes(ix.try_into().unwrap());
    let ix: usize = ix.try_into().map_err(|_| FheError::PlatformArchitecture)?;

    let public_key = bincode::deserialize(&input[4..ix]).map_err(|_| FheError::InvalidEncoding)?;
    let encrypted_argument =
        bincode::deserialize(&input[ix..input.len() - 8]).map_err(|_| FheError::InvalidEncoding)?;
    let plaintext_argument = &input[input.len() - 8..];
    let plaintext_argument: u64 = u64::from_be_bytes(
        plaintext_argument
            .try_into()
            .map_err(|_| FheError::UnexpectedEOF)?,
    );
    let plaintext_argument: i64 = plaintext_argument
        .try_into()
        .map_err(|_| FheError::Overflow)?;

    Ok((public_key, encrypted_argument, plaintext_argument.into()))
}

pub fn pack_nullary_operation(public_key: &PublicKey) -> Vec<u8> {
    serialize(public_key).unwrap()
}

pub fn unpack_nullary_operation(input: &[u8]) -> Result<PublicKey, FheError> {
    deserialize(input).map_err(|_| FheError::InvalidEncoding)
}
