use bincode::{deserialize, serialize};
use sunscreen::{types::bfv::Signed, Ciphertext, PublicKey};

use crate::FheError;

/// Pack data for a binary FHE precompile computation, for example encrypted addition.
///
/// * `public_key` - Public key the parameters are encoded under.
/// * `a` - First argument to a binary precompile
/// * `b` - Second argument to a binary precompile
///
/// Returns a bytestring.
///
/// See also the inverse operation [`unpack_binary_operation`]
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

/// Unpacks data for a binary FHE precompile computation, for example encrypted addition.
///
/// * `input` - Bytestring representing the FHE computation to run.
///
/// Returns the public key and `Ciphertext` arguments to the precompile.
///
/// See also the inverse operation [`pack_binary_operation`]
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

/// Pack data for a binary plaintext FHE precompile computation, for example
/// adding a plaintext number to an encrypted number.
///
/// * `public_key` - Public key the parameters are encoded under.
/// * `encrypted_argument` - The encrypted value in the binary operation.
/// * `plaintext_argument` - The plaintext value in the binary operation.
///
/// Returns a bytestring.
///
/// See also the inverse operation [`unpack_binary_plain_operation`]
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

/// Unpack data for a binary plaintext FHE precompile computation, for example
/// adding a plaintext number to an encrypted number.
///
/// * `input` - Bytestring representing the FHE computation to run.
///
/// Returns the public key and encrypted/plaintext arguments for the precompile.
///
/// See also the inverse operation [`pack_binary_plain_operation`]
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

/// Pack data for a nullary FHE precompile computation, for example
/// encrypting a zero value.
///
/// * `public_key` - Public key the parameters are encoded under.
///
/// Returns a bytestring.
///
/// See also the inverse operation [`unpack_nullary_operation`]
pub fn pack_nullary_operation(public_key: &PublicKey) -> Vec<u8> {
    serialize(public_key).unwrap()
}

/// Unpack data for a nullary FHE precompile computation, for example
/// encrypting a zero value.
///
/// * `input` - Bytestring representing the FHE computation to run.
///
/// Returns the public key.
///
/// See also the inverse operation [`pack_nullary_operation`]
pub fn unpack_nullary_operation(input: &[u8]) -> Result<PublicKey, FheError> {
    deserialize(input).map_err(|_| FheError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use bincode::serialize;
    use once_cell::sync::Lazy;
    use sunscreen::{Params, PrivateKey, Runtime, SchemeType};

    use crate::pack::{pack_binary_operation, pack_binary_plain_operation, pack_nullary_operation};

    use super::*;

    pub static PARAMS: Lazy<Params> = Lazy::new(|| Params {
        lattice_dimension: 4096,
        coeff_modulus: vec![0xffffee001, 0xffffc4001, 0x1ffffe0001],
        plain_modulus: 4_096,
        scheme_type: SchemeType::Bfv,
        security_level: sunscreen::SecurityLevel::TC128,
    });

    pub static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new(&PARAMS).unwrap());

    #[allow(clippy::result_large_err)]
    pub fn generate_keys() -> Result<(PublicKey, PrivateKey), sunscreen::Error> {
        let (public_key, private_key) = RUNTIME.generate_keys()?;
        Ok((
            PublicKey {
                galois_key: None,
                ..public_key
            },
            private_key,
        ))
    }

    fn assert_serialized_eq<T>(a: &T, b: &T)
    where
        T: ?Sized + serde::Serialize,
    {
        assert_eq!(serialize(&a).unwrap(), serialize(&b).unwrap());
    }

    #[test]
    fn unpack_pack_binary_is_id() -> Result<(), FheError> {
        let (public_key, _) = generate_keys().unwrap();

        let a = RUNTIME.encrypt(Signed::from(16), &public_key).unwrap();
        let b = RUNTIME.encrypt(Signed::from(4), &public_key).unwrap();

        let input = pack_binary_operation(&public_key, &a, &b);
        let (public_key_reconstituted, a_reconstituted, b_reconstituted) =
            unpack_binary_operation(&input)?;

        assert_serialized_eq(&public_key, &public_key_reconstituted);
        assert_serialized_eq(&a, &a_reconstituted);
        assert_serialized_eq(&b, &b_reconstituted);
        Ok(())
    }

    #[test]
    fn pack_unpack_binary_is_id() -> Result<(), FheError> {
        let (public_key, _) = generate_keys().unwrap();

        let a = RUNTIME.encrypt(Signed::from(16), &public_key).unwrap();
        let b = RUNTIME.encrypt(Signed::from(4), &public_key).unwrap();

        let input = pack_binary_operation(&public_key, &a, &b);

        let (public_key_reconstituted, a_reconstituted, b_reconstituted) =
            unpack_binary_operation(&input)?;

        let repacked_input = pack_binary_operation(
            &public_key_reconstituted,
            &a_reconstituted,
            &b_reconstituted,
        );

        assert_serialized_eq(&input, &repacked_input);
        Ok(())
    }

    #[test]
    fn unpack_pack_binary_plain_is_id() -> Result<(), FheError> {
        let (public_key, _) = generate_keys().unwrap();

        let a = RUNTIME.encrypt(Signed::from(16), &public_key).unwrap();
        let b = Signed::from(4);

        let input = pack_binary_plain_operation(&public_key, &a, &b);
        let (public_key_reconstituted, a_reconstituted, b_reconstituted) =
            unpack_binary_plain_operation(&input)?;

        assert_serialized_eq(&public_key, &public_key_reconstituted);
        assert_serialized_eq(&a, &a_reconstituted);
        assert_eq!(b, b_reconstituted);
        Ok(())
    }

    #[test]
    fn pack_unpack_binary_plain_is_id() -> Result<(), FheError> {
        let (public_key, _) = generate_keys().unwrap();

        let a = RUNTIME.encrypt(Signed::from(16), &public_key).unwrap();
        let b = Signed::from(4);

        let input = pack_binary_plain_operation(&public_key, &a, &b);

        let (public_key_reconstituted, a_reconstituted, b_reconstituted) =
            unpack_binary_plain_operation(&input)?;

        let repacked_input = pack_binary_plain_operation(
            &public_key_reconstituted,
            &a_reconstituted,
            &b_reconstituted,
        );

        assert_serialized_eq(&input, &repacked_input);
        Ok(())
    }

    #[test]
    fn unpack_pack_nullary_is_id() -> Result<(), FheError> {
        let (public_key, _) = generate_keys().unwrap();

        let input = pack_nullary_operation(&public_key);
        let public_key_reconstituted = unpack_nullary_operation(&input)?;

        assert_serialized_eq(&public_key, &public_key_reconstituted);
        Ok(())
    }

    #[test]
    fn pack_unpack_nullary_is_id() -> Result<(), FheError> {
        let (public_key, _) = generate_keys().unwrap();

        let input = pack_nullary_operation(&public_key);
        let public_key_reconstituted = unpack_nullary_operation(&input)?;
        let repacked_input = pack_nullary_operation(&public_key_reconstituted);

        assert_serialized_eq(&input, &repacked_input);
        Ok(())
    }
}
