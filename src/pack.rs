use bincode::{deserialize, serialize};
use crypto_bigint::{Encoding, U256};
use sunscreen::{types::bfv::Unsigned256, Ciphertext, PublicKey};

use crate::FheError;

/// This is the integral type we use to index into the precompile input byte arrays.
type Index = u32;

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

    let arg_offset_1 = packed_public_key.len() + 2 * std::mem::size_of::<Index>();
    let arg_offset_2 = arg_offset_1 + packed_a.len();

    let arg_offset_1: Index = arg_offset_1.try_into().unwrap();
    let arg_offset_2: Index = arg_offset_2.try_into().unwrap();

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
    let ix_size = std::mem::size_of::<Index>();

    if input.len() < 2 * ix_size {
        return Err(FheError::UnexpectedEOF);
    }
    let ix_1 = &input[..ix_size];
    let ix_2 = &input[ix_size..ix_size * 2];

    // The following unwraps are safe due to length check above
    let ix_1 = Index::from_be_bytes(ix_1.try_into().unwrap());
    let ix_2 = Index::from_be_bytes(ix_2.try_into().unwrap());

    let ix_1: usize = ix_1
        .try_into()
        .map_err(|_| FheError::PlatformArchitecture)?;
    let ix_2: usize = ix_2
        .try_into()
        .map_err(|_| FheError::PlatformArchitecture)?;

    let public_key =
        deserialize(&input[ix_size * 2..ix_1]).map_err(|_| FheError::InvalidEncoding)?;
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
    plaintext_argument: &Unsigned256,
) -> Vec<u8> {
    let packed_public_key = serialize(public_key).unwrap();
    let packed_encrypted_argument = serialize(encrypted_argument).unwrap();

    let arg_offset_1 = packed_public_key.len() + std::mem::size_of::<Index>();
    let arg_offset_1: Index = arg_offset_1.try_into().unwrap();

    let mut packed = Vec::new();
    packed.extend(arg_offset_1.to_be_bytes());
    packed.extend(packed_public_key);
    packed.extend(packed_encrypted_argument);
    packed.extend(U256::from(*plaintext_argument).to_be_bytes());

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
) -> Result<(PublicKey, Ciphertext, Unsigned256), FheError> {
    let ix_size = std::mem::size_of::<Index>();
    let pt_size = std::mem::size_of::<U256>();
    if input.len() < ix_size + pt_size {
        return Err(FheError::UnexpectedEOF);
    }
    let ix = &input[..ix_size];
    // The following unwrap is safe due to length check above
    let ix = Index::from_be_bytes(ix.try_into().unwrap());
    let ix: usize = ix.try_into().map_err(|_| FheError::PlatformArchitecture)?;

    let public_key =
        bincode::deserialize(&input[ix_size..ix]).map_err(|_| FheError::InvalidEncoding)?;
    let ciphertext = bincode::deserialize(&input[ix..input.len() - pt_size])
        .map_err(|_| FheError::InvalidEncoding)?;
    let plaintext = U256::from_be_bytes(
        input[input.len() - pt_size..]
            .try_into()
            .map_err(|_| FheError::UnexpectedEOF)?,
    );

    Ok((public_key, ciphertext, plaintext.into()))
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

    use super::*;
    use crate::pack::{pack_binary_operation, pack_binary_plain_operation, pack_nullary_operation};
    use crate::testnet::one::FHE;

    fn assert_serialized_eq<T>(a: &T, b: &T)
    where
        T: ?Sized + serde::Serialize,
    {
        assert_eq!(serialize(&a).unwrap(), serialize(&b).unwrap());
    }

    #[test]
    fn unpack_pack_binary_is_id() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();
        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

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
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();
        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

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
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();
        let b = Unsigned256::from(4);

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
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();
        let b = Unsigned256::from(4);

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
        let (public_key, _) = FHE.generate_keys().unwrap();

        let input = pack_nullary_operation(&public_key);
        let public_key_reconstituted = unpack_nullary_operation(&input)?;

        assert_serialized_eq(&public_key, &public_key_reconstituted);
        Ok(())
    }

    #[test]
    fn pack_unpack_nullary_is_id() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let input = pack_nullary_operation(&public_key);
        let public_key_reconstituted = unpack_nullary_operation(&input)?;
        let repacked_input = pack_nullary_operation(&public_key_reconstituted);

        assert_serialized_eq(&input, &repacked_input);
        Ok(())
    }
}
