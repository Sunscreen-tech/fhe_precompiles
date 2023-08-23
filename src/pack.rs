use bincode::{deserialize, serialize};
use crypto_bigint::{Encoding, U256, U64};
use sunscreen::{
    types::bfv::{Fractional, Signed, Unsigned256, Unsigned64},
    Ciphertext, PublicKey,
};

use crate::FheError;

/// This is the integral type we use to index into the precompile input byte arrays.
type Index = u32;

pub trait FHESerialize {
    fn fhe_serialize(&self) -> Vec<u8>;

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized;
}

impl FHESerialize for Ciphertext {
    fn fhe_serialize(&self) -> Vec<u8> {
        serialize(self).unwrap()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        deserialize(bytes).map_err(|_| FheError::InvalidEncoding)
    }
}

impl FHESerialize for PublicKey {
    fn fhe_serialize(&self) -> Vec<u8> {
        serialize(self).unwrap()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        deserialize(bytes).map_err(|_| FheError::InvalidEncoding)
    }
}

impl FHESerialize for Unsigned64 {
    fn fhe_serialize(&self) -> Vec<u8> {
        U64::from(*self).to_be_bytes().to_vec()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        let val = U64::from_be_bytes(bytes.try_into().map_err(|_| FheError::InvalidEncoding)?);
        Ok(val.into())
    }
}

impl FHESerialize for Unsigned256 {
    fn fhe_serialize(&self) -> Vec<u8> {
        U256::from(*self).to_be_bytes().to_vec()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        let val = U256::from_be_bytes(bytes.try_into().map_err(|_| FheError::InvalidEncoding)?);
        Ok(val.into())
    }
}

// Signed currently only has the single size of 64 bits.
impl FHESerialize for Signed {
    fn fhe_serialize(&self) -> Vec<u8> {
        let val: i64 = (*self).into();
        val.to_be_bytes().to_vec()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        let val = i64::from_be_bytes(bytes.try_into().map_err(|_| FheError::InvalidEncoding)?);
        Ok(val.into())
    }
}

impl<const N: usize> FHESerialize for Fractional<N> {
    fn fhe_serialize(&self) -> Vec<u8> {
        let val: f64 = (*self).into();
        val.to_be_bytes().to_vec()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        let val = f64::from_be_bytes(bytes.try_into().map_err(|_| FheError::InvalidEncoding)?);
        Ok(val.into())
    }
}

impl FHESerialize for Vec<u8> {
    fn fhe_serialize(&self) -> Vec<u8> {
        self.clone()
    }

    fn fhe_deserialize(bytes: &[u8]) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        Ok(bytes.to_vec())
    }
}

pub fn pack_two_arguments<A, B>(a: &A, b: &B) -> Vec<u8>
where
    A: FHESerialize,
    B: FHESerialize,
{
    let packed_a = a.fhe_serialize();
    let packed_b = b.fhe_serialize();

    let arg_offset_1 = packed_a.len() + std::mem::size_of::<Index>();

    let arg_offset_1: Index = arg_offset_1.try_into().unwrap();

    let mut packed = Vec::new();
    packed.extend(arg_offset_1.to_be_bytes());
    packed.extend(packed_a);
    packed.extend(packed_b);

    packed
}

pub fn unpack_two_arguments<A, B>(input: &[u8]) -> Result<(A, B), FheError>
where
    A: FHESerialize,
    B: FHESerialize,
{
    let ix_size = std::mem::size_of::<Index>();
    if input.len() < ix_size {
        return Err(FheError::UnexpectedEOF);
    }
    let ix_1 = &input[..ix_size];

    // The following unwraps are safe due to length check above
    let ix_1 = Index::from_be_bytes(ix_1.try_into().unwrap());

    let ix_1: usize = ix_1
        .try_into()
        .map_err(|_| FheError::PlatformArchitecture)?;

    let a = A::fhe_deserialize(&input[ix_size..ix_1])?;
    let b = B::fhe_deserialize(&input[ix_1..])?;

    Ok((a, b))
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

/// Pack data for a binary FHE precompile computation, for example
/// addition.
/// * `public_key` - Public key the parameters are encoded under.
/// * `a` - First argument to the FHE computation.
/// * `b` - Second argument to the FHE computation.
/// Returns a bytestring.
/// See also the inverse operation [`unpack_binary_operation`]
pub fn pack_binary_operation<A, B>(public_key: &PublicKey, a: &A, b: &B) -> Vec<u8>
where
    A: FHESerialize,
    B: FHESerialize,
{
    let packed_public_key = public_key.fhe_serialize();
    let packed_a = a.fhe_serialize();
    let packed_b = b.fhe_serialize();

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

/// Unpack data for a binary FHE precompile computation, for example
/// addition.
/// * `input` - Bytestring representing the FHE parameters.
/// Returns the public key, and the two arguments.
/// See also the inverse operation [`pack_binary_operation`]
pub fn unpack_binary_operation<A, B>(input: &[u8]) -> Result<(PublicKey, A, B), FheError>
where
    A: FHESerialize,
    B: FHESerialize,
{
    let ix_size = std::mem::size_of::<Index>();
    if input.len() < ix_size * 2 {
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

    let public_key = PublicKey::fhe_deserialize(&input[ix_size * 2..ix_1])?;
    let a = A::fhe_deserialize(&input[ix_1..ix_2])?;
    let b = B::fhe_deserialize(&input[ix_2..])?;

    Ok((public_key, a, b))
}

#[cfg(test)]
mod tests {
    use bincode::serialize;

    use super::*;
    use crate::pack::pack_nullary_operation;
    use crate::testnet::one::FHE;

    fn serialized_eq<T>(a: &T, b: &T) -> bool
    where
        T: ?Sized + serde::Serialize,
    {
        serialize(&a).unwrap() == serialize(&b).unwrap()
    }

    fn assert_serialized_eq<T>(a: &T, b: &T)
    where
        T: ?Sized + serde::Serialize,
    {
        assert!(serialized_eq(a, b));
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

    // Not precisely the inverse relation because we can't generate random valid
    // bytestrings.
    fn unpack_pack_are_inverse<A, B, EqA, EqB>(
        public_key: PublicKey,
        a: A,
        b: B,
        a_eq: EqA,
        b_eq: EqB,
    ) -> Result<(), FheError>
    where
        A: FHESerialize,
        B: FHESerialize,
        EqA: Fn(&A, &A) -> bool,
        EqB: Fn(&B, &B) -> bool,
    {
        // Test that unpack(pack(x)) == x
        let input = pack_binary_operation(&public_key, &a, &b);
        let (public_key_reconstituted, a_reconstituted, b_reconstituted) =
            unpack_binary_operation(&input)?;

        assert_serialized_eq(&public_key, &public_key_reconstituted);

        if !a_eq(&a, &a_reconstituted) {
            println!("a != a_reconstituted");
        }

        if !b_eq(&b, &b_reconstituted) {
            println!("b != b_reconstituted");
        }

        // Test that pack(unpack(pack(x))) == pack(x)
        let input2 = pack_binary_operation(
            &public_key_reconstituted,
            &a_reconstituted,
            &b_reconstituted,
        );
        assert_eq!(input2, input);
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_unsigned256cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_unsigned64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned64::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_signed64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = FHE.runtime().encrypt(Signed::from(4), &public_key).unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_unsigned256() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = Unsigned256::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_unsigned64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = Unsigned64::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_signed64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = Signed::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256cipher_vec() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = vec![1u8, 2, 3];

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64cipher_unsigned256cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned64::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64cipher_unsigned64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned64::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned64::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64cipher_signed64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned64::from(16), &public_key)
            .unwrap();

        let b = FHE.runtime().encrypt(Signed::from(4), &public_key).unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64cipher_unsigned256() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned64::from(16), &public_key)
            .unwrap();

        let b = Unsigned256::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64cipher_unsigned64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned64::from(16), &public_key)
            .unwrap();

        let b = Unsigned64::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64cipher_signed64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned64::from(16), &public_key)
            .unwrap();

        let b = Signed::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64cipher_unsigned256cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Signed::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64cipher_unsigned64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Signed::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned64::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64cipher_signed64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Signed::from(16), &public_key)
            .unwrap();

        let b = FHE.runtime().encrypt(Signed::from(4), &public_key).unwrap();

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64cipher_unsigned256() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Signed::from(16), &public_key)
            .unwrap();

        let b = Unsigned256::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64cipher_unsigned64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Signed::from(16), &public_key)
            .unwrap();

        let b = Unsigned64::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64cipher_signed64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Signed::from(16), &public_key)
            .unwrap();

        let b = Signed::from(4);

        unpack_pack_are_inverse(public_key, a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256_unsigned256cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256_unsigned64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);

        let b = FHE
            .runtime()
            .encrypt(Unsigned64::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256_signed64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);

        let b = FHE.runtime().encrypt(Signed::from(4), &public_key).unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256_unsigned256() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);

        let b = Unsigned256::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256_unsigned64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);

        let b = Unsigned64::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned256_signed64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);

        let b = Signed::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64_unsigned256cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64_unsigned64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);

        let b = FHE
            .runtime()
            .encrypt(Unsigned64::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64_signed64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);

        let b = FHE.runtime().encrypt(Signed::from(4), &public_key).unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64_unsigned256() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);

        let b = Unsigned256::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64_unsigned64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);

        let b = Unsigned64::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_unsigned64_signed64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);

        let b = Signed::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64_unsigned256cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64_unsigned64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);

        let b = FHE
            .runtime()
            .encrypt(Unsigned64::from(4), &public_key)
            .unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64_signed64cipher() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);

        let b = FHE.runtime().encrypt(Signed::from(4), &public_key).unwrap();

        unpack_pack_are_inverse(public_key, a, b, std::cmp::PartialEq::eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64_unsigned256() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);

        let b = Unsigned256::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64_unsigned64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);

        let b = Unsigned64::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    #[test]
    fn unpack_pack_is_id_signed64_signed64() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);

        let b = Signed::from(4);

        unpack_pack_are_inverse(
            public_key,
            a,
            b,
            std::cmp::PartialEq::eq,
            std::cmp::PartialEq::eq,
        )?;
        Ok(())
    }

    // Not precisely the inverse relation because we can't generate random valid
    // bytestrings.
    fn unpack_pack_two_arguments_are_inverse<A, B, EqA, EqB>(
        a: A,
        b: B,
        a_eq: EqA,
        b_eq: EqB,
    ) -> Result<(), FheError>
    where
        A: FHESerialize,
        B: FHESerialize,
        EqA: Fn(&A, &A) -> bool,
        EqB: Fn(&B, &B) -> bool,
    {
        // Test that unpack(pack(x)) == x
        let input = pack_two_arguments(&a, &b);
        let (a_reconstituted, b_reconstituted) = unpack_two_arguments(&input)?;

        if !a_eq(&a, &a_reconstituted) {
            println!("a != a_reconstituted");
        }

        if !b_eq(&b, &b_reconstituted) {
            println!("b != b_reconstituted");
        }

        // Test that pack(unpack(pack(x))) == pack(x)
        let input2 = pack_two_arguments(&a_reconstituted, &b_reconstituted);
        assert_eq!(input2, input);
        Ok(())
    }

    #[test]
    fn unpack_pack_two_argument_is_id_ciphertext_ciphertext() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = FHE
            .runtime()
            .encrypt(Unsigned256::from(4), &public_key)
            .unwrap();

        unpack_pack_two_arguments_are_inverse(a, b, serialized_eq, serialized_eq)?;
        Ok(())
    }

    #[test]
    fn unpack_pack_two_argument_is_id_ciphertext_vec() -> Result<(), FheError> {
        let (public_key, _) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime()
            .encrypt(Unsigned256::from(16), &public_key)
            .unwrap();

        let b = vec![1u8, 2, 3];

        unpack_pack_two_arguments_are_inverse(a, b, serialized_eq, std::cmp::PartialEq::eq)?;
        Ok(())
    }
}
