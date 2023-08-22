use std::ops::{Add, Mul, Sub};

use super::{FheError, PrecompileResult};
use crate::pack::{unpack_binary_operation, unpack_two_arguments, FHESerialize};
use bincode::serialize;
use sha2::{Digest, Sha512};
use sunscreen::{
    fhe_program,
    types::{
        bfv::{Fractional, Signed, Unsigned256, Unsigned64},
        Cipher, TryFromPlaintext, TryIntoPlaintext, TypeName,
    },
    Ciphertext, Compiler, FheApplication, FheProgramInput, FheRuntime, Params, PrivateKey,
    PublicKey, Runtime, RuntimeError,
};

/// Expects input to be packed with the
/// [`pack_binary_operation`][crate::pack::pack_binary_operation()] function.
fn fhe_binary_op<F, A, B>(op: F, input: &[u8]) -> PrecompileResult
where
    A: FHESerialize,
    B: FHESerialize,
    F: FnOnce(A, B, PublicKey) -> Result<Ciphertext, RuntimeError>,
{
    let (public_key, a, b) = unpack_binary_operation(input)?;
    let result = op(a, b, public_key).map_err(FheError::SunscreenError)?;
    Ok(serialize(&result).unwrap())
}

/// Generate keys for an FHE application without the galois keys. Meant to be
/// wrapped in other functions in this crate only.
pub(crate) fn generate_keys(runtime: &FheRuntime) -> Result<(PublicKey, PrivateKey), RuntimeError> {
    runtime.generate_keys().map(|(public_key, private_key)| {
        (
            PublicKey {
                galois_key: None,
                ..public_key
            },
            private_key,
        )
    })
}

/// Convert 512 bits in u8 format to u64 format.
fn u8_bits_to_u64_512_bits(input: [u8; 64]) -> [u64; 8] {
    input
        .chunks(8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap()
}

pub struct FheApp {
    application: FheApplication,
    runtime: FheRuntime,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl FheApp {
    pub fn runtime(&self) -> &FheRuntime {
        &self.runtime
    }

    /// Generate the FHE precompile functions for a specific set of parameters.
    pub fn from_params(params: &Params) -> Self {
        let params = params.clone();
        let application = Compiler::new()
            // u256
            .fhe_program(add_cipheru256_cipheru256)
            .fhe_program(add_cipheru256_u256)
            .fhe_program(add_u256_cipheru256)
            .fhe_program(sub_cipheru256_cipheru256)
            .fhe_program(sub_cipheru256_u256)
            .fhe_program(sub_u256_cipheru256)
            .fhe_program(mul_cipheru256_cipheru256)
            .fhe_program(mul_cipheru256_u256)
            .fhe_program(mul_u256_cipheru256)
            // u64
            .fhe_program(add_cipheru64_cipheru64)
            .fhe_program(add_cipheru64_u64)
            .fhe_program(add_u64_cipheru64)
            .fhe_program(sub_cipheru64_cipheru64)
            .fhe_program(sub_cipheru64_u64)
            .fhe_program(sub_u64_cipheru64)
            .fhe_program(mul_cipheru64_cipheru64)
            .fhe_program(mul_cipheru64_u64)
            .fhe_program(mul_u64_cipheru64)
            // i64
            .fhe_program(add_cipheri64_cipheri64)
            .fhe_program(add_cipheri64_i64)
            .fhe_program(add_i64_cipheri64)
            .fhe_program(sub_cipheri64_cipheri64)
            .fhe_program(sub_cipheri64_i64)
            .fhe_program(sub_i64_cipheri64)
            .fhe_program(mul_cipheri64_cipheri64)
            .fhe_program(mul_cipheri64_i64)
            .fhe_program(mul_i64_cipheri64)
            // frac64
            .fhe_program(add_cipherfrac64_cipherfrac64)
            .fhe_program(add_cipherfrac64_frac64)
            .fhe_program(add_frac64_cipherfrac64)
            .fhe_program(sub_cipherfrac64_cipherfrac64)
            .fhe_program(sub_cipherfrac64_frac64)
            .fhe_program(sub_frac64_cipherfrac64)
            .fhe_program(mul_cipherfrac64_cipherfrac64)
            .fhe_program(mul_cipherfrac64_frac64)
            .fhe_program(mul_frac64_cipherfrac64)
            .with_params(&params)
            .compile()
            .unwrap();
        let runtime = Runtime::new_fhe(&params).unwrap();

        let public_key = bincode::deserialize(include_bytes!("data/network.pub")).unwrap();
        let private_key = bincode::deserialize(include_bytes!("data/network.pri")).unwrap();

        Self {
            application,
            runtime,
            public_key,
            private_key,
        }
    }

    /// Generate keys for an FHE application.
    pub fn generate_keys(&self) -> Result<(PublicKey, PrivateKey), RuntimeError> {
        generate_keys(&self.runtime)
    }

    fn run(
        &self,
        program: impl AsRef<str>,
        a: impl Into<FheProgramInput>,
        b: impl Into<FheProgramInput>,
        public_key: PublicKey,
    ) -> Result<Ciphertext, RuntimeError> {
        self.runtime
            .run(
                self.application.get_fhe_program(program).unwrap(),
                vec![a.into(), b.into()],
                &public_key,
            )
            .map(|mut out| out.pop().unwrap())
    }

    /**********************************************************************
     * u256
     *********************************************************************/

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipheru256_cipheru256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(add_cipheru256_cipheru256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipheru256_u256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Unsigned256, key: PublicKey| {
                self.run(add_cipheru256_u256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_u256_cipheru256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Unsigned256, b: Ciphertext, key: PublicKey| {
                self.run(add_u256_cipheru256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipheru256_cipheru256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(sub_cipheru256_cipheru256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipheru256_u256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Unsigned256, key: PublicKey| {
                self.run(sub_cipheru256_u256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_u256_cipheru256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Unsigned256, b: Ciphertext, key: PublicKey| {
                self.run(sub_u256_cipheru256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipheru256_cipheru256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(mul_cipheru256_cipheru256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipheru256_u256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Unsigned256, key: PublicKey| {
                self.run(mul_cipheru256_u256, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_u256_cipheru256(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Unsigned256, b: Ciphertext, key: PublicKey| {
                self.run(mul_u256_cipheru256, a, b, key)
            },
            input,
        )
    }

    /**********************************************************************
     * u64
     *********************************************************************/

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipheru64_cipheru64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(add_cipheru64_cipheru64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipheru64_u64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Unsigned64, key: PublicKey| self.run(add_cipheru64_u64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_u64_cipheru64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Unsigned64, b: Ciphertext, key: PublicKey| self.run(add_u64_cipheru64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipheru64_cipheru64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(sub_cipheru64_cipheru64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipheru64_u64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Unsigned64, key: PublicKey| self.run(sub_cipheru64_u64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_u64_cipheru64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Unsigned64, b: Ciphertext, key: PublicKey| self.run(sub_u64_cipheru64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipheru64_cipheru64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(mul_cipheru64_cipheru64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipheru64_u64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Unsigned64, key: PublicKey| self.run(mul_cipheru64_u64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_u64_cipheru64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Unsigned64, b: Ciphertext, key: PublicKey| self.run(mul_u64_cipheru64, a, b, key),
            input,
        )
    }

    /**********************************************************************
     * i64
     *********************************************************************/

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipheri64_cipheri64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(add_cipheri64_cipheri64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipheri64_i64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Signed, key: PublicKey| self.run(add_cipheri64_i64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_i64_cipheri64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Signed, b: Ciphertext, key: PublicKey| self.run(add_i64_cipheri64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipheri64_cipheri64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(sub_cipheri64_cipheri64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipheri64_i64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Signed, key: PublicKey| self.run(sub_cipheri64_i64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_i64_cipheri64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Signed, b: Ciphertext, key: PublicKey| self.run(sub_i64_cipheri64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipheri64_cipheri64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(mul_cipheri64_cipheri64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipheri64_i64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Signed, key: PublicKey| self.run(mul_cipheri64_i64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_i64_cipheri64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Signed, b: Ciphertext, key: PublicKey| self.run(mul_i64_cipheri64, a, b, key),
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipherfrac64_cipherfrac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(add_cipherfrac64_cipherfrac64, a, b, key)
            },
            input,
        )
    }

    /**********************************************************************
     * frac64
     *********************************************************************/

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_cipherfrac64_frac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Fractional<64>, key: PublicKey| {
                self.run(add_cipherfrac64_frac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add_frac64_cipherfrac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Fractional<64>, b: Ciphertext, key: PublicKey| {
                self.run(add_frac64_cipherfrac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipherfrac64_cipherfrac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(sub_cipherfrac64_cipherfrac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_cipherfrac64_frac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Fractional<64>, key: PublicKey| {
                self.run(sub_cipherfrac64_frac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn sub_frac64_cipherfrac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Fractional<64>, b: Ciphertext, key: PublicKey| {
                self.run(sub_frac64_cipherfrac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipherfrac64_cipherfrac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Ciphertext, key: PublicKey| {
                self.run(mul_cipherfrac64_cipherfrac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_cipherfrac64_frac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Ciphertext, b: Fractional<64>, key: PublicKey| {
                self.run(mul_cipherfrac64_frac64, a, b, key)
            },
            input,
        )
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn mul_frac64_cipherfrac64(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(
            |a: Fractional<64>, b: Ciphertext, key: PublicKey| {
                self.run(mul_frac64_cipherfrac64, a, b, key)
            },
            input,
        )
    }

    /**********************************************************************
     * Threshold network simulation API
     *********************************************************************/

    /**
     * Encrypt a value with the public key of the network.
     *
     * The input is expected to be packed with the
     * [`pack_two_arguments`][crate::pack::pack_two_arguments()] function.
     *
     * The first argument is the plaintext to encrypt, and the second
     * argument is the public data to be hashed and used as a seed for
     * encryption.
     *
     * The output is the encrypted value.
     */
    pub fn encrypt<P>(&self, input: &[u8]) -> PrecompileResult
    where
        P: TryFromPlaintext + TryIntoPlaintext + TypeName + FHESerialize,
    {
        let (plain, public_data): (P, Vec<u8>) = unpack_two_arguments(input)?;

        let mut hasher = Sha512::new();
        hasher.update(public_data);

        // Add a uniformly random, private constant 512 bit value
        hasher.update([
            15u8, 17, 225, 5, 30, 1, 237, 218, 130, 19, 37, 95, 222, 218, 244, 172, 214, 175, 175,
            110, 173, 103, 172, 60, 43, 76, 40, 150, 215, 96, 23, 78, 22, 39, 30, 177, 107, 130,
            124, 109, 27, 96, 206, 125, 104, 241, 10, 40, 88, 238, 117, 118, 79, 113, 213, 110,
            148, 179, 53, 19, 227, 154, 151, 122,
        ]);
        let seed = u8_bits_to_u64_512_bits(hasher.finalize().into());

        let cipher = self
            .runtime
            .encrypt_deterministic(plain, &self.public_key, &seed)
            .map_err(|_| FheError::FailedEncryption)?;
        Ok(serialize(&cipher).unwrap())
    }

    /**
     * Reencrypt a value with a given public key.
     *
     * The input is expected to be packed with the
     * [`pack_binary_operation`][crate::pack::pack_binary_operation()] function.
     *
     * The first argument is the public key to reencrypt with, the second
     * argument is the ciphertext to reencrypt, and the third argument is the
     * public data to be hashed and used as a seed for encryption.
     *
     * The output is the reencrypted value.
     */
    fn reencrypt_any_key<P>(
        &self,
        public_key: &PublicKey,
        ciphertext: &Ciphertext,
        public_data: &[u8],
    ) -> PrecompileResult
    where
        P: TryFromPlaintext + TryIntoPlaintext + TypeName + FHESerialize,
    {
        let plain: P = self
            .runtime
            .decrypt(ciphertext, &self.private_key)
            .map_err(|_| FheError::FailedDecryption)?;

        let mut hasher = Sha512::new();
        hasher.update(public_data);
        hasher.update(plain.fhe_serialize());
        let seed = u8_bits_to_u64_512_bits(hasher.finalize().into());

        let new_cipher = self
            .runtime
            .encrypt_deterministic(plain, public_key, &seed)
            .map_err(|_| FheError::FailedEncryption)?;

        Ok(serialize(&new_cipher).unwrap())
    }

    /**
     * Reencrypt a value from the network key to another key.
     *
     * The input is expected to be packed with the
     * [`pack_binary_operation`][crate::pack::pack_binary_operation()] function.
     *
     * The first argument is the public key to reencrypt with, the second
     * argument is the ciphertext to reencrypt, and the third argument is the
     * public data to be hashed and used as a seed for encryption.
     */
    pub fn reencrypt<P>(&self, input: &[u8]) -> PrecompileResult
    where
        P: TryFromPlaintext + TryIntoPlaintext + TypeName + FHESerialize,
    {
        let (public_key, ciphertext, public_data): (PublicKey, Ciphertext, Vec<u8>) =
            unpack_binary_operation(input)?;

        let public_data = vec![public_data, input.to_vec()].concat();
        self.reencrypt_any_key::<P>(&public_key, &ciphertext, &public_data)
    }

    /**
     * Refresh a value with the public key of the network.
     *
     * The input is expected to be packed with the
     * [`pack_binary_operation`][crate::pack::pack_binary_operation()] function.
     *
     * The first argument is the ciphertext to refresh, and the second argument
     * is the public data to be hashed and used as a seed for encryption.
     *
     * The output is the refreshed ciphertext.
     */
    pub fn refresh<P>(&self, input: &[u8]) -> PrecompileResult
    where
        P: TryFromPlaintext + TryIntoPlaintext + TypeName + FHESerialize,
    {
        let (ciphertext, public_data): (Ciphertext, Vec<u8>) = unpack_two_arguments(input)?;

        let public_data = vec![public_data, input.to_vec()].concat();
        self.reencrypt_any_key::<P>(&self.public_key, &ciphertext, &public_data)
    }

    pub fn public_key_bytes(&self, _input: &[u8]) -> PrecompileResult {
        Ok(serialize(&self.public_key).unwrap())
    }

    /**********************************************************************
     * Threshold network simulation API specialized to specific types
     *********************************************************************/

    /// See [`encrypt()`][Self::encrypt()] for details. This is a specialized
    /// variant for the Unsigned256 type.
    pub fn encrypt_u256(&self, input: &[u8]) -> PrecompileResult {
        self.encrypt::<Unsigned256>(input)
    }

    /// See [`encrypt()`][Self::encrypt()] for details. This is a specialized
    /// variant for the Unsigned64 type.
    pub fn encrypt_u64(&self, input: &[u8]) -> PrecompileResult {
        self.encrypt::<Unsigned64>(input)
    }

    /// See [`encrypt()`][Self::encrypt()] for details. This is a specialized
    /// variant for the Signed type.
    pub fn encrypt_i64(&self, input: &[u8]) -> PrecompileResult {
        self.encrypt::<Signed>(input)
    }

    /// See [`encrypt()`][Self::encrypt()] for details. This is a specialized
    /// variant for the Fractional::<64> type.
    pub fn encrypt_frac64(&self, input: &[u8]) -> PrecompileResult {
        self.encrypt::<Fractional<64>>(input)
    }

    /// See [`reencrypt()`][Self::reencrypt()] for details. This is a
    /// specialized variant for the Unsigned256 type.
    pub fn reencrypt_u256(&self, input: &[u8]) -> PrecompileResult {
        self.reencrypt::<Unsigned256>(input)
    }

    /// See [`reencrypt()`][Self::reencrypt()] for details. This is a
    /// specialized variant for the Unsigned64 type.
    pub fn reencrypt_u64(&self, input: &[u8]) -> PrecompileResult {
        self.reencrypt::<Unsigned64>(input)
    }

    /// See [`reencrypt()`][Self::reencrypt()] for details. This is a
    /// specialized variant for the Signed type.
    pub fn reencrypt_i64(&self, input: &[u8]) -> PrecompileResult {
        self.reencrypt::<Signed>(input)
    }

    /// See [`reencrypt()`][Self::reencrypt()] for details. This is a
    /// specialized variant for the Fractional::<64> type.
    pub fn reencrypt_frac64(&self, input: &[u8]) -> PrecompileResult {
        self.reencrypt::<Fractional<64>>(input)
    }

    /// See [`refresh()`][Self::refresh()] for details. This is a specialized
    /// variant for the Unsigned256 type.
    pub fn refresh_u256(&self, input: &[u8]) -> PrecompileResult {
        self.refresh::<Unsigned256>(input)
    }

    /// See [`refresh()`][Self::refresh()] for details. This is a specialized
    /// variant for the Unsigned64 type.
    pub fn refresh_u64(&self, input: &[u8]) -> PrecompileResult {
        self.refresh::<Unsigned64>(input)
    }

    /// See [`refresh()`][Self::refresh()] for details. This is a specialized
    /// variant for the Signed type.
    pub fn refresh_i64(&self, input: &[u8]) -> PrecompileResult {
        self.refresh::<Signed>(input)
    }

    /// See [`refresh()`][Self::refresh()] for details. This is a specialized
    /// variant for the Fractional::<64> type.
    pub fn refresh_frac64(&self, input: &[u8]) -> PrecompileResult {
        self.refresh::<Fractional<64>>(input)
    }
}

/// Base operations

/// Addition
fn add<A, B, T>(a: A, b: B) -> T
where
    A: Add<B, Output = T>,
{
    a + b
}

/// Subtract
fn sub<A, B, T>(a: A, b: B) -> T
where
    A: Sub<B, Output = T>,
{
    a - b
}

/// Multiplication
fn mul<A, B, T>(a: A, b: B) -> T
where
    A: Mul<B, Output = T>,
{
    a * b
}

/// FHE programs per type

/**********************************************************************
 * u256
 *********************************************************************/

#[fhe_program(scheme = "bfv")]
fn add_cipheru256_cipheru256(
    a: Cipher<Unsigned256>,
    b: Cipher<Unsigned256>,
) -> Cipher<Unsigned256> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_cipheru256_u256(a: Cipher<Unsigned256>, b: Unsigned256) -> Cipher<Unsigned256> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_u256_cipheru256(a: Unsigned256, b: Cipher<Unsigned256>) -> Cipher<Unsigned256> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipheru256_cipheru256(
    a: Cipher<Unsigned256>,
    b: Cipher<Unsigned256>,
) -> Cipher<Unsigned256> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipheru256_u256(a: Cipher<Unsigned256>, b: Unsigned256) -> Cipher<Unsigned256> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_u256_cipheru256(a: Unsigned256, b: Cipher<Unsigned256>) -> Cipher<Unsigned256> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipheru256_cipheru256(
    a: Cipher<Unsigned256>,
    b: Cipher<Unsigned256>,
) -> Cipher<Unsigned256> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipheru256_u256(a: Cipher<Unsigned256>, b: Unsigned256) -> Cipher<Unsigned256> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_u256_cipheru256(a: Unsigned256, b: Cipher<Unsigned256>) -> Cipher<Unsigned256> {
    mul(a, b)
}

/**********************************************************************
 * u64
 *********************************************************************/

#[fhe_program(scheme = "bfv")]
fn add_cipheru64_cipheru64(a: Cipher<Unsigned64>, b: Cipher<Unsigned64>) -> Cipher<Unsigned64> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_cipheru64_u64(a: Cipher<Unsigned64>, b: Unsigned64) -> Cipher<Unsigned64> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_u64_cipheru64(a: Unsigned64, b: Cipher<Unsigned64>) -> Cipher<Unsigned64> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipheru64_cipheru64(a: Cipher<Unsigned64>, b: Cipher<Unsigned64>) -> Cipher<Unsigned64> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipheru64_u64(a: Cipher<Unsigned64>, b: Unsigned64) -> Cipher<Unsigned64> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_u64_cipheru64(a: Unsigned64, b: Cipher<Unsigned64>) -> Cipher<Unsigned64> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipheru64_cipheru64(a: Cipher<Unsigned64>, b: Cipher<Unsigned64>) -> Cipher<Unsigned64> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipheru64_u64(a: Cipher<Unsigned64>, b: Unsigned64) -> Cipher<Unsigned64> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_u64_cipheru64(a: Unsigned64, b: Cipher<Unsigned64>) -> Cipher<Unsigned64> {
    mul(a, b)
}

/**********************************************************************
 * i64
 *********************************************************************/

#[fhe_program(scheme = "bfv")]
fn add_cipheri64_cipheri64(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_cipheri64_i64(a: Cipher<Signed>, b: Signed) -> Cipher<Signed> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_i64_cipheri64(a: Signed, b: Cipher<Signed>) -> Cipher<Signed> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipheri64_cipheri64(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipheri64_i64(a: Cipher<Signed>, b: Signed) -> Cipher<Signed> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_i64_cipheri64(a: Signed, b: Cipher<Signed>) -> Cipher<Signed> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipheri64_cipheri64(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipheri64_i64(a: Cipher<Signed>, b: Signed) -> Cipher<Signed> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_i64_cipheri64(a: Signed, b: Cipher<Signed>) -> Cipher<Signed> {
    mul(a, b)
}

/**********************************************************************
 * frac64
 *********************************************************************/

#[fhe_program(scheme = "bfv")]
fn add_cipherfrac64_cipherfrac64(
    a: Cipher<Fractional<64>>,
    b: Cipher<Fractional<64>>,
) -> Cipher<Fractional<64>> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_cipherfrac64_frac64(a: Cipher<Fractional<64>>, b: Fractional<64>) -> Cipher<Fractional<64>> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn add_frac64_cipherfrac64(a: Fractional<64>, b: Cipher<Fractional<64>>) -> Cipher<Fractional<64>> {
    add(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipherfrac64_cipherfrac64(
    a: Cipher<Fractional<64>>,
    b: Cipher<Fractional<64>>,
) -> Cipher<Fractional<64>> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_cipherfrac64_frac64(a: Cipher<Fractional<64>>, b: Fractional<64>) -> Cipher<Fractional<64>> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn sub_frac64_cipherfrac64(a: Fractional<64>, b: Cipher<Fractional<64>>) -> Cipher<Fractional<64>> {
    sub(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipherfrac64_cipherfrac64(
    a: Cipher<Fractional<64>>,
    b: Cipher<Fractional<64>>,
) -> Cipher<Fractional<64>> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_cipherfrac64_frac64(a: Cipher<Fractional<64>>, b: Fractional<64>) -> Cipher<Fractional<64>> {
    mul(a, b)
}

#[fhe_program(scheme = "bfv")]
fn mul_frac64_cipherfrac64(a: Fractional<64>, b: Cipher<Fractional<64>>) -> Cipher<Fractional<64>> {
    mul(a, b)
}

#[cfg(test)]
mod tests {
    use bincode::deserialize;
    use sunscreen::types::{TryFromPlaintext, TypeName};
    use sunscreen::{types::bfv::Unsigned256, RuntimeError};

    use super::*;
    use crate::pack::{pack_binary_operation, pack_two_arguments};
    use crate::testnet::one::FHE;

    /**********************************************************************
     * u256 tests
     *********************************************************************/

    #[test]
    fn fhe_add_cipher_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned256::from(4), &public_key)?;

        let result = FHE.run(add_cipheru256_cipheru256, a, b, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(20_u64));
        Ok(())
    }

    #[test]
    fn fhe_add_plain_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = Unsigned256::from(4);

        let result = FHE.run(add_cipheru256_u256, a.clone(), b, public_key.clone())?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(20_u64));

        let result = FHE.run(add_u256_cipheru256, b, a, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(20_u64));

        Ok(())
    }

    #[test]
    fn precompile_add_cipher_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.add_cipheru256_cipheru256(input);
        let arg1 = Unsigned256::from(16);
        let arg2 = Unsigned256::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 + arg2,
        )
    }

    #[test]
    fn precompile_add_plain_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.add_cipheru256_u256(input);
        let precompile_right = |input: &[u8]| FHE.add_u256_cipheru256(input);

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = Unsigned256::from(4);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Unsigned256::from(20),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Unsigned256::from(20),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_sub_cipher_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned256::from(4), &public_key)?;

        let result = FHE.run(sub_cipheru256_cipheru256, a, b, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(12_u64));
        Ok(())
    }

    #[test]
    fn fhe_sub_plain_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = Unsigned256::from(16);
        let b = Unsigned256::from(4);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        let result = FHE.run(sub_cipheru256_u256, a_encrypted, b, public_key.clone())?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(12_u64));

        let result = FHE.run(sub_u256_cipheru256, a, b_encrypted, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(12_u64));

        Ok(())
    }

    #[test]
    fn precompile_sub_cipher_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.sub_cipheru256_cipheru256(input);
        let arg1 = Unsigned256::from(16);
        let arg2 = Unsigned256::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 - arg2,
        )
    }

    #[test]
    fn precompile_sub_plain_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.sub_cipheru256_u256(input);
        let precompile_right = |input: &[u8]| FHE.sub_u256_cipheru256(input);

        let a = Unsigned256::from(16);
        let b = Unsigned256::from(4);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a_encrypted,
            b,
            Unsigned256::from(12),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            a,
            b_encrypted,
            Unsigned256::from(12),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_mul_cipher_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned256::from(4), &public_key)?;

        let result = FHE.run(mul_cipheru256_cipheru256, a, b, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(64_u64));
        Ok(())
    }

    #[test]
    fn fhe_mul_plain_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = Unsigned256::from(4);

        let result = FHE.run(mul_cipheru256_u256, a.clone(), b, public_key.clone())?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(64_u64));

        let result = FHE.run(mul_u256_cipheru256, b, a, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(64_u64));

        Ok(())
    }

    #[test]
    fn precompile_mul_cipher_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.mul_cipheru256_cipheru256(input);
        let arg1 = Unsigned256::from(16);
        let arg2 = Unsigned256::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 * arg2,
        )
    }

    #[test]
    fn precompile_mul_plain_u256_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.mul_cipheru256_u256(input);
        let precompile_right = |input: &[u8]| FHE.mul_u256_cipheru256(input);

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = Unsigned256::from(4);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Unsigned256::from(64),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Unsigned256::from(64),
        )?;

        Ok(())
    }

    /**********************************************************************
     * u64 tests
     *********************************************************************/

    #[test]
    fn fhe_add_cipher_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned64::from(4), &public_key)?;

        let result = FHE.run(add_cipheru64_cipheru64, a, b, public_key)?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(20_u64));
        Ok(())
    }

    #[test]
    fn fhe_add_plain_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = Unsigned64::from(4);

        let result = FHE.run(add_cipheru64_u64, a.clone(), b, public_key.clone())?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(20_u64));

        let result = FHE.run(add_u64_cipheru64, b, a, public_key)?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(20_u64));

        Ok(())
    }

    #[test]
    fn precompile_add_cipher_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.add_cipheru64_cipheru64(input);
        let arg1 = Unsigned64::from(16);
        let arg2 = Unsigned64::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 + arg2,
        )
    }

    #[test]
    fn precompile_add_plain_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.add_cipheru64_u64(input);
        let precompile_right = |input: &[u8]| FHE.add_u64_cipheru64(input);

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = Unsigned64::from(4);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Unsigned64::from(20),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Unsigned64::from(20),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_sub_cipher_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned64::from(4), &public_key)?;

        let result = FHE.run(sub_cipheru64_cipheru64, a, b, public_key)?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(12_u64));
        Ok(())
    }

    #[test]
    fn fhe_sub_plain_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = Unsigned64::from(16);
        let b = Unsigned64::from(4);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        let result = FHE.run(sub_cipheru64_u64, a_encrypted, b, public_key.clone())?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(12_u64));

        let result = FHE.run(sub_u64_cipheru64, a, b_encrypted, public_key)?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(12_u64));

        Ok(())
    }

    #[test]
    fn fhe_mul_cipher_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned64::from(4), &public_key)?;

        let result = FHE.run(mul_cipheru64_cipheru64, a, b, public_key)?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(64_u64));
        Ok(())
    }

    #[test]
    fn fhe_mul_plain_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = Unsigned64::from(4);

        let result = FHE.run(mul_cipheru64_u64, a.clone(), b, public_key.clone())?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(64_u64));

        let result = FHE.run(mul_u64_cipheru64, b, a, public_key)?;
        let c: Unsigned64 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned64::from(64_u64));

        Ok(())
    }

    #[test]
    fn precompile_mul_cipher_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.mul_cipheru64_cipheru64(input);
        let arg1 = Unsigned64::from(16);
        let arg2 = Unsigned64::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 * arg2,
        )
    }

    #[test]
    fn precompile_mul_plain_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.mul_cipheru64_u64(input);
        let precompile_right = |input: &[u8]| FHE.mul_u64_cipheru64(input);

        let a = FHE.runtime.encrypt(Unsigned64::from(16), &public_key)?;
        let b = Unsigned64::from(4);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Unsigned64::from(64),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Unsigned64::from(64),
        )?;

        Ok(())
    }

    #[test]
    fn precompile_sub_cipher_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.sub_cipheru64_cipheru64(input);
        let arg1 = Unsigned64::from(16);
        let arg2 = Unsigned64::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 - arg2,
        )
    }

    #[test]
    fn precompile_sub_plain_u64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.sub_cipheru64_u64(input);
        let precompile_right = |input: &[u8]| FHE.sub_u64_cipheru64(input);

        let a = Unsigned64::from(16);
        let b = Unsigned64::from(4);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a_encrypted,
            b,
            Unsigned64::from(12),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            a,
            b_encrypted,
            Unsigned64::from(12),
        )?;

        Ok(())
    }

    /**********************************************************************
     * i64 tests
     *********************************************************************/

    #[test]
    fn fhe_add_cipher_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Signed::from(4), &public_key)?;

        let result = FHE.run(add_cipheri64_cipheri64, a, b, public_key)?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(20_i64));
        Ok(())
    }

    #[test]
    fn fhe_add_plain_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = Signed::from(4);

        let result = FHE.run(add_cipheri64_i64, a.clone(), b, public_key.clone())?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(20_i64));

        let result = FHE.run(add_i64_cipheri64, b, a, public_key)?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(20_i64));

        Ok(())
    }

    #[test]
    fn precompile_add_cipher_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.add_cipheri64_cipheri64(input);
        let arg1 = Signed::from(16);
        let arg2 = Signed::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 + arg2,
        )
    }

    #[test]
    fn precompile_add_plain_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.add_cipheri64_i64(input);
        let precompile_right = |input: &[u8]| FHE.add_i64_cipheri64(input);

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = Signed::from(4);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Signed::from(20),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Signed::from(20),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_sub_cipher_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Signed::from(4), &public_key)?;

        let result = FHE.run(sub_cipheri64_cipheri64, a, b, public_key)?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(12_i64));
        Ok(())
    }

    #[test]
    fn fhe_sub_plain_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = Signed::from(16);
        let b = Signed::from(4);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        let result = FHE.run(sub_cipheri64_i64, a_encrypted, b, public_key.clone())?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(12_i64));

        let result = FHE.run(sub_i64_cipheri64, a, b_encrypted, public_key)?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(12_i64));

        Ok(())
    }

    #[test]
    fn precompile_sub_cipher_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.sub_cipheri64_cipheri64(input);
        let arg1 = Signed::from(16);
        let arg2 = Signed::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 - arg2,
        )
    }

    #[test]
    fn precompile_sub_plain_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.sub_cipheri64_i64(input);
        let precompile_right = |input: &[u8]| FHE.sub_i64_cipheri64(input);

        let a = Signed::from(16);
        let b = Signed::from(4);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a_encrypted,
            b,
            Signed::from(12),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            a,
            b_encrypted,
            Signed::from(12),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_mul_cipher_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Signed::from(4), &public_key)?;

        let result = FHE.run(mul_cipheri64_cipheri64, a, b, public_key)?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(64_i64));
        Ok(())
    }

    #[test]
    fn fhe_mul_plain_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = Signed::from(4);

        let result = FHE.run(mul_cipheri64_i64, a.clone(), b, public_key.clone())?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(64_i64));

        let result = FHE.run(mul_i64_cipheri64, b, a, public_key)?;
        let c: Signed = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Signed::from(64_i64));

        Ok(())
    }

    #[test]
    fn precompile_mul_cipher_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.mul_cipheri64_cipheri64(input);
        let arg1 = Signed::from(16);
        let arg2 = Signed::from(4);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 * arg2,
        )
    }

    #[test]
    fn precompile_mul_plain_i64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.mul_cipheri64_i64(input);
        let precompile_right = |input: &[u8]| FHE.mul_i64_cipheri64(input);

        let a = FHE.runtime.encrypt(Signed::from(16), &public_key)?;
        let b = Signed::from(4);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Signed::from(64),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Signed::from(64),
        )?;

        Ok(())
    }

    /**********************************************************************
     * frac64 tests
     *********************************************************************/

    #[test]
    fn fhe_add_cipher_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = FHE
            .runtime
            .encrypt(Fractional::<64>::from(4.0), &public_key)?;

        let result = FHE.run(add_cipherfrac64_cipherfrac64, a, b, public_key)?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(20_f64));
        Ok(())
    }

    #[test]
    fn fhe_add_plain_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = Fractional::<64>::from(4.0);

        let result = FHE.run(add_cipherfrac64_frac64, a.clone(), b, public_key.clone())?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(20_f64));

        let result = FHE.run(add_frac64_cipherfrac64, b, a, public_key)?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(20_f64));

        Ok(())
    }

    #[test]
    fn precompile_add_cipher_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.add_cipherfrac64_cipherfrac64(input);
        let arg1 = Fractional::<64>::from(16.0);
        let arg2 = Fractional::<64>::from(4.0);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 + arg2,
        )
    }

    #[test]
    fn precompile_add_plain_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.add_cipherfrac64_frac64(input);
        let precompile_right = |input: &[u8]| FHE.add_frac64_cipherfrac64(input);

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = Fractional::<64>::from(4.0);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Fractional::<64>::from(20.0),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Fractional::<64>::from(20.0),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_sub_cipher_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = FHE
            .runtime
            .encrypt(Fractional::<64>::from(4.0), &public_key)?;

        let result = FHE.run(sub_cipherfrac64_cipherfrac64, a, b, public_key)?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(12_f64));
        Ok(())
    }

    #[test]
    fn fhe_sub_plain_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = Fractional::<64>::from(16.0);
        let b = Fractional::<64>::from(4.0);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        let result = FHE.run(sub_cipherfrac64_frac64, a_encrypted, b, public_key.clone())?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(12_f64));

        let result = FHE.run(sub_frac64_cipherfrac64, a, b_encrypted, public_key)?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(12_f64));

        Ok(())
    }

    #[test]
    fn precompile_sub_cipher_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.sub_cipherfrac64_cipherfrac64(input);
        let arg1 = Fractional::<64>::from(16.0);
        let arg2 = Fractional::<64>::from(4.0);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 - arg2,
        )
    }

    #[test]
    fn precompile_sub_plain_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.sub_cipherfrac64_frac64(input);
        let precompile_right = |input: &[u8]| FHE.sub_frac64_cipherfrac64(input);

        let a = Fractional::<64>::from(16.0);
        let b = Fractional::<64>::from(4.0);

        let a_encrypted = FHE.runtime.encrypt(a, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(b, &public_key)?;

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a_encrypted,
            b,
            Fractional::<64>::from(12.0),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            a,
            b_encrypted,
            Fractional::<64>::from(12.0),
        )?;

        Ok(())
    }

    #[test]
    fn fhe_mul_cipher_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = FHE
            .runtime
            .encrypt(Fractional::<64>::from(4.0), &public_key)?;

        let result = FHE.run(mul_cipherfrac64_cipherfrac64, a, b, public_key)?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(64_f64));
        Ok(())
    }

    #[test]
    fn fhe_mul_plain_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = Fractional::<64>::from(4.0);

        let result = FHE.run(mul_cipherfrac64_frac64, a.clone(), b, public_key.clone())?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(64_f64));

        let result = FHE.run(mul_frac64_cipherfrac64, b, a, public_key)?;
        let c: Fractional<64> = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Fractional::<64>::from(64_f64));

        Ok(())
    }

    #[test]
    fn precompile_mul_cipher_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile = |input: &[u8]| FHE.mul_cipherfrac64_cipherfrac64(input);
        let arg1 = Fractional::<64>::from(16.0);
        let arg2 = Fractional::<64>::from(4.0);

        let a_encrypted = FHE.runtime.encrypt(arg1, &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(arg2, &public_key)?;
        precompile_fhe_op_works(
            precompile,
            &public_key,
            &private_key,
            a_encrypted,
            b_encrypted,
            arg1 * arg2,
        )
    }

    #[test]
    fn precompile_mul_plain_frac64_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let precompile_left = |input: &[u8]| FHE.mul_cipherfrac64_frac64(input);
        let precompile_right = |input: &[u8]| FHE.mul_frac64_cipherfrac64(input);

        let a = FHE
            .runtime
            .encrypt(Fractional::<64>::from(16.0), &public_key)?;
        let b = Fractional::<64>::from(4.0);

        precompile_fhe_op_works(
            precompile_left,
            &public_key,
            &private_key,
            a.clone(),
            b,
            Fractional::<64>::from(64.0),
        )?;

        precompile_fhe_op_works(
            precompile_right,
            &public_key,
            &private_key,
            b,
            a,
            Fractional::<64>::from(64.0),
        )?;

        Ok(())
    }

    /**********************************************************************
     * Threshold simulation API tests
     *********************************************************************/

    #[test]
    fn fhe_encrypt_test() -> Result<(), RuntimeError> {
        let value = Unsigned256::from(12);
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&value, &public_data);

        let result = FHE.encrypt::<Unsigned256>(&input).unwrap();
        let ciphertext: Ciphertext = bincode::deserialize(&result)?;

        let decrypted_value: Unsigned256 = FHE.runtime.decrypt(&ciphertext, &FHE.private_key)?;

        assert_eq!(decrypted_value, value);

        // Check that the encryption generated the same value
        let mut hasher = Sha512::new();
        hasher.update(result);
        let hash = hasher.finalize();

        assert_eq!(
            hash,
            (if cfg!(macos) {
                [
                    59, 222, 214, 129, 107, 159, 17, 247, 190, 136, 204, 214, 176, 76, 221, 202, 6,
                    99, 28, 193, 247, 53, 177, 14, 61, 252, 201, 42, 177, 235, 224, 221, 124, 200,
                    148, 209, 125, 137, 74, 137, 160, 149, 58, 20, 65, 162, 206, 38, 41, 116, 61,
                    142, 196, 54, 244, 225, 201, 207, 3, 24, 33, 20, 91, 79,
                ]
            } else {
                [
                    137, 159, 248, 16, 120, 136, 94, 231, 221, 42, 28, 137, 56, 39, 239, 114, 74,
                    64, 137, 122, 12, 43, 82, 154, 3, 31, 209, 30, 47, 182, 141, 185, 182, 0, 171,
                    80, 108, 155, 79, 33, 87, 73, 126, 182, 59, 252, 150, 238, 87, 164, 232, 25,
                    223, 94, 108, 114, 227, 16, 201, 233, 92, 42, 135, 128,
                ]
            })
            .into()
        );
        Ok(())
    }

    #[test]
    fn fhe_refresh_test() -> Result<(), RuntimeError> {
        let value = Unsigned256::from(12);

        let ciphertext =
            FHE.runtime
                .encrypt_deterministic(value, &FHE.public_key, &[0, 0, 0, 0, 0, 0, 0, 0])?;
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&ciphertext, &public_data);

        let result = FHE.refresh::<Unsigned256>(&input).unwrap();
        let ciphertext: Ciphertext = bincode::deserialize(&result)?;

        let decrypted_value: Unsigned256 = FHE.runtime.decrypt(&ciphertext, &FHE.private_key)?;

        assert_eq!(decrypted_value, value);

        // Check that the encryption generated the same value
        let mut hasher = Sha512::new();
        hasher.update(result);
        let hash = hasher.finalize();

        assert_eq!(
            hash,
            (if cfg!(macos) {
                [
                    149, 79, 157, 29, 182, 252, 150, 248, 218, 113, 137, 145, 138, 66, 255, 188,
                    248, 223, 225, 132, 74, 115, 104, 67, 201, 182, 229, 100, 124, 225, 238, 140,
                    249, 206, 49, 92, 246, 18, 251, 201, 53, 250, 110, 116, 200, 46, 123, 147, 53,
                    40, 40, 253, 104, 13, 255, 76, 105, 10, 11, 188, 233, 112, 198, 172,
                ]
            } else {
                [
                    239, 77, 150, 203, 195, 183, 219, 64, 59, 80, 6, 58, 156, 146, 154, 46, 223,
                    234, 71, 17, 170, 127, 242, 160, 67, 148, 228, 20, 114, 149, 139, 61, 99, 206,
                    149, 175, 129, 54, 96, 30, 128, 211, 137, 116, 99, 180, 40, 168, 179, 246, 205,
                    151, 55, 128, 198, 136, 36, 48, 149, 176, 46, 53, 117, 77,
                ]
            })
            .into()
        );
        Ok(())
    }

    #[test]
    fn fhe_reencrypt_test() -> Result<(), RuntimeError> {
        let public_key =
            bincode::deserialize(include_bytes!("../tests/data/public_key.bin")).unwrap();
        let private_key =
            bincode::deserialize(include_bytes!("../tests/data/private_key.bin")).unwrap();

        let value: Unsigned256 = Unsigned256::from(12);
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&value, &public_data);

        // Encrypt the ciphertext under the network public key
        let result = FHE.encrypt::<Unsigned256>(&input).unwrap();
        let ciphertext: Ciphertext = bincode::deserialize(&result)?;

        // Decrypt under the network key
        let decrypted_value: Unsigned256 = FHE.runtime.decrypt(&ciphertext, &FHE.private_key)?;

        assert_eq!(decrypted_value, value);

        // Key switch
        let input = pack_binary_operation(&public_key, &ciphertext, &public_data);

        let result = FHE.reencrypt::<Unsigned256>(&input).unwrap();
        let ciphertext: Ciphertext = bincode::deserialize(&result)?;

        // Note we are decrypting under the generated private key, not the network key.
        let decrypted_value: Unsigned256 = FHE.runtime.decrypt(&ciphertext, &private_key)?;

        assert_eq!(decrypted_value, value);

        // Check that the encryption generated the same value
        let mut hasher = Sha512::new();
        hasher.update(result);
        let hash = hasher.finalize();

        assert_eq!(
            hash,
            (if cfg!(macos) {
                [
                    239, 77, 150, 203, 195, 183, 219, 64, 59, 80, 6, 58, 156, 146, 154, 46, 223,
                    234, 71, 17, 170, 127, 242, 160, 67, 148, 228, 20, 114, 149, 139, 61, 99, 206,
                    149, 175, 129, 54, 96, 30, 128, 211, 137, 116, 99, 180, 40, 168, 179, 246, 205,
                    151, 55, 128, 198, 136, 36, 48, 149, 176, 46, 53, 117, 77,
                ]
            } else {
                [
                    115, 77, 169, 86, 212, 5, 41, 114, 179, 39, 132, 20, 160, 84, 58, 135, 49, 151,
                    63, 155, 40, 10, 116, 121, 155, 202, 227, 110, 13, 13, 27, 193, 163, 242, 116,
                    12, 114, 215, 215, 213, 177, 187, 74, 62, 4, 192, 225, 125, 45, 186, 96, 145,
                    188, 225, 153, 85, 96, 210, 176, 122, 3, 84, 77, 178,
                ]
            })
            .into()
        );

        Ok(())
    }

    /**********************************************************************
     * Helper functions
     *********************************************************************/

    fn precompile_fhe_op_works<A, B, C, F>(
        fhe_op: F,
        public_key: &PublicKey,
        private_key: &PrivateKey,
        a: A,
        b: B,
        expected: C,
    ) -> Result<(), RuntimeError>
    where
        A: FHESerialize,
        B: FHESerialize,
        C: TryFromPlaintext + TypeName + PartialEq,
        F: Fn(&[u8]) -> PrecompileResult,
    {
        let input = pack_binary_operation(public_key, &a, &b);

        // run precompile w/ gas
        let output = fhe_op(input.as_slice()).unwrap();

        // decode it
        let c_encrypted = deserialize(&output).unwrap();

        // decrypt it
        let c: C = FHE.runtime.decrypt(&c_encrypted, private_key)?;

        if !(c == expected) {
            panic!("Did not get expected result from precompile")
        }
        Ok(())
    }
}
