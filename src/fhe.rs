use std::ops::{Add, Mul, Sub};

use super::{FheError, PrecompileResult};
use crate::pack::{
    unpack_binary_operation, unpack_one_argument, unpack_two_arguments, FHESerialize,
};
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
    public_key_bytes: Vec<u8>,
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

        let public_key_bytes = include_bytes!("data/network.pub");
        let private_key_bytes = include_bytes!("data/network.pri");

        let public_key = bincode::deserialize(public_key_bytes).unwrap();
        let private_key = bincode::deserialize(private_key_bytes).unwrap();

        Self {
            application,
            runtime,
            public_key,
            private_key,
            public_key_bytes: public_key_bytes.to_vec(),
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
        hasher.update(plain.fhe_serialize());
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

        let public_data = [public_data, input.to_vec()].concat();
        self.reencrypt_any_key::<P>(&public_key, &ciphertext, &public_data)
    }

    /**
     * Decrypt a value encrypted under the network key.
     *
     * The input is expected to be packed with the
     * [`pack_one_argument`][crate::pack::pack_one_argument()] function.
     *
     * The argument is the ciphertext to decrypt.
     */
    pub fn decrypt<P>(&self, input: &[u8]) -> PrecompileResult
    where
        P: TryFromPlaintext + TryIntoPlaintext + TypeName + FHESerialize,
    {
        let ciphertext: Ciphertext = unpack_one_argument(input)?;
        let plain = self
            .runtime
            .decrypt::<P>(&ciphertext, &self.private_key)
            .map_err(|_| FheError::FailedDecryption)?;

        Ok(plain.fhe_serialize())
    }

    pub fn public_key_bytes(&self, _input: &[u8]) -> PrecompileResult {
        Ok(self.public_key_bytes.clone())
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

    /// See [`decrypt()`][Self::decrypt()] for details. This is a specialized
    /// variant for the Unsigned256 type.
    pub fn decrypt_u256(&self, input: &[u8]) -> PrecompileResult {
        self.decrypt::<Unsigned256>(input)
    }

    /// See [`decrypt()`][Self::decrypt()] for details. This is a specialized
    /// variant for the Unsigned64 type.
    pub fn decrypt_u64(&self, input: &[u8]) -> PrecompileResult {
        self.decrypt::<Unsigned64>(input)
    }

    /// See [`decrypt()`][Self::decrypt()] for details. This is a specialized
    /// variant for the Signed type.
    pub fn decrypt_i64(&self, input: &[u8]) -> PrecompileResult {
        self.decrypt::<Signed>(input)
    }

    /// See [`decrypt()`][Self::decrypt()] for details. This is a specialized
    /// variant for the Fractional::<64> type.
    pub fn decrypt_frac64(&self, input: &[u8]) -> PrecompileResult {
        self.decrypt::<Fractional<64>>(input)
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
            (if cfg!(target_os = "macos") {
                [
                    195, 187, 246, 29, 229, 222, 20, 246, 218, 16, 114, 27, 129, 99, 163, 244, 92,
                    32, 26, 147, 244, 249, 195, 53, 242, 255, 161, 187, 61, 209, 68, 3, 64, 1, 253,
                    115, 134, 15, 254, 196, 206, 149, 60, 174, 228, 18, 210, 5, 80, 214, 31, 131,
                    22, 81, 220, 190, 246, 192, 62, 177, 213, 218, 109, 67,
                ]
            } else {
                [
                    190, 214, 153, 167, 205, 130, 61, 102, 188, 80, 220, 159, 38, 110, 126, 216,
                    148, 46, 220, 80, 18, 189, 177, 187, 108, 99, 32, 72, 250, 225, 2, 166, 33,
                    155, 22, 86, 221, 82, 4, 174, 144, 196, 45, 28, 190, 100, 194, 192, 37, 81,
                    203, 227, 46, 179, 59, 153, 20, 118, 191, 69, 244, 113, 180, 123,
                ]
            })
            .into()
        );
        Ok(())
    }

    #[test]
    fn encrypt_same_seed_and_value_works() -> Result<(), RuntimeError> {
        // Essentially this checks that we have the transparent ciphertexts setting on.
        let input = pack_two_arguments(&Unsigned256::from(16), &vec![1, 2, 3, 4]);
        let a = FHE.encrypt::<Unsigned256>(&input).unwrap();
        let b = FHE.encrypt::<Unsigned256>(&input).unwrap();

        let a = Ciphertext::fhe_deserialize(&a).unwrap();
        let b = Ciphertext::fhe_deserialize(&b).unwrap();

        let sub_input = pack_binary_operation(&FHE.public_key, &a, &b);

        let result = FHE.sub_cipheru256_cipheru256(&sub_input).unwrap();
        let c = Unsigned256::fhe_deserialize(&FHE.decrypt_u256(&result).unwrap()).unwrap();
        assert_eq!(c, Unsigned256::from(0_u64));

        Ok(())
    }

    #[test]
    fn fhe_refresh_test() -> Result<(), RuntimeError> {
        let value = Unsigned256::from(12);

        let ciphertext =
            FHE.runtime
                .encrypt_deterministic(value, &FHE.public_key, &[0, 0, 0, 0, 0, 0, 0, 0])?;
        let public_data = vec![1, 2, 3];

        let input = pack_binary_operation(&FHE.public_key, &ciphertext, &public_data);

        let result = FHE.reencrypt::<Unsigned256>(&input).unwrap();
        let ciphertext: Ciphertext = bincode::deserialize(&result)?;

        let decrypted_value: Unsigned256 = FHE.runtime.decrypt(&ciphertext, &FHE.private_key)?;

        assert_eq!(decrypted_value, value);

        // Check that the encryption generated the same value
        let mut hasher = Sha512::new();
        hasher.update(result);
        let hash = hasher.finalize();

        assert_eq!(
            hash,
            (if cfg!(target_os = "macos") {
                [
                    34, 231, 60, 243, 80, 8, 85, 177, 250, 151, 122, 228, 89, 44, 120, 35, 197,
                    228, 96, 125, 248, 94, 59, 168, 59, 143, 59, 125, 217, 30, 174, 221, 14, 62,
                    175, 234, 230, 250, 10, 43, 186, 114, 182, 209, 134, 234, 131, 158, 102, 61,
                    227, 178, 241, 108, 237, 3, 118, 234, 126, 102, 253, 197, 27, 26,
                ]
            } else {
                [
                    131, 114, 41, 214, 205, 49, 231, 175, 22, 173, 98, 109, 197, 9, 217, 40, 55,
                    92, 148, 233, 141, 65, 126, 198, 160, 93, 170, 47, 86, 9, 22, 96, 127, 122, 9,
                    104, 175, 217, 65, 221, 247, 106, 80, 165, 58, 197, 218, 5, 138, 166, 250, 52,
                    159, 13, 226, 118, 189, 235, 203, 156, 112, 165, 84, 183,
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
            (if cfg!(target_os = "macos") {
                [
                    185, 128, 232, 30, 242, 123, 217, 237, 229, 166, 21, 236, 50, 206, 231, 153,
                    199, 137, 178, 37, 69, 70, 131, 182, 72, 222, 7, 52, 227, 37, 157, 127, 115,
                    58, 193, 253, 19, 208, 136, 54, 112, 170, 190, 29, 203, 101, 4, 67, 229, 78,
                    94, 252, 200, 100, 139, 78, 85, 213, 182, 224, 166, 115, 156, 106,
                ]
            } else {
                [
                    130, 189, 175, 155, 159, 130, 159, 220, 70, 102, 26, 228, 211, 59, 132, 240,
                    108, 2, 240, 176, 42, 236, 90, 30, 232, 41, 62, 25, 27, 239, 158, 39, 224, 40,
                    62, 212, 113, 151, 199, 5, 155, 15, 9, 35, 77, 46, 238, 46, 133, 185, 243, 242,
                    89, 101, 121, 56, 85, 103, 101, 0, 201, 200, 182, 64,
                ]
            })
            .into()
        );

        Ok(())
    }

    #[test]
    fn fhe_decrypt_test() -> Result<(), RuntimeError> {
        // Unsigned256
        let value = Unsigned256::from(12);
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&value, &public_data);

        let result = FHE.encrypt::<Unsigned256>(&input).unwrap();

        let decrypted_value: Unsigned256 =
            Unsigned256::fhe_deserialize(&FHE.decrypt::<Unsigned256>(&result).unwrap()).unwrap();

        assert_eq!(decrypted_value, value);

        // Unsigned64
        let value = Unsigned64::from(12);
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&value, &public_data);

        let result = FHE.encrypt::<Unsigned64>(&input).unwrap();

        let decrypted_value: Unsigned64 =
            Unsigned64::fhe_deserialize(&FHE.decrypt::<Unsigned64>(&result).unwrap()).unwrap();

        assert_eq!(decrypted_value, value);

        // Signed
        let value = Signed::from(12);
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&value, &public_data);

        let result = FHE.encrypt::<Signed>(&input).unwrap();

        let decrypted_value: Signed =
            Signed::fhe_deserialize(&FHE.decrypt::<Signed>(&result).unwrap()).unwrap();

        assert_eq!(decrypted_value, value);

        // Fractional<64>
        let value = Fractional::<64>::from(12.0);
        let public_data = vec![1, 2, 3];

        let input = pack_two_arguments(&value, &public_data);

        let result = FHE.encrypt::<Fractional<64>>(&input).unwrap();

        let decrypted_value: Fractional<64> =
            Fractional::<64>::fhe_deserialize(&FHE.decrypt::<Fractional<64>>(&result).unwrap())
                .unwrap();

        assert_eq!(decrypted_value, value);

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
