use std::ops::{Add, Mul, Sub};

use super::{FheError, PrecompileResult};
use crate::pack::{unpack_binary_operation, unpack_nullary_operation, FHESerialize};
use bincode::serialize;
use sunscreen::{
    fhe_program,
    types::{
        bfv::{Fractional, Signed, Unsigned256, Unsigned64},
        Cipher,
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

pub struct FheApp {
    application: FheApplication,
    runtime: FheRuntime,
}

impl FheApp {
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

        Self {
            application,
            runtime,
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

    /// Expects input to be packed with the
    /// [`pack_nullary_operation`][crate::pack::pack_nullary_operation()]
    /// function.
    pub fn encrypt_zero(&self, input: &[u8]) -> PrecompileResult {
        let public_key = unpack_nullary_operation(input)?;
        let zero = self
            .runtime
            .encrypt(Unsigned256::from(0), &public_key)
            .map_err(FheError::SunscreenError)?;

        Ok(serialize(&zero).unwrap())
    }

    pub fn runtime(&self) -> &FheRuntime {
        &self.runtime
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
    use crate::pack::{pack_binary_operation, pack_nullary_operation};
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
     * encrypt zero tests
     *********************************************************************/

    #[test]
    fn precompile_encrypt_zero_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        // Encode public_key
        let public_key_enc = pack_nullary_operation(&public_key);

        // run precompile w/o gas
        let output = FHE.encrypt_zero(&public_key_enc).unwrap();
        // decode it
        let c_encrypted = deserialize(&output).unwrap();
        // decrypt it
        let c: Unsigned256 = FHE.runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(c, Unsigned256::from(0u64));
        Ok(())
    }

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
