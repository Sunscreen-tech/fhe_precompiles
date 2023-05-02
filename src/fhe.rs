use super::{FheError, PrecompileResult};
use crate::pack::{
    unpack_binary_operation, unpack_binary_plain_operation, unpack_nullary_operation,
};
use bincode::serialize;
use sunscreen::{
    fhe_program,
    types::{bfv::Unsigned256, Cipher},
    Ciphertext, Compiler, FheApplication, FheProgramInput, FheRuntime, Params, PrivateKey,
    PublicKey, Runtime, RuntimeError,
};

/// Expects input to be packed with the
/// [`pack_binary_operation`][crate::pack::pack_binary_operation()] function.
fn fhe_binary_op<F>(op: F, input: &[u8]) -> PrecompileResult
where
    F: FnOnce(Ciphertext, Ciphertext, PublicKey) -> Result<Ciphertext, RuntimeError>,
{
    let (public_key, a, b) = unpack_binary_operation(input)?;
    let result = op(a, b, public_key).map_err(FheError::SunscreenError)?;
    Ok(serialize(&result).unwrap())
}

/// Expects input to be packed with the
/// [`pack_binary_plain_operation`][crate::pack::pack_binary_plain_operation()]
/// function.
fn fhe_binary_op_plain<F>(op: F, input: &[u8]) -> PrecompileResult
where
    F: FnOnce(Ciphertext, Unsigned256, PublicKey) -> Result<Ciphertext, RuntimeError>,
{
    let (public_key, encrypted_argument, plaintext_argument) =
        unpack_binary_plain_operation(input)?;
    let result =
        op(encrypted_argument, plaintext_argument, public_key).map_err(FheError::SunscreenError)?;
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
            .fhe_program(add)
            .fhe_program(add_plain)
            .fhe_program(subtract)
            .fhe_program(subtract_plain)
            .fhe_program(multiply)
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

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn add(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(|a, b, key| self.run(add, a, b, key), input)
    }

    /// Expects input to be packed with the
    /// [`pack_binary_plain_operation`][crate::pack::pack_binary_plain_operation()]
    /// function.
    pub fn add_plain(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op_plain(|a, b, key| self.run(add_plain, a, b, key), input)
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn subtract(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(|a, b, key| self.run(subtract, a, b, key), input)
    }

    /// Expects input to be packed with the
    /// [`pack_binary_plain_operation`][crate::pack::pack_binary_plain_operation()]
    /// function.  The response is the bincode-encoded encrypted difference
    /// `ciphertext - plaintext`.
    pub fn subtract_plain(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op_plain(|a, b, key| self.run(subtract_plain, a, b, key), input)
    }

    /// Expects input to be packed with the
    /// [`pack_binary_operation`][crate::pack::pack_binary_operation()]
    /// function.
    pub fn multiply(&self, input: &[u8]) -> PrecompileResult {
        fhe_binary_op(|a, b, key| self.run(multiply, a, b, key), input)
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

/// Addition
#[fhe_program(scheme = "bfv")]
fn add(a: Cipher<Unsigned256>, b: Cipher<Unsigned256>) -> Cipher<Unsigned256> {
    a + b
}

/// Addition with plaintext
#[fhe_program(scheme = "bfv")]
fn add_plain(a: Cipher<Unsigned256>, b: Unsigned256) -> Cipher<Unsigned256> {
    a + b
}

/// Subtraction
#[fhe_program(scheme = "bfv")]
fn subtract(a: Cipher<Unsigned256>, b: Cipher<Unsigned256>) -> Cipher<Unsigned256> {
    a - b
}

/// Subtraction with plaintext
#[fhe_program(scheme = "bfv")]
fn subtract_plain(a: Cipher<Unsigned256>, b: Unsigned256) -> Cipher<Unsigned256> {
    a - b
}

/// Multiplication
#[fhe_program(scheme = "bfv")]
fn multiply(a: Cipher<Unsigned256>, b: Cipher<Unsigned256>) -> Cipher<Unsigned256> {
    a * b
}

#[cfg(test)]
mod tests {
    use bincode::deserialize;
    use crypto_bigint::U256;
    use sunscreen::{types::bfv::Unsigned256, RuntimeError};

    use super::*;
    use crate::pack::{pack_binary_operation, pack_binary_plain_operation, pack_nullary_operation};
    use crate::testnet::one::FHE;

    #[test]
    fn fhe_add_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned256::from(4), &public_key)?;

        let result = FHE.run(add, a, b, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(20_u64));
        Ok(())
    }

    #[test]
    fn fhe_multiply_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        let a = FHE.runtime.encrypt(Unsigned256::from(16), &public_key)?;
        let b = FHE.runtime.encrypt(Unsigned256::from(4), &public_key)?;

        let result = FHE.run(multiply, a, b, public_key)?;
        let c: Unsigned256 = FHE.runtime.decrypt(&result, &private_key)?;
        assert_eq!(c, Unsigned256::from(64_u64));
        Ok(())
    }

    #[test]
    fn precompile_add_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.add(input);
        precompile_fhe_op_works(precompile, 4u8.into(), 5u8.into(), (4u8 + 5).into())
    }

    #[test]
    fn precompile_subtract_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.subtract(input);
        precompile_fhe_op_works(
            precompile,
            11341_u32.into(),
            134_u32.into(),
            (11341_u32 - 134).into(),
        )
    }

    #[test]
    fn precompile_multiply_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.multiply(input);
        precompile_fhe_op_works(precompile, 4u8.into(), 5u8.into(), (4u8 * 5).into())
    }

    #[test]
    fn precompile_add_plain_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.add_plain(input);
        precompile_fhe_plain_op_works(
            precompile,
            82_u32.into(),
            145_u32.into(),
            (82_u32 + 145).into(),
        )
    }

    #[test]
    fn precompile_subtract_plain_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.subtract_plain(input);
        precompile_fhe_plain_op_works(
            precompile,
            315_u32.into(),
            64_u32.into(),
            (315_u32 - 64).into(),
        )
    }

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

    fn precompile_fhe_op_works<F>(
        fhe_op: F,
        a: U256,
        b: U256,
        expected: U256,
    ) -> Result<(), RuntimeError>
    where
        F: Fn(&[u8]) -> PrecompileResult,
    {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        // Encrypt values
        let a_encrypted = FHE.runtime.encrypt(Unsigned256::from(a), &public_key)?;
        let b_encrypted = FHE.runtime.encrypt(Unsigned256::from(b), &public_key)?;

        let input = pack_binary_operation(&public_key, &a_encrypted, &b_encrypted);

        // run precompile w/ gas
        let output = fhe_op(input.as_slice()).unwrap();

        // decode it
        let c_encrypted = deserialize(&output).unwrap();

        // decrypt it
        let c: Unsigned256 = FHE.runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(expected, U256::from(c));
        Ok(())
    }

    fn precompile_fhe_plain_op_works<F>(
        fhe_op: F,
        a: U256,
        b: U256,
        expected: U256,
    ) -> Result<(), RuntimeError>
    where
        F: Fn(&[u8]) -> PrecompileResult,
    {
        let (public_key, private_key) = FHE.generate_keys().unwrap();

        // Encrypt a
        let a_encrypted = FHE.runtime.encrypt(Unsigned256::from(a), &public_key)?;

        let input = pack_binary_plain_operation(&public_key, &a_encrypted, &Unsigned256::from(b));

        // run precompile
        let output = fhe_op(&input).unwrap();

        // decode it
        let c_encrypted = deserialize(&output).unwrap();

        // decrypt it
        let c: Unsigned256 = FHE.runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(expected, U256::from(c));
        Ok(())
    }
}
