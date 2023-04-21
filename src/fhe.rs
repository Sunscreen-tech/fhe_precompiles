use super::{FheError, PrecompileResult};
use crate::pack::{
    unpack_binary_operation, unpack_binary_plain_operation, unpack_nullary_operation,
};
use bincode::serialize;
use sunscreen::{
    fhe_program,
    types::{bfv::Signed, Cipher},
    Application, Ciphertext, Compiler, FheProgramInput, Params, PublicKey, Runtime, RuntimeError,
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
    F: FnOnce(Ciphertext, Signed, PublicKey) -> Result<Ciphertext, RuntimeError>,
{
    let (public_key, encrypted_argument, plaintext_argument) =
        unpack_binary_plain_operation(input)?;
    let result =
        op(encrypted_argument, plaintext_argument, public_key).map_err(FheError::SunscreenError)?;
    Ok(serialize(&result).unwrap())
}

pub struct FheApp {
    application: Application,
    runtime: Runtime,
}

impl FheApp {
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
        let runtime = Runtime::new(&params).unwrap();

        Self {
            application,
            runtime,
        }
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
                self.application.get_program(program).unwrap(),
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
    /// `encrypted - (signed as i64)`.
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
            .encrypt(Signed::from(0), &public_key)
            .map_err(FheError::SunscreenError)?;

        Ok(serialize(&zero).unwrap())
    }
}

/// Addition
#[fhe_program(scheme = "bfv")]
fn add(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    a + b
}

/// Addition with plaintext
#[fhe_program(scheme = "bfv")]
fn add_plain(a: Cipher<Signed>, b: Signed) -> Cipher<Signed> {
    a + b
}

/// Subtraction
#[fhe_program(scheme = "bfv")]
fn subtract(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    a - b
}

/// Subtraction with plaintext
#[fhe_program(scheme = "bfv")]
fn subtract_plain(a: Cipher<Signed>, b: Signed) -> Cipher<Signed> {
    a - b
}

/// Multiplication
#[fhe_program(scheme = "bfv")]
fn multiply(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    a * b
}

#[cfg(test)]
mod tests {
    use bincode::deserialize;
    use sunscreen::{types::bfv::Signed, RuntimeError};

    use super::*;
    use crate::pack::{pack_binary_operation, pack_binary_plain_operation, pack_nullary_operation};
    use crate::testnet::one::{generate_keys, FHE, RUNTIME};

    #[test]
    fn fhe_add_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = generate_keys().unwrap();

        let a = RUNTIME.encrypt(Signed::from(16), &public_key)?;
        let b = RUNTIME.encrypt(Signed::from(4), &public_key)?;

        let result = FHE.run(add, a, b, public_key)?;
        let c: Signed = RUNTIME.decrypt(&result, &private_key)?;
        assert_eq!(<Signed as Into<i64>>::into(c), 20_i64);
        Ok(())
    }

    #[test]
    fn fhe_multiply_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = generate_keys().unwrap();

        let a = RUNTIME.encrypt(Signed::from(16), &public_key)?;
        let b = RUNTIME.encrypt(Signed::from(4), &public_key)?;

        let result = FHE.run(multiply, a, b, public_key)?;
        let c: Signed = RUNTIME.decrypt(&result, &private_key)?;
        assert_eq!(<Signed as Into<i64>>::into(c), 64_i64);
        Ok(())
    }

    #[test]
    fn precompile_add_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.add(input);
        precompile_fhe_op_works(precompile, 4, 5, 4 + 5)
    }

    #[test]
    fn precompile_subtract_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.subtract(input);
        precompile_fhe_op_works(precompile, 11341, 134, 11341 - 134)
    }

    #[test]
    fn precompile_multiply_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.multiply(input);
        precompile_fhe_op_works(precompile, 4, 5, 4 * 5)
    }

    #[test]
    fn precompile_add_plain_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.add_plain(input);
        precompile_fhe_plain_op_works(precompile, 82, 145, 82 + 145)
    }

    #[test]
    fn precompile_subtract_plain_works() -> Result<(), RuntimeError> {
        let precompile = |input: &[u8]| FHE.subtract_plain(input);
        precompile_fhe_plain_op_works(precompile, 315, 64, 315 - 64)
    }

    #[test]
    fn precompile_encrypt_zero_works() -> Result<(), RuntimeError> {
        let (public_key, private_key) = generate_keys().unwrap();

        // Encode public_key
        let public_key_enc = pack_nullary_operation(&public_key);

        // run precompile w/o gas
        let output = FHE.encrypt_zero(&public_key_enc).unwrap();
        // decode it
        let c_encrypted = deserialize(&output).unwrap();
        // decrypt it
        let c: Signed = RUNTIME.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(0, <Signed as Into<i64>>::into(c));
        Ok(())
    }

    fn precompile_fhe_op_works<F>(
        fhe_op: F,
        a: i64,
        b: i64,
        expected: i64,
    ) -> Result<(), RuntimeError>
    where
        F: Fn(&[u8]) -> PrecompileResult,
    {
        let (public_key, private_key) = generate_keys().unwrap();

        // Encrypt values
        let a_encrypted = RUNTIME.encrypt(Signed::from(a), &public_key)?;
        let b_encrypted = RUNTIME.encrypt(Signed::from(b), &public_key)?;

        let input = pack_binary_operation(&public_key, &a_encrypted, &b_encrypted);

        // run precompile w/ gas
        let output = fhe_op(input.as_slice()).unwrap();

        // decode it
        let c_encrypted = deserialize(&output).unwrap();

        // decrypt it
        let c: Signed = RUNTIME.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(expected, <Signed as Into<i64>>::into(c));
        Ok(())
    }

    fn precompile_fhe_plain_op_works<F>(
        fhe_op: F,
        a: i64,
        b: i64,
        expected: i64,
    ) -> Result<(), RuntimeError>
    where
        F: Fn(&[u8]) -> PrecompileResult,
    {
        let (public_key, private_key) = generate_keys().unwrap();

        // Encrypt a
        let a_encrypted = RUNTIME.encrypt(Signed::from(a), &public_key)?;

        let input = pack_binary_plain_operation(&public_key, &a_encrypted, &Signed::from(b));

        // run precompile
        let output = fhe_op(&input).unwrap();

        // decode it
        let c_encrypted = deserialize(&output).unwrap();

        // decrypt it
        let c: Signed = RUNTIME.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(expected, <Signed as Into<i64>>::into(c));
        Ok(())
    }
}
