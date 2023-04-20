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
    F: FnOnce(Ciphertext, Ciphertext, PublicKey) -> Result<Ciphertext, Box<RuntimeError>>,
{
    let (public_key, a, b) = unpack_binary_operation(input)?;
    let result = op(a, b, public_key).unwrap();

    Ok(serialize(&result).unwrap())
}

/// Expects input to be packed with the
/// [`pack_binary_plain_operation`][crate::pack::pack_binary_plain_operation()]
/// function.
fn fhe_binary_op_plain<F>(op: F, input: &[u8]) -> PrecompileResult
where
    F: FnOnce(Ciphertext, Signed, PublicKey) -> Result<Ciphertext, Box<RuntimeError>>,
{
    let (public_key, encrypted_argument, plaintext_argument) =
        unpack_binary_plain_operation(input)?;
    let result = op(encrypted_argument, plaintext_argument, public_key).unwrap();

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
    ) -> Result<Ciphertext, Box<RuntimeError>> {
        self.runtime
            .run(
                self.application.get_program(program).unwrap(),
                vec![a.into(), b.into()],
                &public_key,
            )
            .map_err(Box::new)
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
    pub fn fhe_enc_zero(&self, input: &[u8]) -> PrecompileResult {
        let pubk = unpack_nullary_operation(input)?;
        let zero = self
            .runtime
            .encrypt(Signed::from(0), &pubk)
            .map_err(|err| FheError::SunscreenError(Box::new(err)))?;

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
