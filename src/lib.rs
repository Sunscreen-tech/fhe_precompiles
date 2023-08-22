use sunscreen::RuntimeError;

#[derive(Debug, Clone)]
pub enum FheError {
    UnexpectedEOF,
    PlatformArchitecture,
    InvalidEncoding,
    Overflow,
    FailedEncryption,
    FailedDecryption,
    SunscreenError(RuntimeError),
}

impl From<FheError> for i32 {
    /// Converts an FheError into an error code.
    fn from(error: FheError) -> Self {
        match error {
            FheError::UnexpectedEOF => 1,
            FheError::PlatformArchitecture => 2,
            FheError::InvalidEncoding => 3,
            FheError::Overflow => 4,
            FheError::FailedDecryption => 5,
            FheError::FailedEncryption => 6,
            FheError::SunscreenError(_) => 7,
        }
    }
}

impl FheError {
    /// Converts a C precompile error code into a str.
    ///
    /// * `error_code` - Error code returned from one of the C precompiles.
    pub fn error_code_to_str<'a>(error_code: i32) -> &'a str {
        match error_code {
            1 => "Unexpected end of file",
            2 => "Platform architecture invalid",
            3 => "Invalid encoding",
            4 => "Overflow in FHE program",
            5 => "Invalid decryption",
            6 => "Invalid encryption",
            7 => "Base sunscreen error",
            _ => "Unknown error",
        }
    }
}

#[macro_use]
extern crate alloc;
extern crate libc;

// A precompile operation result.
pub type PrecompileResult = Result<Vec<u8>, FheError>;

pub mod c_fhe;
mod fhe;
pub mod pack;
pub mod testnet;
pub use fhe::FheApp;
