use sunscreen::RuntimeError;

#[derive(Debug)]
pub enum FheError {
    UnexpectedEOF,
    PlatformArchitecture,
    InvalidEncoding,
    Overflow,
    SunscreenError(Box<RuntimeError>),
}

#[macro_use]
extern crate alloc;
extern crate libc;

// A precompile operation result.
pub type PrecompileResult = Result<Vec<u8>, FheError>;

mod c_fhe;
mod fhe;
pub mod pack;
pub mod testnet;
pub use fhe::FheApp;
