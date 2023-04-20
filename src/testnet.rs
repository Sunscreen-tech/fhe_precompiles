use once_cell::sync::Lazy;
use sunscreen::{Params, PrivateKey, PublicKey, Runtime, SchemeType};

use crate::fhe::FheApp;

pub static TESTNET1_PARAMS: Lazy<Params> = Lazy::new(|| Params {
    lattice_dimension: 4096,
    coeff_modulus: vec![0xffffee001, 0xffffc4001, 0x1ffffe0001],
    plain_modulus: 4_096,
    scheme_type: SchemeType::Bfv,
    security_level: sunscreen::SecurityLevel::TC128,
});

pub static TESTNET1_RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new(&TESTNET1_PARAMS).unwrap());

/// Generate public and private keys that work with the testnet.
/// unnecessary galois portion (cuts keys from ~13MB to 1.3MB).
//
// Note clippy allowance can be removed when upgrading sunscreen
#[allow(clippy::result_large_err)]
pub fn generate_testnet1_keys() -> Result<(PublicKey, PrivateKey), sunscreen::Error> {
    let (public_key, private_key) = TESTNET1_RUNTIME.generate_keys()?;
    Ok((
        PublicKey {
            galois_key: None,
            ..public_key
        },
        private_key,
    ))
}

pub static TESTNET1_FHE: Lazy<FheApp> =
    Lazy::new(|| FheApp::from_params(Lazy::force(&TESTNET1_PARAMS)));
