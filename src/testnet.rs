/// Parameters related to the first testnet
pub mod one {
    use once_cell::sync::Lazy;
    use sunscreen::{Params, PrivateKey, PublicKey, Runtime, SchemeType};

    use crate::fhe::FheApp;

    /// Key generation and runtime parameters for the first testnet.
    pub static PARAMS: Lazy<Params> = Lazy::new(|| Params {
        lattice_dimension: 4096,
        coeff_modulus: vec![0xffffee001, 0xffffc4001, 0x1ffffe0001],
        plain_modulus: 4_096,
        scheme_type: SchemeType::Bfv,
        security_level: sunscreen::SecurityLevel::TC128,
    });

    /// [`sunscreen::Runtime`] for the first testnet
    pub static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new(&PARAMS).unwrap());

    /// Generate public and private keys that work with the first testnet.
    // Note clippy allowance can be removed when upgrading sunscreen
    #[allow(clippy::result_large_err)]
    pub fn generate_keys() -> Result<(PublicKey, PrivateKey), sunscreen::Error> {
        let (public_key, private_key) = RUNTIME.generate_keys()?;
        Ok((
            PublicKey {
                // unnecessary galois portion (cuts keys from ~13MB to 1.3MB).
                galois_key: None,
                ..public_key
            },
            private_key,
        ))
    }

    /// The FHE precompile operations available in the first testnet.
    pub static FHE: Lazy<FheApp> = Lazy::new(|| FheApp::from_params(&PARAMS));
}
