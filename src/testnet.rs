/// Parameters related to the first testnet
pub mod one {
    use once_cell::sync::Lazy;
    use sunscreen::{Params, SchemeType};

    use crate::fhe::FheApp;

    /// Key generation and runtime parameters for the first testnet.
    static PARAMS: Lazy<Params> = Lazy::new(|| Params {
        lattice_dimension: 4096,
        coeff_modulus: vec![0xffffee001, 0xffffc4001, 0x1ffffe0001],
        plain_modulus: 4_096,
        scheme_type: SchemeType::Bfv,
        security_level: sunscreen::SecurityLevel::TC128,
    });

    /// The FHE precompile operations available in the first testnet.
    pub static FHE: Lazy<FheApp> = Lazy::new(|| FheApp::from_params(&PARAMS));
}
