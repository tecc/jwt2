#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod header;
pub mod repr;
pub mod sign;

pub mod util;
pub mod jwt;

pub use header::Header;
pub use sign::{JwsSigner, JwsVerifier, SigningAlgorithm};

pub use util::WithKeyId;
pub use jwt::JwtData;

// TODO: Crate-level documentation.
