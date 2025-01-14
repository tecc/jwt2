#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod header;
pub mod repr;
pub mod sign;

pub mod jwt;
pub mod util;

pub use header::{Header, Algorithm, ValidateHeaderParams, RecommendHeaderParams};
pub use sign::{JwsSigner, JwsVerifier, SigningAlgorithm};

pub use jwt::JwtData;
pub use util::WithKeyId;

// TODO: Crate-level documentation.
