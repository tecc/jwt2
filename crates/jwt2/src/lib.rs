#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod header;
pub mod repr;
pub mod sign;

pub(crate) mod util;

pub use header::Header;
pub use sign::{JwsSigner, JwsVerifier, SigningAlgorithm};

// TODO: Crate-level documentation.
