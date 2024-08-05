#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod header;
pub mod repr;
pub mod sign;

pub(crate) mod util;

pub use header::Header;
pub use sign::{SigningAlgorithm, JwsVerifier, JwsSigner};

// TODO: Crate-level documentation.
