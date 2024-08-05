#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod header;
pub mod repr;
pub mod sign;

pub use header::SigningHeader;
pub use sign::{SigningAlgorithm, SigningVerifier};

// TODO: Crate-level documentation.
