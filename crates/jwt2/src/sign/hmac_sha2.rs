//! # SHA2-based algorithms ([`HS256`], [`HS384`], [`HS512`]).
//!
//! This module contains the implementations for all the HMAC/SHA2-based algorithms.
//!
//! These
//!
//! ## Security considerations
//! Per [section 3.2 of RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2),
//! the key length must be greater than the output size of the underlying hash.
//!
//! This requirement is not directly enforced by `jwt2`, but may be so in the future.
//!
//! It is upon the user to ensure that keys are secure enough.

use crate::header::SigningHeader;
use crate::sign::{SigningAlgorithm, SigningVerifier};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

pub type ConstructError = hmac::digest::InvalidLength;

/// HMAC using SHA2-256.
pub struct HS256 {
    inner: Hmac<Sha256>,
}
impl HS256 {
    /// Creates a HS256 instance.
    ///
    /// See the [security considerations](self#security-considerations) of this module.
    pub fn new(key: &[u8]) -> Result<Self, ConstructError> {
        Ok(Self {
            inner: Hmac::new_from_slice(key)?,
        })
    }
}

/// HMAC using SHA2-384.
pub struct HS384 {
    inner: Hmac<Sha384>,
}
impl HS384 {
    /// Creates a HS384 instance.
    ///
    /// See the [security considerations](self#security-considerations) of this module.
    pub fn new(key: &[u8]) -> Result<Self, ConstructError> {
        Ok(Self {
            inner: Hmac::new_from_slice(key)?,
        })
    }
}

/// HMAC using SHA2-512.
pub struct HS512 {
    inner: Hmac<Sha512>,
}
impl HS512 {
    /// Creates a HS512 instance.
    ///
    /// See the [security considerations](self#security-considerations) of this module.
    pub fn new(key: &[u8]) -> Result<Self, ConstructError> {
        Ok(Self {
            inner: Hmac::new_from_slice(key)?,
        })
    }
}

macro_rules! impl_hs {
    ($struct_ident:ty: alg = $algorithm:expr) => {
        impl SigningVerifier for $struct_ident {
            fn check_header(&self, header: &SigningHeader) -> bool {
                return header.algorithm == $algorithm;
            }

            fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
                let mut inner = self.inner.clone();
                inner.update(data);
                return inner.verify_slice(signature).is_ok();
            }
        }
    };
}

impl_hs!(HS256: alg = SigningAlgorithm::HS256);
impl_hs!(HS384: alg = SigningAlgorithm::HS384);
impl_hs!(HS512: alg = SigningAlgorithm::HS512);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr;

    macro_rules! do_test {
        ($target_ty:ty => data: $data:expr, sig: $signature:expr, key: $key:expr) => {{
            let data: &[u8] = { $data }.as_ref();
            let signature =
                repr::decode_bytes_from_base64url($signature).expect("invalid signature");
            let key: &[u8] = { $key }.as_ref();

            let instance = <$target_ty>::new(key).expect("could not create verifier");

            assert!(
                instance.verify_signature(data, &signature),
                "{}: the signature couldn't be verified",
                stringify!($ty)
            )
        }};
    }

    #[test]
    fn hs256() {
        do_test!(
            HS256 =>
            data: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            sig: "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            key: b"your-256-bit-secret"
        );
        do_test!(
            HS256 =>
            data: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0",
            sig: "eH9qoMvdv12LsZ3Og_K20no8uiBQFuJg6k6A7O8l06U",
            key: "your-256-bit-secret"
        );
    }
    #[test]
    fn hs384() {
        do_test!(
            HS384 =>
            data: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
            sig:  "bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh",
            key:  "your-384-bit-secret"
        );
        do_test!(
            HS384 =>
            data: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0",
            sig:  "a-ezeeJcey3XsFBva3BnF_cZbJ9p461eGI9XWkw-Bs4w_c3E3qM5GlxEpUmNgxYJ",
            key:  "your-384-bit-secret"
        );
    }
    #[test]
    fn hs512() {
        do_test!(
            HS512 =>
            data: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
            sig:  "VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg",
            key:  "your-512-bit-secret"
        );
        do_test!(
            HS512 =>
            data: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0",
            sig:  "GsvmpqH8-zqpoMshseGSahCipAkxF8lDDK7G21jUXpFgjMZiFjn-4sgO62xGdI8T_gfay2Q3uZJUeJT0TKVC-g",
            key:  "your-512-bit-secret"
        );
    }
}
