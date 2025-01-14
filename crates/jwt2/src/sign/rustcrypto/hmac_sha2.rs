//! # HMAC-based algorithms ([`HS256`], [`HS384`], [`HS512`])
//!
//! This module contains the implementations for all the HMAC/SHA2-based algorithms.
//!
//! Among them, the most well-known is probably [`HS256`].
//!
//! ## Security considerations
//! Per [section 3.2 of RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2),
//! the key length must be greater than the output size of the underlying hash.
//!
//! This requirement is not directly enforced by `jwt2`, but may be so in the future.
//!
//! It is upon the user to ensure that keys are secure enough.

use crate::header::{Header, Algorithm, ValidateHeaderParams, RecommendHeaderParams};
use crate::sign::{JwsSigner, JwsVerifier, SigningAlgorithm};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

pub type ConstructError = hmac::digest::InvalidLength;

/// HMAC using SHA2-256.
///
/// This algorithm is required to be implemented (i.e. available) according to
/// [section 3.1 of RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1),
/// but `jwt2` does not enforce this requirement.
/// In the terms of RFCs this crate treats `HS256`'s "Required" as a "Recommended".
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
    ($struct_ident:ty: alg = $algorithm:expr, hash = $hash_ty:ty) => {
        impl $struct_ident {
            /// Generates a suitable key for this algorithm.
            #[cfg(feature = "rand")]
            #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
            pub fn generate_key<R>(rng: &mut R) -> Vec<u8>
            where
                R: rand_core::CryptoRngCore,
            {
                use hmac::digest::crypto_common::KeySizeUser;
                let mut vec = vec![0u8; Hmac::<$hash_ty>::key_size()];
                rng.fill_bytes(&mut vec);
                vec
            }
        }

        impl RecommendHeaderParams for $struct_ident {
            fn alg(&self) -> Algorithm {
                Algorithm::Signing($algorithm)
            }
        }
        impl JwsSigner for $struct_ident {
            fn sign(&self, data: &[u8]) -> Vec<u8> {
                let mut inner = self.inner.clone();
                inner.update(data);
                let result = inner.finalize();
                crate::util::to_byte_vec(result.into_bytes().as_ref())
            }
        }

        impl ValidateHeaderParams for $struct_ident {
            fn validate_header(&self, header: &Header) -> bool {
                header.algorithm == $algorithm
            }
        }
        impl JwsVerifier for $struct_ident {
            fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
                let mut inner = self.inner.clone();
                inner.update(data);
                return inner.verify_slice(signature).is_ok();
            }
        }
    };
}

impl_hs!(
    HS256:
    alg = SigningAlgorithm::HS256,
    hash = Sha256
);
impl_hs!(
    HS384:
    alg = SigningAlgorithm::HS384,
    hash = Sha384
);
impl_hs!(
    HS512:
    alg = SigningAlgorithm::HS512,
    hash = Sha512
);

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
