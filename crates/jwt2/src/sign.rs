#[cfg(feature = "hmac-sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
#[path = "sign/rustcrypto/hmac_sha2.rs"]
pub mod hmac_sha2;

#[cfg(feature = "hmac-sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
pub use hmac_sha2::{HS256, HS384, HS512};

#[cfg(feature = "rsa-pkcs1")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa-pkcs1")))]
#[path = "sign/rustcrypto/rsa_pkcs1.rs"]
pub mod rsa_pkcs1;

#[cfg(feature = "rsa-pkcs1")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa-pkcs1")))]
pub use rsa_pkcs1::{RS256Public, RS384Public, RS512Public, RS256, RS384, RS512};

// My goodness this is a long list of feature flags.
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
#[path = "sign/rustcrypto/ecdsa.rs"]
pub mod ecdsa;

use crate::header::Header;
use crate::util::algorithms_decl;

algorithms_decl!(
    /// Signing algorithms supported by `jwt2`.
    ///
    /// The list of algorithms supported is non-exhaustive, but should endeavour to be
    /// all defined `alg` header parameter values intended for JWS.
    /// Most of these algorithms are also feature-gated; see the individual variants for
    /// more documentation.
    ///
    /// See [section 3 of RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-3)
    /// for a reference regarding the algorithms that `jwt2` should support.
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    #[non_exhaustive]
    SigningAlgorithm;
    /// HMAC using SHA2-256. See [`hmac_sha2::HS256`] and the [`hmac_sha2`] module.
    ///
    /// Note that this algorithm *must* be supported for standards-compliance.
    /// `jwt2` gives the library consumer the choice through the use of the `hmac_sha2` feature,
    /// although for reasons of said compliance it is strongly recommended to keep that feature on.
    #[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
    HS256 {
        cfg: #[cfg(feature = "hmac-sha2")];
    },
    /// HMAC using SHA2-384. See [`hmac_sha2::HS384`] and the [`hmac_sha2`] module.
    #[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
    HS384 {
        cfg: #[cfg(feature = "hmac-sha2")];
    },
    /// HMAC using SHA2-512. See [`hmac_sha2::HS512`] and the [`hmac_sha2`] module.
    #[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
    HS512 {
        cfg: #[cfg(feature = "hmac-sha2")];
    },

    /// RSASSA-PKCS1-v1_5 using SHA2-256.
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa-pkcs1")))]
    RS256 {
        cfg: #[cfg(feature = "rsa-pkcs1")];
    },
    /// RSASSA-PKCS1-v1_5 using SHA2-384.
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa-pkcs1")))]
    RS384 {
        cfg: #[cfg(feature = "rsa-pkcs1")];
    },
    /// RSASSA-PKCS1-v1_5 using SHA2-512.
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa-pkcs1")))]
    RS512 {
        cfg: #[cfg(feature = "rsa-pkcs1")];
    },

    /// ECDSA using P-256 and SHA2-256.
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    ES256 {
        cfg: #[cfg(feature = "ecdsa")];
    },

    /// ECDSA using P-384 and SHA2-384.
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    ES384 {
        cfg: #[cfg(feature = "ecdsa")];
    },
    /// ECDSA using P-521 and SHA2-512.
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    ES512 {
        cfg: #[cfg(feature = "ecdsa")];
    }
);

/// Signifies that something can verify a signature (see [`JwsVerifier::verify_signature`]).
///
/// This trait can also easily be used in cases where multiple verifiers are required,
/// by using [`JwsVerifier::check_header`] on all available verifiers:
///
/// ```
/// use jwt2::repr::{decode_bytes_from_base64url, decode_value_from_base64url};
/// use jwt2::sign::hmac_sha2::HS256;
/// use jwt2::{Header, JwsVerifier};
///
/// // Step 1: Declare your verifiers in some easily-accessible place.
/// let hs256 = HS256::new(b"your-256-bit-secret").expect("Could not construct HS256");
/// let verifiers: &[&dyn JwsVerifier] = &[
///     &hs256
/// ];
///
/// let jwt_header_and_payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
///
/// let (header, payload) = jwt_header_and_payload.split_once('.').expect("could not split");
/// let signature = decode_bytes_from_base64url("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").expect("could not decode signature");///
/// // {"alg": "HS256", "typ": "JWT"} (whitespace may be incorrect)
/// let header: Header = decode_value_from_base64url(header).expect("could not decode header");
///
/// for verifier in verifiers {
///     if !verifier.check_header(&header) { continue; }
///     assert!(verifier.verify_signature(jwt_header_and_payload.as_bytes(), &signature));
/// }
/// ```
pub trait JwsVerifier {
    /// Check that the header is supported by this verifier.
    fn check_header(&self, header: &Header) -> bool;
    /// Verifies that `signature` is a valid signature for `data`.
    ///
    /// Note that this will not tell you if `signature` itself is invalid.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool;
}
/// Signifies that something can sign a string (see [`JwsSigner::sign`]).
///
/// ```
/// use jwt2::repr::{decode_bytes_from_base64url, encode_bytes_as_base64url};
/// use jwt2::sign::hmac_sha2::HS256;
/// use jwt2::sign::JwsSigner;
///
/// let hs256 = HS256::new(b"your-256-bit-secret").expect("Could not construct HS256");
/// let jwt_header_and_payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
///
/// let signature = encode_bytes_as_base64url(&hs256.sign(jwt_header_and_payload.as_bytes()));
/// let expected_signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
/// assert_eq!(signature, expected_signature);
/// ```
pub trait JwsSigner {
    // TODO: Maybe a function that modifies a header?
    //       That might be a bit *eh* since the algorithm could make potentially unwanted changes.

    /// Creates a signature for data.
    fn sign(&self, data: &[u8]) -> Vec<u8>;
    // TODO: Possibly introduce errors for `JwsSigner::sign` (the function before this comment)
    // TODO: A streaming version of `sign` so we don't have to allocate 5000 times (see `Jwt::create_jws`)
}
