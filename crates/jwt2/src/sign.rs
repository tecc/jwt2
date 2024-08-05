#[cfg(feature = "hmac-sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
pub mod hmac_sha2;

#[cfg(feature = "hmac-sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac-sha2")))]
pub use hmac_sha2::*;

use crate::header::SigningHeader;

macro_rules! algorithms {
    (
        $(#[$enum_attrs:meta])*
        $enum_ident:ident;
        $(
            $(#[$variant_attrs:meta])* $variant_ident:ident {
                $(cfg: $(#[$variant_attrs_cfg:meta])*;)?
            }
        ),*
    ) => {
        $(#[$enum_attrs])*
        pub enum $enum_ident {
            $(
            $(#[$variant_attrs])*
            $( $(#[$variant_attrs_cfg])* )?
            $variant_ident,
            )*
        }

        impl core::str::FromStr for $enum_ident {
            type Err = ();

            /// Tries to get an algorithm from a string.
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                // I prefer to be liberal in what is accepted, but RFC 7515 specifies that
                // algorithm names are indeed case-sensitive.
                $(
                    $( $(#[$variant_attrs_cfg])* )?
                    if value.eq(stringify!($variant_ident)) {
                        return Ok(Self::$variant_ident);
                    }
                )*
                Err(())
            }
        }

        impl serde::ser::Serialize for $enum_ident {
            fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
                where S: serde::ser::Serializer
            {
                match self {
                    $(
                    $( $(#[$variant_attrs_cfg])* )?
                    Self::$variant_ident => ser.serialize_str(stringify!($variant_ident)),
                    )*
                }
            }
        }
        impl<'de> serde::de::Deserialize<'de> for $enum_ident {
            fn deserialize<D>(de: D) -> Result<Self, D::Error>
                where D: serde::de::Deserializer<'de>
            {
                struct VisitorImpl;
                impl<'de> serde::de::Visitor<'de> for VisitorImpl {
                    type Value = $enum_ident;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        // TODO: Maybe improve this message?
                        f.write_str(stringify!($enum_ident))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: serde::de::Error {
                        $(
                        $( $(#[$variant_attrs_cfg])* )?
                        const $variant_ident: &'static str = stringify!($variant_ident);
                        $( $(#[$variant_attrs_cfg])* )?
                        if value.eq($variant_ident) {
                            return Ok($enum_ident::$variant_ident);
                        }
                        )*

                        const VARIANTS: &[&'static str] = &[
                            $(
                            $( $(#[$variant_attrs_cfg])* $variant_ident, )?
                            )*
                        ];

                        Err(E::unknown_variant(value, VARIANTS))
                    }
                }

                de.deserialize_str(VisitorImpl)
            }
        }
    };
}

algorithms!(
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
    }
);

/// Signifies that something can verify a signature (see [`SigningVerifier::verify_signature`]).
///
/// This trait can also easily be used in cases where multiple verifiers are required,
/// by using [`SigningVerifier::check_header`] on all available verifiers:
///
/// ```
/// use jwt2::repr::{decode_bytes_from_base64url, decode_value_from_base64url};
/// use jwt2::sign::hmac_sha2::HS256;
/// use jwt2::{SigningHeader, SigningVerifier};
///
/// // Step 1: Declare your verifiers in some easily-accessible place.
/// let hs256 = HS256::new(b"your-256-bit-secret").expect("Could not construct HS256");
/// let verifiers: &[&dyn SigningVerifier] = &[
///     &hs256
/// ];
///
/// let jwt_header_and_payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
///
/// let (header, payload) = jwt_header_and_payload.split_once('.').expect("could not split");
/// let signature = decode_bytes_from_base64url("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").expect("could not decode signature");///
/// // {"alg": "HS256", "typ": "JWT"} (whitespace may be incorrect)
/// let header: SigningHeader = decode_value_from_base64url(header).expect("could not decode header");
///
/// for verifier in verifiers {
///     if !verifier.check_header(&header) { continue }
///     assert!(verifier.verify_signature(jwt_header_and_payload.as_bytes(), &signature));
/// }
/// ```
pub trait SigningVerifier {
    /// Check that the header is valid and supported by this verifier.
    fn check_header(&self, header: &SigningHeader) -> bool;
    /// Verifies that `signature` is a valid signature for `data`.
    ///
    /// Note that this will not tell you if `signature` itself is invalid.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool;
}
