//! # ECDSA-based algorithms ([`ES256`], [`ES384`], [`ES512`])
//!
//!

use crate::{Header, JwsSigner, JwsVerifier, SigningAlgorithm};
use base64ct::LineEnding;
use ecdsa::elliptic_curve::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use signature::{Signer, Verifier};

macro_rules! impl_es {
    (
        $( #[$main_attrs:meta] )*
        main: $main_ident:ident,
        $( #[$public_attrs:meta] )*
        public: $public_ident:ident,
        curve: $curve_ty:ty
    ) => {
        $( #[$main_attrs] )*
        pub struct $main_ident {
            key: SigningKey<$curve_ty>
        }

        $( #[$public_attrs] )*
        pub struct $public_ident {
            key: VerifyingKey<$curve_ty>
        }

        impl $main_ident {
            pub fn from(key: SigningKey<$curve_ty>) -> Self {
                Self {
                    key
                }
            }
            pub fn parse_pem(key: &str) -> ecdsa::elliptic_curve::pkcs8::Result<Self> {
                SigningKey::from_pkcs8_pem(key).map(Self::from)
            }

            /// Generates a new key.
            #[cfg(feature = "rand")]
            #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
            pub fn new_rand<R>(rng: &mut R) -> Self
            where
                R: rand_core::CryptoRngCore
            {
                Self {
                    key: SigningKey::random(rng)
                }
            }

            /// Creates a corresponding verifying-only instance from `self`.
            pub fn public(&self) -> $public_ident {
                // This function is only duplicated for the convenience of the consumer.
                // In reality they have no implementation differences.
                $public_ident::from(self.key.verifying_key().clone())
            }
        }
        impl $public_ident {
            pub fn from(key: VerifyingKey<$curve_ty>) -> Self {
                Self {
                    key
                }
            }
            pub fn parse_pem(key: &str) -> ecdsa::elliptic_curve::pkcs8::spki::Result<Self> {
                VerifyingKey::from_public_key_pem(key).map(Self::from)
            }
        }

        impl JwsSigner for $main_ident {
            fn sign(&self, data: &[u8]) -> Vec<u8> {
                let signature: Signature<$curve_ty> = Signer::sign(&self.key, data);
                signature.to_vec()
            }
        }
        impl JwsVerifier for $main_ident {
            fn check_header(&self, header: &Header) -> bool {
                header.algorithm == SigningAlgorithm::$main_ident
            }
            fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
                let Ok(signature) = Signature::<$curve_ty>::from_slice(signature) else { return false };
                Verifier::verify(self.key.verifying_key(), data, &signature).is_ok()
            }
        }
        impl JwsVerifier for $public_ident {
            fn check_header(&self, header: &Header) -> bool {
                header.algorithm == SigningAlgorithm::$main_ident
            }
            fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
                let Ok(signature) = Signature::<$curve_ty>::from_slice(signature) else { return false };
                Verifier::verify(&self.key, data, &signature).is_ok()
            }
        }
    };
}

// TODO: Documentation

impl_es!(
    main: ES256,
    public: ES256Public,
    curve: p256::NistP256
);
impl_es!(
    main: ES384,
    public: ES384Public,
    curve: p384::NistP384
);
impl_es!(
    main: ES512,
    public: ES512Public,
    curve: p521::NistP521
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr;
    use ecdsa::elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use ecdsa::RecoveryId;
    use signature::{Signer, Verifier};

    #[test]
    fn jwtio() {
        let signature = "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        let signature =
            repr::decode_bytes_from_base64url(signature).expect("Could not decode signature");
        let signature: Signature<p256::NistP256> =
            ecdsa::Signature::try_from(signature.as_slice()).expect("Could not parse signature");

        let data = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let bdata = data.as_bytes();

        // p256::elliptic_curve::PublicKey::from_public_key_pem();
        let signing_key: SigningKey<p256::NistP256> =
            SigningKey::from_pkcs8_pem(JWTIO_PRIVATE_KEY_ES256)
                .expect("Could not decode signing key");

        let verifying_key: VerifyingKey<p256::NistP256> =
            VerifyingKey::from_public_key_pem(JWTIO_PUBLIC_KEY_ES256)
                .expect("Could not decode verifying key");

        verifying_key
            .verify(bdata, &signature)
            .expect("Signature is incorrect");

        let new_signature: Signature<p256::NistP256> = Signer::sign(&signing_key, bdata);
        let new_signature2: Signature<p256::NistP256> = Signer::sign(&signing_key, bdata);

        eprintln!(
            "{}\n{}\n{}",
            repr::encode_bytes_as_base64url(&signature.to_bytes()),
            repr::encode_bytes_as_base64url(&new_signature.to_bytes()),
            repr::encode_bytes_as_base64url(&new_signature2.to_bytes())
        );

        verifying_key
            .verify(bdata, &new_signature)
            .expect("Signature is incorrect");
    }

    const JWTIO_PUBLIC_KEY_ES256: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----";
    const JWTIO_PRIVATE_KEY_ES256: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----";
}
