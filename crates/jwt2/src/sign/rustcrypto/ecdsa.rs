//! # ECDSA-based algorithms ([`ES256`], [`ES384`])
//!
//! Currently, `ES512` is not implemented because neither RustCrypto nor ring support it.
//!
//! The prerelease version of the `p521` crate *is* compatible, but it would break
//! the dependency tree into smithereens, so for now you'll have to live without.

use crate::{Header, JwsSigner, JwsVerifier, SigningAlgorithm};
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
    /// ECDSA using NIST P-256 and SHA2-256.
    main: ES256,
    public: ES256Public,
    curve: p256::NistP256
);
impl_es!(
    /// ECDSA using NIST P-384 and SHA2-384.
    main: ES384,
    public: ES384Public,
    curve: p384::NistP384
);
// We do not have an ES512 implementation because the p521 crate does not play nice.
// I'm considering switching to `ring` for this reason.
// NOTE(tecc): `ring` doesn't have it either :)
//             I guess fate doesn't like Rust having an ES512 implementation here
//             ---
//             In the future, when we can upgrade RustCrypto dependencies to use the currently
//             prerelease versions, ES512 will be implemented and I will be happy.
//             Thank the stars that ES512 isn't a requirement.
/*
impl_es!(
    main: ES512,
    public: ES512Public,
    curve: p521::NistP521
);*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr;
    use ecdsa::elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use ecdsa::RecoveryId;
    use signature::{Signer, Verifier};

    macro_rules! test_ecdsa {
        (
            $private_ty:path = $private_key:expr,
            $public_ty:path = $public_key:expr =>
            data: $data:expr,
            sig: $signature:expr
        ) => {{
            {
                let data: &[u8] = { $data }.as_ref();
                let signature =
                    repr::decode_bytes_from_base64url($signature).expect("invalid signature");

                let private_instance = <$private_ty>::from($private_key);

                let created_signature = private_instance.sign(data);
                // eprintln!("{}", repr::encode_bytes_as_base64url(&created_signature));

                let public_instance = <$public_ty>::from($public_key);
                assert!(
                    public_instance.verify_signature(data, &signature),
                    "Precalculated signature does not match"
                );
                assert!(
                    public_instance.verify_signature(data, &created_signature),
                    "Precalculated signature does not match"
                );
            }
        }};
    }

    #[test]
    fn es256() {
        let jwtio_private_key: SigningKey<p256::NistP256> =
            SigningKey::from_pkcs8_pem(JWTIO_PRIVATE_KEY_ES256)
                .expect("Could not decode signing key");
        let jwtio_public_key: VerifyingKey<p256::NistP256> =
            VerifyingKey::from_public_key_pem(JWTIO_PUBLIC_KEY_ES256)
                .expect("Could not decode verifying key");

        test_ecdsa!(
            ES256 = jwtio_private_key.clone(), ES256Public = jwtio_public_key.clone() =>
            data: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
            sig:  "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
        );
    }

    #[test]
    fn es384() {
        let jwtio_private_key: SigningKey<p384::NistP384> =
            SigningKey::from_pkcs8_pem(JWTIO_PRIVATE_KEY_ES384)
                .expect("Could not decode signing key");
        let jwtio_public_key: VerifyingKey<p384::NistP384> =
            VerifyingKey::from_public_key_pem(JWTIO_PUBLIC_KEY_ES384)
                .expect("Could not decode verifying key");
        test_ecdsa!(
            ES384 = jwtio_private_key.clone(), ES384Public = jwtio_public_key.clone() =>
            data: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
            sig:  "VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj"
        );
    }

    const JWTIO_PRIVATE_KEY_ES256: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----";
    const JWTIO_PUBLIC_KEY_ES256: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----";

    const JWTIO_PRIVATE_KEY_ES384: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END PRIVATE KEY-----";
    const JWTIO_PUBLIC_KEY_ES384: &str = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----";
}
