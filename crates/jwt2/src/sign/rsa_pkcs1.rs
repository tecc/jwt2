//! # RSA-based algorithms using PKCS1-v1_5 ([`RS256`], [`RS384`], [`RS512`])

use crate::{Header, JwsSigner, JwsVerifier, SigningAlgorithm};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Keypair, SignatureEncoding};
use sha2::{Sha256, Sha384, Sha512};

pub struct RSAVerifierConfig {}

macro_rules! impl_rs {
    (
        $(#[$main_attrs:meta])*
        main: $main_ident:ident,
        $(#[$public_attrs:meta])*
        public: $public_ident:ident,
        hash: $hash_ty:ty
    ) => {
        $(#[$main_attrs])*
        pub type $main_ident = GenericRsaImpl<SigningKey<$hash_ty>>;
        $(#[$public_attrs])*
        pub type $public_ident = GenericRsaImpl<VerifyingKey<$hash_ty>>;

        impl $main_ident {
            // TODO: Documentation
            /// Create an instance of this algorithm from a signing key.
            pub fn from(key: SigningKey<$hash_ty>) -> Self {
                Self {
                    key
                }
            }

            pub fn parse_pkcs1_pem(key: &str) -> rsa::pkcs1::Result<Self> {
                SigningKey::from_pkcs1_pem(key).map(Self::from)
            }
            pub fn parse_pkcs8_pem(key: &str) -> rsa::pkcs8::Result<Self> {
                SigningKey::from_pkcs8_pem(key).map(Self::from)
            }


            #[cfg(feature = "rand")]
            #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
            pub fn new_rand<R>(rng: &R, bits: usize) -> Self where R: rand_core::CryptoRngCore {
                Self {
                    key: SigningKey::random(rng, bits)
                }
            }

            /// Creates a corresponding verifying-only instance from `self`.
            pub fn public(&self) -> $public_ident {
                // This function is only duplicated for the convenience of the consumer.
                // In reality they have no implementation differences.
                self.verifying_key()
            }
        }
        impl $public_ident {
            /// Create an instance of this algorithm from
            pub fn from(key: VerifyingKey<$hash_ty>) -> Self {
                Self {
                    key
                }
            }
            pub fn parse_pkcs1_pem(key: &str) -> rsa::pkcs1::Result<Self> {
                VerifyingKey::from_pkcs1_pem(key).map(Self::from)
            }
            pub fn parse_pkcs8_pem(key: &str) -> rsa::pkcs8::Result<Self> {
                VerifyingKey::from_pkcs8_pem(key).map(Self::from)
            }
        }
    };
}

impl_rs!(
    /// RSASSA-PKCS1-v1_5 using SHA2-256.
    ///
    /// If you only need verifying capabilities, try [`RS256Public`].
    main: RS256,
    public: RS256Public,
    hash: Sha256
);
impl_rs!(
    /// RSASSA-PKCS1-v1_5 using SHA2-384.
    ///
    /// If you only need verifying capabilities, try [`RS384Public`].
    main: RS384,
    public: RS384Public,
    hash: Sha384
);
impl_rs!(
    /// RSASSA-PKCS1-v1_5 using SHA2-512.
    ///
    /// If you only need verifying capabilities, try [`RS512Public`].
    main: RS512,
    /// RSASSA-PKCS1-v1_5 using SHA2-512.
    ///
    /// If you only need verifying capabilities, try [`RS512Public`].
    public: RS512Public,
    hash: Sha512
);

/// RSA algorithm.
pub struct GenericRsaImpl<Key> {
    key: Key,
}

impl<Key> JwsVerifier for GenericRsaImpl<Key>
where
    Key: rsa::signature::Verifier<Signature>,
{
    fn check_header(&self, header: &Header) -> bool {
        header.algorithm == SigningAlgorithm::RS256
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = Signature::try_from(signature) else {
            return false;
        };
        self.key.verify(data, &signature).is_ok()
    }
}
impl<Key> JwsSigner for GenericRsaImpl<Key>
where
    Key: rsa::signature::Signer<Signature>,
{
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key.sign(data).to_bytes().into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr::decode_bytes_from_base64url;
    use rsa::pkcs1v15::{Signature, SigningKey};
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use rsa::signature::{Keypair, Signer, Verifier};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    #[test]
    fn jwtio() {
        let public_key = RsaPublicKey::from_public_key_pem(JWT_IO_PUBLIC_KEY)
            .expect("could not decode public key");
        let private_key = RsaPrivateKey::from_pkcs8_pem(JWT_IO_PRIVATE_KEY)
            .expect("could not decode private key");

        let data = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let bdata = data.as_bytes();

        let signature = "VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg";
        let signature = decode_bytes_from_base64url(signature).expect("could not decode signature");

        let signature = Signature::try_from(&signature).expect("could not create");

        let signing_key = SigningKey::<Sha256>::from(private_key);
        let verifying_key = signing_key.verifying_key();

        verifying_key
            .verify(data.as_bytes(), &signature)
            .expect("Verification failed");
        let new_signature = signing_key.sign(&bdata);
        assert_eq!(new_signature, signature);
    }

    // Taken fro [jwt.io](https://jwt.io).
    const JWT_IO_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----";
    const JWT_IO_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----";
}
