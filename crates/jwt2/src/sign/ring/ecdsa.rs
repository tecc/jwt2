use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};


// NOTE: this file does not work, other people feel free to implement it

pub struct ES256 {
    key: ring::signature::EcdsaKeyPair
}

impl ES256 {
    fn new() {

    }

    pub fn generate(rand: &dyn SecureRandom) -> Self {
        let generated = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rand)?;
        Self {
            key: EcdsaKeyPair::from_pkcs8(&generated, rand)
        }
    }
}