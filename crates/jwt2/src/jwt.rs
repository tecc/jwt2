use crate::{repr, Algorithm, Header, JwsSigner, JwsVerifier};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct JwtData<Claims> {
    pub header: Header,
    pub claims: Claims,
}

impl<Claims> JwtData<Claims> {
    pub fn new(algorithm: Algorithm, claims: Claims) -> Self {
        Self {
            header: Header::new(algorithm),
            claims,
        }
    }

    /// Gets the JWS signing input (i.e. `<base64url(header)>.<base64url(payload)>`.
    pub fn to_signing_input(&self) -> Result<String, serde_json::Error>
    where
        Claims: Serialize,
    {
        // NOTE(tecc): This code so fundamentally bothers my allocation-hating mind,
        //             but I'll leave it like this since It Can Be Improved Later.
        let header = repr::encode_value_as_base64url(&self.header)?;
        let payload = repr::encode_value_as_base64url(&self.claims)?;
        Ok(format!("{}.{}", header, payload))
    }

    pub fn sign_with<Signer>(&self, signer: &Signer) -> Result<String, JwtCreateError>
    where
        Signer: JwsSigner,
        Claims: Serialize,
    {
        let header_and_payload = self.to_signing_input()?;

        let signature = signer.sign(header_and_payload.as_bytes());
        let signature = repr::encode_bytes_as_base64url(&signature);

        // NOTE(tecc): My goodness do I hate this code vehemently.

        Ok(format!("{}.{}", header_and_payload, signature))
    }
}

pub struct RawJwt<'a> {
    pub header_and_payload: &'a str,
    pub header: Header,
    pub payload: &'a str,
    // The decoded signature
    pub signature: Vec<u8>,
}
impl<'a> RawJwt<'a> {
    pub fn decode(source: &'a str) -> Result<Self, JwtDecodeError> {
        let (header, payload, header_and_payload, signature) =
            get_jwt_parts(source).ok_or(JwtDecodeError::InvalidFormat)?;

        let header: Header = repr::decode_value_from_base64url(header)?;
        let signature = repr::decode_bytes_from_base64url(signature)
            .map_err(|e| JwtDecodeError::Decode(repr::DecodeError::Base64(e)))?;

        Ok(Self {
            header_and_payload,
            header,
            payload,
            signature,
        })
    }

    pub fn parse<Claims>(&self) -> Result<JwtData<Claims>, JwtDecodeError>
    where
        Claims: DeserializeOwned,
    {
        let claims: Claims = repr::decode_value_from_base64url(self.payload)?;
        Ok(JwtData {
            header: self.header.clone(),
            claims,
        })
    }
    pub fn parse_owned<Claims>(self) -> Result<JwtData<Claims>, JwtDecodeError> {
        let claims: Claims = repr::decode_value_from_base64url(self.payload)?;
        Ok(JwtData {
            header: self.header,
            claims
        })
    }

    /// Checks if [`Self::signature`] is correct using `verifier`.
    ///
    /// This function also checks whether the header is supported by the verifier,
    /// although this may change in the future.
    pub fn verify_signature<Verifier>(&self, verifier: &Verifier) -> bool
    where
        Verifier: ?Sized + JwsVerifier,
    {
        if !verifier.validate_header(&self.header) {
            return false;
        }
        if !verifier.verify_signature(self.header_and_payload.as_bytes(), &self.signature) {
            return false;
        }

        true
    }
    pub fn verify_signature_multi<'v, Verifier>(
        &self,
        verifiers: impl Iterator<Item = &'v Verifier>,
    ) -> bool
    where
        Verifier: ?Sized + JwsVerifier + 'v,
    {
        for verifier in verifiers {
            // This does duplicate the code of verify_signature and I intend to keep it that way.
            if verifier.validate_header(&self.header) {
                continue;
            }
            if verifier.verify_signature(self.header_and_payload.as_bytes(), &self.signature) {
                return true;
            }
        }
        false
    }
}

fn get_jwt_parts(input: &str) -> Option<(&str, &str, &str, &str)> {
    let (header_and_payload, signature) = input.rsplit_once('.')?;
    let (header, payload) = header_and_payload.split_once('.')?;
    Some((header, payload, header_and_payload, signature))
}

#[derive(Debug, thiserror::Error)]
pub enum JwtDecodeError {
    #[error("the JWT is formatted incorrectly (not 3 parts separated by dots)")]
    InvalidFormat,
    #[error("could not decode value: {0}")]
    Decode(#[from] repr::DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum JwtCreateError {
    #[error("could not encode value: {0}")]
    Encode(#[from] serde_json::Error), // Currently repr only has encoding errors because of Serde so :)
}
