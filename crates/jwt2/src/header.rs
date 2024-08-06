use crate::sign::SigningAlgorithm;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    /// The algorithm that this object is/will be signed with.
    /// Corresponds to the `alg` header parameter.
    ///
    /// See [section 4.1.1 of RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1).
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    /// The type of the object that is encoded with this header.
    /// Corresponds to the `kid` header parameter.
    ///
    /// See [section 4.1.4 of RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4).
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    /// The type of the object that is encoded with this header.
    /// Corresponds to the `typ` header parameter.
    ///
    /// See [section 4.1.9 of RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9).
    #[serde(rename = "typ")]
    pub obj_type: Option<String>,

    /// A list of parameters, i.e. field names, that the JWS implementation (i.e. `jwt2`) is
    /// required to process.
    /// Corresponds to the `crit` header parameter.
    ///
    /// This is a field that `jwt2` doesn't really support yet, but it is left in for the sake of
    /// being standards-compliant.
    ///
    /// To validate this, use the [`Header::required_extensions`] function.
    ///
    /// See [section 4.1.11 of RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11).
    #[serde(rename = "crit")]
    pub required_extensions: Option<Vec<String>>,
}
impl Header {
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            key_id: None,
            obj_type: None,
            required_extensions: None,
        }
    }

    /// Checks if this library supports the required extensions.
    ///
    /// # Implementation details
    /// For now, this will return true if [`Self::required_extensions`] is `Some`.
    ///
    /// This is standards-compliant and "correct" behaviour since if it returns `true`:
    /// 1. the array is empty, which is not standards-compliant:
    ///    > Producers MUST NOT use the empty list `[]` as the `crit` value.
    /// 2. the array contains headers which are technically supported by `jwt2`.
    ///    At the moment, `jwt2` only supports header parameters that are specified by
    ///    [the JWS RFC](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1)
    ///    or those specified by [the JWA RFC](https://www.rfc-editor.org/rfc/rfc7518.html).
    ///    > Recipients MAY consider the JWS to be invalid if the critical list contains
    ///    > any Header Parameter names defined by this specification or JWA for use with JWS
    ///    > or if any other constraints on its use are violated.
    /// 3. the array specifies any parameter that `jwt2` does not recognise,
    ///    being the genuinely correct case.
    ///    > If any of the listed extension Header Parameters are not understood
    ///    > and supported by the recipient, then the JWS is invalid.
    ///
    /// In the future, however, this function should properly check if the parameters are handled.
    pub fn supports_required_extensions(&self) -> bool {
        self.required_extensions.is_some()
    }
}

/// JSON Web Algorithm.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    /// The `none` algorithm, indicating that no digital signature
    #[serde(rename = "none")]
    None,
    /// An algorithm for use with JSON Web Signatures.
    #[serde(untagged)]
    Signing(SigningAlgorithm),
}

impl PartialEq<SigningAlgorithm> for Algorithm {
    fn eq(&self, other: &SigningAlgorithm) -> bool {
        match self {
            Self::Signing(me) => me == other,
            _ => false,
        }
    }
}

// Don't ask me why I chose core::fmt instead of std::fmt
impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::None => f.write_str("<none>"),
            Self::Signing(alg) => core::fmt::Display::fmt(alg, f)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_value() {
        macro_rules! test {
            ($value:expr => $expected:expr) => {
                let value = $value;
                let json = serde_json::to_string(&value).expect("Could not serialise");
                let expected = $expected;
                assert_eq!(json, expected);
            };
        }
        test!(Algorithm::None => "\"none\"");
        #[cfg(feature = "hmac-sha2")]
        {
            test!(Algorithm::Signing(SigningAlgorithm::HS256) => "\"HS256\"");
            test!(Algorithm::Signing(SigningAlgorithm::HS384) => "\"HS384\"");
            test!(Algorithm::Signing(SigningAlgorithm::HS512) => "\"HS512\"");
        }
        #[cfg(feature = "rsa-pkcs1")]
        {
            test!(Algorithm::Signing(SigningAlgorithm::RS256) => "\"RS256\"");
            test!(Algorithm::Signing(SigningAlgorithm::RS384) => "\"RS384\"");
            test!(Algorithm::Signing(SigningAlgorithm::RS512) => "\"RS512\"");
        }
        #[cfg(feature = "ecdsa")]
        {
            test!(Algorithm::Signing(SigningAlgorithm::ES256) => "\"ES256\"");
            test!(Algorithm::Signing(SigningAlgorithm::ES384) => "\"ES384\"");
            // test!(Algorithm::Signing(SigningAlgorithm::ES512) => "\"ES512\"");
        }
    }
}
