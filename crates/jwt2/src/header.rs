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
    /// Corresponds to the `typ` header parameter.
    ///
    /// See [section 4.1.9 of RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9)
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
#[derive(Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Algorithm {
    /// An algorithm for use with JSON Web Signatures.
    Signing(SigningAlgorithm),
    /// The `none` algorithm, indicating that no digital signature
    #[serde(rename = "none")]
    None
}

impl PartialEq<SigningAlgorithm> for Algorithm {
    fn eq(&self, other: &SigningAlgorithm) -> bool {
        match self {
            Self::Signing(me) => me == other,
            _ => false
        }
    }
}