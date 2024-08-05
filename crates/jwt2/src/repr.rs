use base64ct::Encoding;

/// Encodes to the preferred base64 format specified by RFC 7515:
///
/// > Base64 encoding using the URL- and filename-safe character set
/// > defined in [Section 5 of RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html#section-5),
/// > with all trailing '=' characters omitted (as permitted by Section 3.2) and without the
/// > inclusion of any line breaks, whitespace, or other additional
/// > characters.
///
/// This internally uses `base64ct`, since `jwt2` is not here to reinvent the wheel.
#[inline(always)]
pub fn encode_bytes_as_base64url(s: &[u8]) -> String {
    base64ct::Base64UrlUnpadded::encode_string(s)
}

/// Decodes bytes from the preferred base64 format specified by RFC 7515:
///
/// > Base64 encoding using the URL- and filename-safe character set
/// > defined in [Section 5 of RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html#section-5),
/// > with all trailing '=' characters omitted (as permitted by Section 3.2) and without the
/// > inclusion of any line breaks, whitespace, or other additional
/// > characters.
///
/// This internally uses `base64ct`, since `jwt2` is not here to reinvent the wheel.
pub fn decode_bytes_from_base64url(s: &str) -> Result<Vec<u8>, base64ct::Error> {
    // Note: This function uses a &str for its input parameter only because
    // base64ct's implementation does too.
    // I should probably open an issue for the function to take in a &[u8] instead.
    base64ct::Base64UrlUnpadded::decode_vec(s)
}

/// Encodes a value as a base64-encoded JSON string.
///
/// Effectively equivalent to the following:
/// ```
/// let value = serde_json::json!({ "hello": "world!" });
/// let json = serde_json::to_vec(&value).expect("Could not serialise JSON");
/// let base64 = jwt2::repr::encode_bytes_as_base64url(&json);
/// ```
pub fn encode_value_as_base64url<T>(value: &T) -> Result<String, serde_json::Error>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value)?;
    Ok(encode_bytes_as_base64url(&bytes))
}

/// Decodes a value from a base64-encoded JSON string.
///
/// Effectively equivalent to the following:
/// ```
/// let base64 = "WzMyLDY0XQ"; // This can technically have padding
/// let json = jwt2::repr::decode_bytes_from_base64url(&base64).expect("Could not decode base64");
/// let value: (u64, u64) = serde_json::from_slice(&json).expect("Could not deserialize JSON");
/// ```
pub fn decode_value_from_base64url<T>(s: &str) -> Result<T, DecodeError>
where
    T: serde::de::DeserializeOwned,
{
    let decoded = decode_bytes_from_base64url(s).map_err(DecodeError::Base64)?;
    Ok(serde_json::from_slice(&decoded)?)
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid base64: {0}")]
    Base64(base64ct::Error),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test of encoding the example JWS Protected Header in
    /// [RFC 7515's Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1).
    #[test]
    fn rfc7515_a1_encoding_header() {
        let arr = [
            123u8, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103,
            34, 58, 34, 72, 83, 50, 53, 54, 34, 125,
        ];

        let encoded = encode_bytes_as_base64url(&arr);
        assert_eq!(encoded, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        let decoded = decode_bytes_from_base64url(&encoded).expect("Could not decode");
        assert_eq!(arr, decoded.as_slice())
    }
    /// A test of encoding the example JWS Protected Header in
    /// [RFC 7515's Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1).
    #[test]
    fn rfc7515_a1_encoding_payload() {
        let arr = [
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];

        let encoded = encode_bytes_as_base64url(&arr);
        assert_eq!(encoded, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

        let decoded = decode_bytes_from_base64url(&encoded).expect("Could not decode");
        assert_eq!(arr, decoded.as_slice())
    }
}
