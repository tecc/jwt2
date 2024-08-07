use crate::{
    Algorithm, Header, JwsSigner, JwsVerifier, RecommendHeaderParams, ValidateHeaderParams,
};

/// A utility for use with [`Header::key_id`].
///
/// In the case of [`ValidateHeaderParams`]s, [`ValidateHeaderParams::validate_header`] will also
/// make sure that the `key_id` if present, is equal to the specified `key_id`.
/// If the `key_id` isn't present, it returns whatever the `accept_missing_key_id` field is set to.
///
/// See [`WithKeyId::new`] and [`WithKeyId::new_accept_missing`].
pub struct WithKeyId<Inner> {
    pub key_id: String,
    pub inner: Inner,
    pub accept_missing_key_id: bool,
}
impl<Inner> WithKeyId<Inner> {
    /// Creates a new [`WithKeyId`] that requires [`Header::key_id`] to be present and equal to
    /// `key_id` for [`ValidateHeaderParams::validate_header`] to return true.
    ///
    /// If a non-present `Header::key_id` should match, consider using
    /// [`WithKeyId::new_accept_missing`].
    pub fn new(key_id: String, inner: Inner) -> Self {
        Self {
            key_id,
            inner,
            accept_missing_key_id: false,
        }
    }
    /// Creates a new [`WithKeyId`] that requires [`Header::key_id`] to be equal to `key_id`
    /// *if `Header::key_id` is present* for [`ValidateHeaderParams::validate_header`].
    ///
    /// If the absence of `Header::key_id` should not match, consider using [`WithKeyId::new`].
    pub fn new_accept_missing(key_id: String, inner: Inner) -> Self {
        Self {
            key_id,
            inner,
            accept_missing_key_id: true,
        }
    }
    pub fn key_id(&self) -> &str {
        self.key_id.as_str()
    }
}

impl<Inner> RecommendHeaderParams for WithKeyId<Inner>
where
    Inner: RecommendHeaderParams,
{
    fn alg(&self) -> Algorithm {
        self.inner.alg()
    }
    fn kid(&self) -> Option<&str> {
        Some(self.key_id.as_str())
    }
}

impl<Inner> JwsSigner for WithKeyId<Inner>
where
    Inner: JwsSigner,
{
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.inner.sign(data)
    }
}

impl<Inner> ValidateHeaderParams for WithKeyId<Inner>
where
    Inner: ValidateHeaderParams,
{
    fn validate_header(&self, header: &Header) -> bool {
        let Some(ref header_key_id) = header.key_id else {
            return self.accept_missing_key_id;
        };

        if header_key_id.eq(&self.key_id) {
            self.inner.validate_header(header)
        } else {
            false
        }
    }
}

impl<Inner> JwsVerifier for WithKeyId<Inner>
where
    Inner: JwsVerifier,
{
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        self.inner.verify_signature(data, signature)
    }
}
