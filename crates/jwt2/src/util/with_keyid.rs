use crate::{
    Algorithm, Header, JwsSigner, JwsVerifier, RecommendHeaderParams, ValidateHeaderParams,
};

/// A utility for use with [`Header::key_id`].
///
/// In the case of [`JwsVerifier`]s, [`JwsVerifier::check_header`] will also make sure that
/// the `key_id` is present and is equal to the specified `key_id`.
pub struct WithKeyId<Inner> {
    pub key_id: String,
    pub inner: Inner,
    pub accept_missing_key_id: bool,
}
impl<Inner> WithKeyId<Inner> {
    pub fn new(key_id: String, inner: Inner) -> Self {
        Self {
            key_id,
            inner,
            accept_missing_key_id: false,
        }
    }
    // Note: `new` is generally preferred, at least in my mind.
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

impl<Inner> RecommendHeaderParams for WithKeyId<Inner>
where
    Inner: RecommendHeaderParams,
{
    fn alg(&self) -> Option<Algorithm> {
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
