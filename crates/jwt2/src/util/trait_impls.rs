use crate::{
    Algorithm, Header, JwsSigner, JwsVerifier, RecommendHeaderParams, ValidateHeaderParams,
};

macro_rules! proxy_impl {
    (
        $(
            $bounded_type:tt $(: $bound:tt $(+ $bound_extra:tt )*)?
        ),+
        => $target_ty:ty : $self_ident:ident => $inner_expr:expr) => {
        impl< $( $bounded_type $(: $bound $(+ $bound_extra )*)? ),+ > RecommendHeaderParams for $target_ty
        where
            T: RecommendHeaderParams + ?Sized
        {
            fn alg(&$self_ident) -> Algorithm {
                T::alg($inner_expr)
            }
            fn kid(&$self_ident) -> Option<&str> {
                T::kid($inner_expr)
            }
        }
        impl< $( $bounded_type $(: $bound $(+ $bound_extra )*)? ),+ > JwsSigner for $target_ty
        where
            T: JwsSigner + ?Sized
        {
            fn sign(&$self_ident, data: &[u8]) -> Vec<u8> {
                T::sign($inner_expr, data)
            }
        }
        impl< $( $bounded_type $(: $bound $(+ $bound_extra )*)? ),+ > ValidateHeaderParams for $target_ty
        where
            T: ValidateHeaderParams + ?Sized
        {
            fn validate_header(&$self_ident, header: &Header) -> bool {
                T::validate_header($inner_expr, header)
            }
        }
        impl< $( $bounded_type $(: $bound $(+ $bound_extra )*)? ),+ > JwsVerifier for $target_ty
        where
            T: JwsVerifier + ?Sized
        {
            fn verify_signature(&$self_ident, data: &[u8], signature: &[u8]) -> bool {
                T::verify_signature($inner_expr, data, signature)
            }
        }
    };
}

proxy_impl!(T => &T : self => self);
proxy_impl!(T => Box<T> : self => self);
proxy_impl!(T => std::rc::Rc<T> : self => self);
proxy_impl!(T => std::sync::Arc<T> : self => self);
proxy_impl!('a, T: 'a + ToOwned => std::borrow::Cow<'a, T> : self => self.as_ref());

// TODO: Proxy impl for Pin<T>, I think