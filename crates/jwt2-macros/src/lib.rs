use proc_macro2::Span;

// A thing has been added!
// I'll get working on this some other time.

// TODO: Good design for a Claims derive (so people don't need to write claims validation over and over)
//       Notes for the DOers:
//         1. #[derive(jwt2::Claims)] should give you a correct claims validation function.
//         2. It should support various kinds of time structures and configurations
//            (e.g. std::time::SystemTime, chrono::DateTime<Tz>, and even raw UNIX timestamps as u64s)
//         3. It should also generate implementations for configurable 'leeway';
//            if the expiry is some small amount of time in the past, let it be.

#[proc_macro_derive(Claims, attributes(jwt2))]
pub fn derive_claims(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    syn::Error::new(Span::call_site(), "This macro is not yet supported")
        .into_compile_error()
        .into()
}
