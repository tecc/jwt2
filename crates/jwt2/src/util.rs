mod with_keyid;

pub use with_keyid::*;

macro_rules! algorithms_decl {
    (
        $(#[$enum_attrs:meta])*
        $enum_ident:ident;
        $(
            $(#[$variant_attrs:meta])* $variant_ident:ident {
                $(cfg: $(#[$variant_attrs_cfg:meta])*;)?
            }
        ),*
    ) => {
        $(#[$enum_attrs])*
        pub enum $enum_ident {
            $(
            $(#[$variant_attrs])*
            $( $(#[$variant_attrs_cfg])* )?
            $variant_ident,
            )*
        }

        #[allow(unreachable_code, unreachable_patterns)]
        const _: () = {
            $(
            $( $(#[$variant_attrs_cfg])* )?
            const $variant_ident: &'static str = stringify!($variant_ident);
            )*

            impl core::str::FromStr for $enum_ident {
                type Err = ();

                /// Tries to get an algorithm from a string.
                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    // I prefer to be liberal in what is accepted, but RFC 7515 specifies that
                    // algorithm names are indeed case-sensitive.
                    $(
                        $( $(#[$variant_attrs_cfg])* )?
                        if value.eq($variant_ident) {
                            return Ok(Self::$variant_ident);
                        }
                    )*
                    Err(())
                }
            }

            impl core::fmt::Display for $enum_ident {
                fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    match self {
                        $(
                        $( $(#[$variant_attrs_cfg])* )?
                        Self::$variant_ident => f.write_str($variant_ident),
                        )*
                        _ => f.write_str("<invalid>")
                    }
                }
            }

            impl serde::ser::Serialize for $enum_ident {
                fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
                    where S: serde::ser::Serializer
                {
                    match self {
                        $(
                        $( $(#[$variant_attrs_cfg])* )?
                        Self::$variant_ident => ser.serialize_str($variant_ident),
                        )*
                        _ => panic!("The default match should not be reachable for this enum")
                    }
                }
            }
            impl<'de> serde::de::Deserialize<'de> for $enum_ident {
                fn deserialize<D>(de: D) -> Result<Self, D::Error>
                    where D: serde::de::Deserializer<'de>
                {
                    struct VisitorImpl;
                    impl<'de> serde::de::Visitor<'de> for VisitorImpl {
                        type Value = $enum_ident;
                        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                            // TODO: Maybe improve this message?
                            f.write_str(stringify!($enum_ident))
                        }

                        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: serde::de::Error {
                            $(
                            $( $(#[$variant_attrs_cfg])* )?
                            if value.eq($variant_ident) {
                                return Ok($enum_ident::$variant_ident);
                            }
                            )*

                            const VARIANTS: &[&'static str] = &[
                                $(
                                $( $(#[$variant_attrs_cfg])* $variant_ident, )?
                                )*
                            ];

                            Err(E::unknown_variant(value, VARIANTS))
                        }
                    }

                    de.deserialize_str(VisitorImpl)
                }
            }
        };
    };
}

pub(crate) use algorithms_decl;

pub(crate) fn to_byte_vec(r: &[u8]) -> Vec<u8> {
    Vec::from(r)
}
