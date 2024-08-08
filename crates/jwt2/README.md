# `jwt2`: JSON Web Tokens, done right.

`jwt2` is a crate that aims to correctly deal with JSON Web Tokens.

It is intended as a replacement for the `jsonwebtoken` crate.

> **WARNING!**
> 
> `jwt2` is currently unstable and prone to changes. 
> Whilst I am mostly happy with the code thus far, 
> major changes to the API may occur at any time.
> 
> The algorithms this crate provides are all tested to some extent so 
> it is "safe" to use in actual code. If you want a tried-and-tested\* crate, 
> try the aforementioned `jsonwebtoken` crate.
> 
> <sup>\*May not be actually tried-and-tested. 
> It's got over 24 million all-time downloads though, so there's that.</sup>

## Goals and non-goals

`jwt2` is (supposed to be):
- A library that helps you construct, decode, sign, and verify 
  JSON Web Tokens.
- Compatible with as many platforms as reasonably possible.
- Standards-compliant.
- Correct.

`jwt2` is **not**, and *should never be*:
- A library to manage your application's sessions.
- A wrapper around some authorization API that gets session tokens.

Whilst `jwt2` may not necessarily fulfill all the goals specified above,
at some point I hope it will.

## Feature gates

All algorithms implemented by `jwt2` are gated behind the following features.
None of these are enabled by default.

- `hmac-sha2`: Defines the `HS256`, `HS384`, and `HS512` algorithms.
- `rsa-pkcs1`: Defines the `RS256`, `RS384`, and `RS512` algorithms.
- `ecdsa`: Defines the `ES256` and `ES384` algorithms.
- `rand`: Provides utility functions to generate keys.
  > This feature is still not complete, nor is it properly tested.

## Libraries used

`jwt2` is made using the wonderfully easy-to-use `RustCrypto` family of crates as 
the backing implementations of all the algorithms thus far.
- `HS256`, `HS384`, and `HS512` use the 
  [`hmac`](https://github.com/RustCrypto/MACs/tree/master/hmac) and 
  [`sha2`](https://github.com/RustCrypto/hashes/tree/master/sha2) crates.
- `RS256`, `RS384`, and `RS512` use the 
  [`rsa`](https://github.com/RustCrypto/RSA) and
  [`sha2`](https://github.com/RustCrypto/hashes/tree/master/sha2) crates.
- `ES256` and `ES384` use the 
  [`p256`](https://github.com/RustCrypto/elliptic-curves/tree/master/p256) and 
  [`p384`](https://github.com/RustCrypto/elliptic-curves/tree/master/p384) crates.
  > `p256` and `p384` warn that the EC algorithm they contain have never been independently audited.
  > For those that consider this a dealbreaker, don't use the `ES256` or `ES384` algorithms. 
- Base64 encoding and decoding is done using the 
  [`base64ct`](https://github.com/RustCrypto/formats/tree/master/base64ct) crate.

JSON functionality is provided by the libraries [Serde](https://serde.rs) 
and [Serde JSON](https://github.com/serde-rs/json).

## Resources referenced

`jwt2`, in its pursuit to be standards-compliant, principally references and at times
incorporates documentation from the standards in question.

The standards in question are the following RFCs:
- [RFC 7515: JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7516: JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516.html)
- [RFC 7518: JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518.html)

To test the correctness of `jwt2`, beyond the tests included in the code, 
I've cross-referenced the example values from [jwt.io](https://jwt.io), presuming their correctness.

## Licence

`jwt2` is licensed under the Apache 2.0 License.

```
Copyright 2024 tecc <tecc@tecc.me>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
