//! AES-CTR ciphers implementation.
//!
//! Cipher functionality is accessed using traits from re-exported
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! This crate will select appropriate implementation at compile time depending
//! on target architecture and enabled target features. For the best performance
//! on x86-64 CPUs enable `aes`, `sse2` and `ssse3` target features. You can do
//! it either by using `RUSTFLAGS="-C target-feature=+aes,+ssse3"` or by editing
//! your `.cargo/config`. (`sse2` target feature is usually enabled by default)
//!
//! # Security Warning
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Usage example
//! ```
//! use aes_ctr::Aes128Ctr;
//! use aes_ctr::cipher::{
//!     generic_array::GenericArray,
//!     stream::{
//!         NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek
//!     }
//! };
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = GenericArray::from_slice(b"very secret key.");
//! let nonce = GenericArray::from_slice(b"and secret nonce");
//! // create cipher instance
//! let mut cipher = Aes128Ctr::new(&key, &nonce);
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [6, 245, 126, 124, 180, 146, 37]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

#[cfg(not(all(
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
mod soft;

#[cfg(not(all(
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
use soft as aes;

#[cfg(all(
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
))]
use aesni as aes;

pub use crate::aes::{Aes128Ctr, Aes192Ctr, Aes256Ctr};

#[test]
fn compare_to_openssl_with_over_64bit_nonce_and_counter() {
    use cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use core::fmt;
    use hex_literal::hex;
    // values from https://github.com/RustCrypto/stream-ciphers/issues/12 poc

    #[derive(PartialEq, Eq)]
    struct HexOnly<'a>(&'a [u8]);

    impl<'a> fmt::Debug for HexOnly<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.iter().try_for_each(|b| write!(fmt, "{:02x}", b))
        }
    }

    let key = hex!("0dc1 430e 6954 f687 d8d8 28fb 1a54 77df");
    let nonce = hex!("1aff ffff ffff ffff ffff ffff ffff ffff");
    let data = hex!(
        "ffff ffff ffff ffff ffff ffff ffff ffff
        ffff ffff ffff ffff ffff ffff ffff ffff
        ffff ffff ffff ffff ffff ffff ffff ffff
        ffff ffff ffff ffff ffff ffff 07ff ffff
        ffff ffff ffff ffff ffff ffff ffff ffff
        ffff ffff ffff ffff ffff ffff ffff ffff
        ffff ca7c d800"
    );

    let openssl = hex!(
        "6cfd 499f 292b 5e4f 0f79 80ba 87f6 c257
        1bde e9d8 024a 6a4f 46ef 695d 7da9 3bf3
        abe1 0fa5 6657 4f01 1f7d 9748 c7b8 470e
        45c8 0d05 ab1a 6a56 8137 fedb a633 2269
        9aa6 0c6c ef64 997d e588 561e e995 a94d
        9a19 e26b cd35 90e9 3ee1 edda 07f6 3d92
        1fbd d4b2 6858"
    );

    let mut cipher = Aes128Ctr::new_var(&key, &nonce).unwrap();
    let mut encrypted = data.to_vec();
    cipher.apply_keystream(&mut encrypted);

    assert_eq!(HexOnly(&encrypted[..]), HexOnly(&openssl[..]));

    cipher.seek(0);
    cipher.apply_keystream(&mut encrypted[..]);

    assert_eq!(&encrypted[..], &data[..]);
}
