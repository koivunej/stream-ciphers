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
fn compare_to_openssl_with_poc_values() {
    use hex_literal::hex;
    // values from https://github.com/RustCrypto/stream-ciphers/issues/12 poc

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

    compare_scenario(&key, &data, &nonce, &openssl);
}

#[test]
fn compare_to_openssl_at_zero_nonce() {
    use hex_literal::hex;

    let nonce = [0; 16];
    let expected = hex!("66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0");

    // this should match the behaviour before the #75
    compare_scenario(&[0; 16], &[0; 4 * 16], &nonce, &expected);
}

#[test]
fn compare_to_openssl_near_64bit_le() {
    use hex_literal::hex;

    let nonce = (u64::MAX as u128 - 1).to_le_bytes();
    let expected = hex!("0fc33b45e52ac8f00392805984e573c6e2a4ba8f764fa3fbe8b6e6e3cda6ecfff7ffe7a8bc8c8214384903c72e2d54fd20c10ba6f72ff0734fc4e545b7b1e585");

    // this shouldn't wrap around as the nonce is treated as big endian input; this should match
    // behaviour before the #75
    compare_scenario(&[0; 16], &[0; 4 * 16], &nonce, &expected);
}

#[test]
fn compare_to_openssl_near_64bit_be() {
    use hex_literal::hex;

    let nonce = (u64::MAX as u128 - 1).to_be_bytes();
    let expected = hex!("99c5f4ae0531eece7c33dab98d5e289d747cb9267e59fa9e4e615668db0909bc788bcd111ecf73d4e78d2e21bef55460daacdaf76b0cffc0fa1498a35ebe1dfc");

    // changed in #75 as previously counter was 64-bit and only half of nonce was affected by it
    // wrapping around.
    compare_scenario(&[0; 16], &[0; 4 * 16], &nonce, &expected);
}

#[test]
fn compare_to_openssl_near_128bit_be() {
    use hex_literal::hex;

    let nonce = (u128::MAX as u128 - 1).to_be_bytes();
    let expected = hex!("5c005e72c1418c44f569f2ea33ba54f33f5b8cc9ea855a0afa7347d23e8d664e66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a");

    // changed in #75 for same reason as `compare_to_openssl_near_64bit_be`.
    compare_scenario(&[0; 16], &[0; 4 * 16], &nonce, &expected);
}

/// Run aes-ctr against openssl generated next four blocks from the nonce.
#[cfg(test)]
fn compare_scenario(key: &[u8], data: &[u8], nonce: &[u8], expected: &[u8]) {
    use cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
    use core::fmt;

    #[derive(PartialEq, Eq)]
    struct HexOnly<'a>(&'a [u8]);

    impl<'a> fmt::Debug for HexOnly<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.iter().try_for_each(|b| write!(fmt, "{:02x}", b))
        }
    }

    assert_eq!(expected.len(), data.len());

    let mut cipher = Aes128Ctr::new_var(&key, &nonce).unwrap();

    let mut encrypted = data.to_vec();
    cipher.apply_keystream(&mut encrypted[..]);
    assert_eq!(&encrypted[..], &expected[..]);

    cipher.seek(0);
    cipher.apply_keystream(&mut encrypted[..]);
    assert_eq!(&encrypted[..], &data[..]);
}
