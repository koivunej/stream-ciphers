#[cfg(test)]
mod tests {
    use core::fmt;

    #[test]
    fn counter_wrapping_against_openssl() {
        use cipher::generic_array::{typenum::U16, GenericArray};
        use cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
        use core::convert::*;
        use openssl::symm;

        // this is probably fine for aes-ctr tests since we arent really interested in the
        // cipherstream, just what happens when the counter wraps around
        let key = [0u8; 16];

        let data = [0; 4 * 16];

        for orig_nonce in [
            0u128,
            u128::MAX - 1,
            u64::MAX as u128 - 1,
            u32::MAX as u128 - 1,
            u16::MAX as u128 - 1,
        ]
        .iter()
        {
            let nonce: GenericArray<u8, U16> = orig_nonce.to_be_bytes().into();
            let mut cipher = aes_ctr::Aes128Ctr::new((&key).into(), &nonce);

            eprintln!("{:?}", cipher);

            let mut encrypted = data.to_vec();
            let by_openssl = symm::encrypt(
                symm::Cipher::aes_128_ctr(),
                &key[..],
                // this is required, there is no default IV for None
                Some(&nonce[..]),
                &data[..],
            )
            .unwrap();

            cipher.apply_keystream(&mut encrypted[..]);
            assert_eq!(&by_openssl[..], &encrypted[..]);

            // then decrypt it back
            cipher.seek(0);
            cipher.apply_keystream(&mut encrypted);

            assert_eq!(&data[..], &encrypted[..]);
        }
    }

    #[derive(PartialEq, Eq)]
    struct HexOnly<'a>(&'a [u8]);

    impl<'a> fmt::Debug for HexOnly<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.iter().try_for_each(|b| write!(fmt, "{:02x}", b))
        }
    }
}
