// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::Error;
use super::{base64_decode, base64_encode};
use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};

type Result<T, E = Error> = std::result::Result<T, E>;

/// The one nonce every value is encrypted under. It is fixed on purpose:
/// the ciphertext carries no nonce, so a value can only be read back with
/// the nonce it was written under, and AES-GCM-SIV is nonce misuse
/// resistant - repeating a nonce reveals whether two plaintexts are equal,
/// never their contents. Changing it makes every stored secret unreadable.
const PINGAP_NONCE: [u8; 12] = *b"pingap nonce";

const KEY_SIZE: usize = 32;

/// Derives the 32-byte key from the input: truncated when longer, padded
/// with zeros when shorter.
fn generate_key(key: &str) -> [u8; KEY_SIZE] {
    let mut block = [0u8; KEY_SIZE];
    let buf = key.as_bytes();
    let len = buf.len().min(KEY_SIZE);
    block[..len].copy_from_slice(&buf[..len]);
    block
}

fn new_cipher(key: &str) -> Result<Aes256GcmSiv> {
    Aes256GcmSiv::new_from_slice(&generate_key(key)).map_err(|e| {
        Error::Invalid {
            message: e.to_string(),
        }
    })
}

/// Encrypts data using AES-256-GCM-SIV with a static nonce.
///
/// # Arguments
/// * `key` - The encryption key
/// * `data` - The plaintext data to encrypt
///
/// # Returns
/// * `Ok(String)` - Base64 encoded ciphertext
/// * `Err(Error)` - If encryption fails
pub fn aes_encrypt(key: &str, data: &str) -> Result<String> {
    let cipher_text = new_cipher(key)?
        .encrypt(&Nonce::from(PINGAP_NONCE), data.as_bytes())
        .map_err(|e| Error::Aes {
            message: e.to_string(),
        })?;
    Ok(base64_encode(cipher_text))
}

/// Decrypts AES-256-GCM-SIV encrypted data using a static nonce.
///
/// # Arguments
/// * `key` - The decryption key
/// * `data` - Base64 encoded ciphertext to decrypt
///
/// # Returns
/// * `Ok(String)` - Decrypted plaintext
/// * `Err(Error)` - If decryption or base64 decoding fails
pub fn aes_decrypt(key: &str, data: &str) -> Result<String> {
    let cipher_text =
        base64_decode(data).map_err(|e| Error::Base64Decode { source: e })?;
    let plaintext = new_cipher(key)?
        .decrypt(&Nonce::from(PINGAP_NONCE), cipher_text.as_ref())
        .map_err(|e| Error::Aes {
            message: e.to_string(),
        })?;
    String::from_utf8(plaintext).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })
}

/// Encrypts `data` under `key` with a nonce of its own, for what is handed
/// to somebody who is not to read or change it: a session in a cookie.
/// `nonce` is to be a new random one for every value. The result is the
/// nonce and the ciphertext, in the base64 of urls.
pub fn seal(
    key: &[u8; KEY_SIZE],
    nonce: [u8; 12],
    data: &[u8],
) -> Result<String> {
    use base64::Engine;
    let cipher =
        Aes256GcmSiv::new_from_slice(key).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
    let cipher_text =
        cipher
            .encrypt(&Nonce::from(nonce), data)
            .map_err(|e| Error::Aes {
                message: e.to_string(),
            })?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&cipher_text);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed))
}

/// What [`seal`] was given, when `value` is one it made under `key` and
/// has not been changed since.
pub fn unseal(key: &[u8; KEY_SIZE], value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let sealed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()?;
    let (nonce, cipher_text) = sealed.split_at_checked(12)?;
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    Aes256GcmSiv::new_from_slice(key)
        .ok()?
        .decrypt(&Nonce::from(nonce), cipher_text)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_aes_encrypt() {
        for key in [
            "12345678901234567890123456789012",
            "12345678901234567890123456789012ABC",
            "1234567890123456789012345678901",
        ] {
            let data = "hello";
            let result = aes_encrypt(key, data);
            assert_eq!(result.is_ok(), true);

            let result = aes_decrypt(key, &result.unwrap());
            assert_eq!(result.is_ok(), true);
            assert_eq!(result.unwrap(), data);
        }
    }

    /// Values encrypted by earlier releases must still decrypt, and the
    /// same input must still encrypt to the same bytes: the nonce and the
    /// key derivation are part of the stored format.
    #[test]
    fn test_aes_stored_format_is_stable() {
        assert_eq!(
            "ckosmpE7P8FUPbIY7mKyURn+9G46",
            aes_encrypt("12345678901234567890123456789012", "hello").unwrap()
        );
        assert_eq!(
            "pingap secret",
            aes_decrypt(
                "short-key",
                "ytvtT0b5XoF1pdqRbfqX9qgATJJ25guB2xxG0T0="
            )
            .unwrap()
        );
        // A wrong key is an authentication failure, not garbage.
        assert_eq!(
            true,
            aes_decrypt(
                "other-key",
                "ytvtT0b5XoF1pdqRbfqX9qgATJJ25guB2xxG0T0="
            )
            .is_err()
        );
    }

    /// What is sealed comes back for the key it was sealed under, and
    /// for nothing that was changed.
    #[test]
    fn test_seal() {
        let key = [7u8; KEY_SIZE];
        let sealed = seal(&key, [1u8; 12], b"a session").unwrap();
        assert_eq!(Some(b"a session".to_vec()), unseal(&key, &sealed));
        // Text for a url or a cookie.
        assert_eq!(
            true,
            sealed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        // Another nonce, another text: what is sealed twice is not seen
        // to be the same.
        let again = seal(&key, [2u8; 12], b"a session").unwrap();
        assert_eq!(true, sealed != again);
        assert_eq!(Some(b"a session".to_vec()), unseal(&key, &again));

        assert_eq!(None, unseal(&[8u8; KEY_SIZE], &sealed));
        for end in [0, 5, 16, sealed.len() - 1] {
            assert_eq!(None, unseal(&key, &sealed[..end]), "{end}");
        }
        let mut changed = sealed.into_bytes();
        changed[20] = if changed[20] == b'A' { b'B' } else { b'A' };
        assert_eq!(None, unseal(&key, std::str::from_utf8(&changed).unwrap()));
        assert_eq!(None, unseal(&key, "not base64 !"));
        // Nothing at all can be sealed too.
        let empty = seal(&key, [3u8; 12], b"").unwrap();
        assert_eq!(Some(vec![]), unseal(&key, &empty));
    }
}
