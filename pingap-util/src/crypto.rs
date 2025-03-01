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
use once_cell::sync::Lazy;

type Result<T, E = Error> = std::result::Result<T, E>;

static PINGAP_NONCE: Lazy<&Nonce> =
    Lazy::new(|| Nonce::from_slice(b"pingap nonce"));

/// Generates a 32-byte key from the input string.
/// If the input is longer than 32 bytes, it's truncated.
/// If shorter, it's padded with zeros.
///
/// # Arguments
/// * `key` - The input string to generate the key from
///
/// # Returns
/// A Vec<u8> containing the 32-byte key
fn generate_key(key: &str) -> Vec<u8> {
    let key_size = 32;
    let buf = key.as_bytes();
    let pos = buf.len();
    if pos > key_size {
        return buf[0..key_size].to_vec();
    }
    if pos == key_size {
        return buf.to_vec();
    }
    let mut block: Vec<u8> = vec![0; key_size];
    block[..pos].copy_from_slice(buf);
    block
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
    let cipher =
        Aes256GcmSiv::new_from_slice(&generate_key(key)).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })?;
    let cipher_text =
        cipher
            .encrypt(&PINGAP_NONCE, data.as_bytes())
            .map_err(|e| Error::Aes {
                message: e.to_string(),
            })?;
    Ok(base64_encode(&cipher_text))
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
    let cipher =
        Aes256GcmSiv::new_from_slice(&generate_key(key)).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })?;
    let cipher_text =
        base64_decode(data).map_err(|e| Error::Base64Decode { source: e })?;
    let plaintext = cipher
        .decrypt(&PINGAP_NONCE, cipher_text.as_ref())
        .map_err(|e| Error::Aes {
            message: e.to_string(),
        })?;

    Ok(std::str::from_utf8(&plaintext)
        .unwrap_or_default()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_aes_encrypt() {
        let key = "12345678901234567890123456789012";
        let data = "hello";
        let result = aes_encrypt(key, data);
        assert_eq!(result.is_ok(), true);

        let result = aes_decrypt(key, &result.unwrap());
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), data);
    }
}
