// Copyright 2024 Tree xie.
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
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use once_cell::sync::Lazy;

type Result<T, E = Error> = std::result::Result<T, E>;

static PINGAP_NONCE: Lazy<&Nonce> =
    Lazy::new(|| Nonce::from_slice(b"pingap nonce"));

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

pub fn aes_encrypt(key: &str, data: &str) -> Result<String> {
    let cipher =
        Aes256GcmSiv::new_from_slice(&generate_key(key)).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })?;
    let ciphertext =
        cipher
            .encrypt(&PINGAP_NONCE, data.as_bytes())
            .map_err(|e| Error::Aes {
                message: e.to_string(),
            })?;
    Ok(base64_encode(&ciphertext))
}

pub fn aes_decrypt(key: &str, data: &str) -> Result<String> {
    let cipher =
        Aes256GcmSiv::new_from_slice(&generate_key(key)).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })?;
    let ciphertext =
        base64_decode(data).map_err(|e| Error::Base64Decode { source: e })?;
    let plaintext = cipher
        .decrypt(&PINGAP_NONCE, ciphertext.as_ref())
        .map_err(|e| Error::Aes {
            message: e.to_string(),
        })?;

    Ok(std::str::from_utf8(&plaintext)
        .unwrap_or_default()
        .to_string())
}
