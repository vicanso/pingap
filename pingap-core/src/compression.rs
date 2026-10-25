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

//! Response compression: pingora's, with the brotli streams finished.
//!
//! pingora 0.9.0 ends a brotli stream with a flush and never finishes it
//! (cloudflare/pingora#1013, pingap#256): every `br` body lacks its last
//! meta-block. Browsers render it all the same; a strict decoder - Node's
//! `fetch`, `brotli -t` - rejects it. After a flush the stream is
//! byte-aligned, so one byte finishes it: an empty last meta-block. A
//! stream the encoder wrote nothing of becomes the one byte of an empty
//! stream.
//!
//! The byte is added only while pingora's encoder leaves its streams
//! unfinished, which is checked once ([`brotli_needs_tail`]): a pingora
//! that finishes them turns this off by itself, and a finished stream is
//! never given a second end. Once pingora finishes its streams, this
//! module goes: `test_pingora_still_leaves_brotli_unfinished` fails then.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::modules::http::{
    HttpModule, HttpModuleBuilder, Module, ModuleBuilder,
};
use pingora::protocols::http::compression::{
    Algorithm, ResponseCompressionCtx,
};
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::sync::LazyLock;

/// An empty last meta-block: `ISLAST` and `ISLASTEMPTY` set, the rest of
/// the byte padding.
const LAST_EMPTY_META_BLOCK: u8 = 0x03;
/// A whole stream with nothing in it.
const EMPTY_STREAM: u8 = 0x06;
/// The name pingora's brotli compressor reports itself by (its decoder is
/// `de-brotli`).
const PINGORA_BROTLI: &str = "brotli";

/// Whether the stream is a whole brotli stream: a strict decoder reads it
/// to its end.
fn is_complete_brotli(stream: &[u8]) -> bool {
    let mut out = vec![];
    brotli::Decompressor::new(stream, 4096)
        .read_to_end(&mut out)
        .is_ok()
}

/// Whether pingora's brotli encoder leaves its streams unfinished, so
/// that what it writes needs [`BrotliTail`]. Found out once, by encoding a
/// few bytes.
pub fn brotli_needs_tail() -> bool {
    static NEEDS: LazyLock<bool> = LazyLock::new(|| {
        let Some(mut encoder) = Algorithm::Brotli.compressor(5) else {
            return false;
        };
        encoder
            .encode(b"pingap", true)
            .is_ok_and(|stream| !is_complete_brotli(&stream))
    });
    *NEEDS
}

/// What finishes the stream of one brotli encoder: the output of each of
/// its calls passes through it, the last one gains the end of the stream,
/// and nothing goes after that.
#[derive(Debug, Default)]
pub struct BrotliTail {
    written: bool,
    finished: bool,
}

impl BrotliTail {
    /// `chunk`, what the encoder gave for one call, as it is to be sent;
    /// `end` says the call was the last.
    pub fn apply(&mut self, chunk: Bytes, end: bool) -> Bytes {
        // Once more at the end, as a done filter after the body's own end
        // asks: a flush after the end would be bytes after the stream.
        if self.finished {
            return Bytes::new();
        }
        self.written |= !chunk.is_empty();
        if !end {
            return chunk;
        }
        self.finished = true;
        let tail = if self.written {
            LAST_EMPTY_META_BLOCK
        } else {
            EMPTY_STREAM
        };
        let mut out = BytesMut::with_capacity(chunk.len() + 1);
        out.extend_from_slice(&chunk);
        out.extend_from_slice(&[tail]);
        out.freeze()
    }
}

/// pingora's response compression module, the same in all but one thing:
/// the brotli streams it writes are finished. It holds pingora's context,
/// and is handed to the plugins as that context.
pub struct ResponseCompression {
    ctx: ResponseCompressionCtx,
    /// Set once the body shows it is compressed by pingora's brotli
    /// encoder, while that encoder leaves its streams unfinished.
    tail: Option<BrotliTail>,
}

impl Deref for ResponseCompression {
    type Target = ResponseCompressionCtx;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl DerefMut for ResponseCompression {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}

impl ResponseCompression {
    fn new(level: u32) -> Self {
        Self {
            ctx: ResponseCompressionCtx::new(level, false, false),
            tail: None,
        }
    }

    /// What the context gave for the body, finished where it is brotli.
    fn finish(&mut self, out: Option<Bytes>, end: bool) -> Option<Bytes> {
        if self.tail.is_none()
            && self
                .ctx
                .get_info()
                .is_some_and(|(name, ..)| name == PINGORA_BROTLI)
            && brotli_needs_tail()
        {
            self.tail = Some(BrotliTail::default());
        }
        match &mut self.tail {
            Some(tail) => Some(tail.apply(out.unwrap_or_default(), end)),
            None => out,
        }
    }
}

#[async_trait]
impl HttpModule for ResponseCompression {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    async fn request_header_filter(
        &mut self,
        req: &mut RequestHeader,
    ) -> pingora::Result<()> {
        self.ctx.request_filter(req);
        Ok(())
    }

    async fn response_header_filter(
        &mut self,
        resp: &mut ResponseHeader,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        self.ctx.response_header_filter(resp, end_of_stream);
        Ok(())
    }

    fn response_body_filter(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if !self.ctx.is_enabled() {
            return Ok(());
        }
        let compressed =
            self.ctx.response_body_filter(body.as_ref(), end_of_stream);
        if let Some(compressed) = self.finish(compressed, end_of_stream) {
            *body = Some(compressed);
        }
        Ok(())
    }

    /// The end of a response that did not end in its body: what is left of
    /// the stream, and its end.
    fn response_done_filter(&mut self) -> pingora::Result<Option<Bytes>> {
        if !self.ctx.is_enabled() {
            return Ok(None);
        }
        let compressed = self.ctx.response_body_filter(None, true);
        Ok(self.finish(compressed, true))
    }
}

/// The builder of [`ResponseCompression`], in place of pingora's.
pub struct ResponseCompressionBuilder {
    level: u32,
}

impl ResponseCompressionBuilder {
    /// The module with `level` for every algorithm, 0 being off: the
    /// plugins set the level of each per request.
    pub fn enable(level: u32) -> ModuleBuilder {
        Box::new(ResponseCompressionBuilder { level })
    }
}

impl HttpModuleBuilder for ResponseCompressionBuilder {
    fn init(&self) -> Module {
        Box::new(ResponseCompression::new(self.level))
    }

    /// Where pingora runs its own: later than most other filters.
    fn order(&self) -> i16 {
        i16::MIN / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// What the stream decodes to, if it is one whole brotli stream and
    /// nothing after it, as `brotli -t` takes it: `Decompressor` stops
    /// reading at the end and says nothing of a second end after it.
    fn decode(stream: &[u8]) -> Option<Vec<u8>> {
        use brotli::{
            BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc,
            HuffmanCode,
        };
        let mut state = BrotliState::new(
            HeapAlloc::<u8>::new(0),
            HeapAlloc::<u32>::new(0),
            HeapAlloc::<HuffmanCode>::new(HuffmanCode::default()),
        );
        let (mut available_in, mut input_offset) = (stream.len(), 0);
        let mut buf = vec![0; 65_536];
        let mut out = vec![];
        loop {
            let (mut available_out, mut output_offset, mut total) =
                (buf.len(), 0, 0);
            let result = BrotliDecompressStream(
                &mut available_in,
                &mut input_offset,
                stream,
                &mut available_out,
                &mut output_offset,
                &mut buf,
                &mut total,
                &mut state,
            );
            out.extend_from_slice(&buf[..output_offset]);
            match result {
                BrotliResult::NeedsMoreOutput => continue,
                BrotliResult::ResultSuccess => {
                    return (available_in == 0).then_some(out);
                },
                // the input ran out before the end, or is no brotli
                _ => return None,
            }
        }
    }

    /// The decoder of these tests refuses what `Decompressor` lets by:
    /// bytes after the end of the stream.
    #[test]
    fn test_decode_is_strict() {
        let mut encoder = Algorithm::Brotli.compressor(5).unwrap();
        let mut whole = encoder.encode(b"pingap", true).unwrap().to_vec();
        whole.push(LAST_EMPTY_META_BLOCK);
        assert_eq!(Some(b"pingap".to_vec()), decode(&whole));
        whole.push(LAST_EMPTY_META_BLOCK);
        assert_eq!(None, decode(&whole));
        let mut out = vec![];
        assert_eq!(
            true,
            brotli::Decompressor::new(whole.as_slice(), 4096)
                .read_to_end(&mut out)
                .is_ok()
        );
    }

    /// The text of a page, long enough for several calls of the encoder.
    fn page() -> Vec<u8> {
        (0..20_000)
            .map(|i| format!("upstream {i} location /api/{} ", i % 97))
            .collect::<String>()
            .into_bytes()
    }

    /// The tripwire: pingora 0.9.0 leaves its brotli streams unfinished.
    /// When this fails, pingora finishes them itself: delete this module,
    /// put pingora's `ResponseCompressionBuilder` and `ResponseCompression`
    /// back in pingap-proxy and pingap-plugin, drop `BrotliTail` from the
    /// compressor of the plugin's upstream mode, and the `brotli`
    /// dependency (see CLAUDE.md).
    #[test]
    fn test_pingora_still_leaves_brotli_unfinished() {
        assert_eq!(true, brotli_needs_tail());
    }

    /// pingora's encoder, chunk by chunk, with the tail: a whole stream
    /// that decodes to the input. Without it, a strict decoder refuses it.
    #[test]
    fn test_brotli_tail_finishes_the_stream() {
        let input = page();
        for size in [1, 4096, 65_536, input.len()] {
            let mut encoder = Algorithm::Brotli.compressor(5).unwrap();
            let mut tail = BrotliTail::default();
            let mut raw = vec![];
            let mut sent = vec![];
            let chunks: Vec<&[u8]> = input.chunks(size).collect();
            for (index, chunk) in chunks.iter().enumerate() {
                let end = index == chunks.len() - 1;
                let out = encoder.encode(chunk, end).unwrap();
                raw.extend_from_slice(&out);
                sent.extend_from_slice(&tail.apply(out, end));
            }
            assert_eq!(None, decode(&raw), "chunks of {size}");
            assert_eq!(Some(input.clone()), decode(&sent), "chunks of {size}");
            // and nothing after the end
            assert_eq!(
                Bytes::new(),
                tail.apply(Bytes::from_static(b"x"), true)
            );
        }
    }

    /// A body with nothing in it is a whole stream as well: what the
    /// encoder writes for no input and the end, and with no call of the
    /// encoder at all (nothing went by), the empty stream.
    #[test]
    fn test_brotli_tail_of_an_empty_body() {
        let mut encoder = Algorithm::Brotli.compressor(5).unwrap();
        let mut tail = BrotliTail::default();
        let sent = tail.apply(encoder.encode(b"", true).unwrap(), true);
        assert_eq!(Some(vec![]), decode(&sent));

        let mut tail = BrotliTail::default();
        assert_eq!(Some(vec![]), decode(&tail.apply(Bytes::new(), true)));
    }

    async fn run(
        module: &mut ResponseCompression,
        accept: &str,
        encoding: Option<&str>,
        body: &[u8],
        chunk: usize,
        end_in_done: bool,
    ) -> (Option<String>, Vec<u8>) {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Accept-Encoding", accept).unwrap();
        module.ctx.adjust_algorithm_level(Algorithm::Brotli, 5);
        module.request_header_filter(&mut req).await.unwrap();
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "text/html").unwrap();
        if let Some(encoding) = encoding {
            resp.insert_header("Content-Encoding", encoding).unwrap();
        }
        module
            .response_header_filter(&mut resp, false)
            .await
            .unwrap();
        let mut sent = vec![];
        let chunks: Vec<&[u8]> = body.chunks(chunk).collect();
        for (index, part) in chunks.iter().enumerate() {
            let end = !end_in_done && index == chunks.len() - 1;
            let mut data = Some(Bytes::copy_from_slice(part));
            module.response_body_filter(&mut data, end).unwrap();
            sent.extend_from_slice(&data.unwrap_or_default());
        }
        if let Some(rest) = module.response_done_filter().unwrap() {
            sent.extend_from_slice(&rest);
        }
        let encoding = resp
            .headers
            .get("Content-Encoding")
            .map(|value| value.to_str().unwrap().to_string());
        (encoding, sent)
    }

    /// The module compresses as pingora's does and finishes the stream,
    /// whether the response ends in its body or in the done filter, and
    /// leaves alone a body that came compressed.
    #[tokio::test]
    async fn test_response_compression_finishes_brotli() {
        let input = page();
        for end_in_done in [false, true] {
            let mut module = ResponseCompression::new(0);
            let (encoding, sent) =
                run(&mut module, "br", None, &input, 16_384, end_in_done).await;
            assert_eq!(Some("br".to_string()), encoding);
            assert_eq!(Some(input.clone()), decode(&sent), "{end_in_done}");
        }

        // A stream the upstream finished itself is passed on as it is.
        let mut encoder = Algorithm::Brotli.compressor(5).unwrap();
        let mut whole = encoder.encode(&input, true).unwrap().to_vec();
        whole.push(LAST_EMPTY_META_BLOCK);
        let mut module = ResponseCompression::new(0);
        let (encoding, sent) =
            run(&mut module, "br", Some("br"), &whole, 4096, false).await;
        assert_eq!(Some("br".to_string()), encoding);
        assert_eq!(whole, sent);

        // Decoded by pingora for a client that takes no br (the plugin's
        // `decompression`): the text, with no byte of brotli after it.
        let mut module = ResponseCompression::new(0);
        module.ctx.adjust_decompression(true);
        let (encoding, sent) =
            run(&mut module, "identity", Some("br"), &whole, 4096, false).await;
        assert_eq!(None, encoding);
        assert_eq!(input, sent);
        assert_eq!(true, module.tail.is_none());

        // gzip is pingora's as ever
        let mut module = ResponseCompression::new(0);
        module.ctx.adjust_algorithm_level(Algorithm::Gzip, 6);
        let (encoding, _) =
            run(&mut module, "gzip", None, &input, 16_384, false).await;
        assert_eq!(Some("gzip".to_string()), encoding);
        assert_eq!(true, module.tail.is_none());
    }
}
