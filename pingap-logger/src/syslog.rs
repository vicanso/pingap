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
use pingap_core::get_hostname;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use syslog::{
    Facility, Formatter3164, Formatter5424, LogFormat, LoggerBackend, Severity,
};
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriter};

type Result<T, E = Error> = std::result::Result<T, E>;

const DEFAULT_PORT: u16 = 514;
/// Connect and write timeout for a TCP syslog server: a stalled server must
/// not hold up the threads that log for long.
const TCP_TIMEOUT: Duration = Duration::from_secs(1);
/// How long messages are dropped after a syslog server or socket could not
/// be reached, before the next connection attempt.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

enum Formatter {
    Rfc3164(Formatter3164),
    Rfc5424(Formatter5424),
}

impl Formatter {
    fn format(&self, buf: &mut Vec<u8>, message: &str) -> syslog::Result<()> {
        match self {
            Self::Rfc3164(f) => f.format(buf, Severity::LOG_INFO, message),
            Self::Rfc5424(f) => {
                f.format(buf, Severity::LOG_INFO, (0, BTreeMap::new(), message))
            },
        }
    }
}

/// A TCP syslog server, connected on the first message and again after a
/// failure.
struct TcpTransport {
    server: String,
    stream: Option<TcpStream>,
    retry_at: Option<Instant>,
}

fn connect_tcp(server: &str) -> io::Result<TcpStream> {
    let mut last_error =
        io::Error::new(io::ErrorKind::NotFound, "no address resolved");
    for addr in server.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, TCP_TIMEOUT) {
            Ok(stream) => {
                stream.set_write_timeout(Some(TCP_TIMEOUT))?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            },
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

impl TcpTransport {
    /// Sends one framed message. While the server is unreachable messages
    /// are dropped and a reconnect is tried every `RETRY_INTERVAL`. Failures go
    /// to stderr: this is a log writer, it has no log to report them to.
    fn send(&mut self, message: &[u8]) {
        if self.stream.is_none() {
            if self.retry_at.is_some_and(|at| Instant::now() < at) {
                return;
            }
            match connect_tcp(&self.server) {
                Ok(stream) => {
                    self.stream = Some(stream);
                    self.retry_at = None;
                },
                Err(e) => {
                    self.retry_at = Some(Instant::now() + RETRY_INTERVAL);
                    eprintln!(
                        "syslog server {} is unreachable, dropping messages for {}s: {e}",
                        self.server,
                        RETRY_INTERVAL.as_secs()
                    );
                    return;
                },
            }
        }
        if let Some(stream) = &mut self.stream
            && let Err(e) = stream.write_all(message)
        {
            self.stream = None;
            eprintln!(
                "syslog server {} write fail, reconnecting: {e}",
                self.server
            );
        }
    }
}

/// The socket at `path`, or the local daemon's usual one when there is no
/// path.
fn connect_unix(path: &str) -> syslog::Result<LoggerBackend> {
    // The formatter is only needed to build the logger; messages are
    // formatted by `SyslogSender`.
    let formatter = Formatter3164::default();
    let logger = if path.len() <= 1 {
        syslog::unix(formatter)
    } else {
        syslog::unix_custom(formatter, path)
    }?;
    Ok(logger.backend)
}

/// A unix socket of the local syslog daemon, connected again after a
/// failure.
struct UnixTransport {
    path: String,
    backend: Option<LoggerBackend>,
    retry_at: Option<Instant>,
}

impl UnixTransport {
    /// Sends one message. A syslog daemon that is restarted leaves this end
    /// of the socket connected to nothing: every write failed from then on,
    /// and the log was gone until pingap itself was restarted. So a write
    /// that fails connects again and sends the message once more. While
    /// there is no daemon messages are dropped and a reconnect is tried
    /// every `RETRY_INTERVAL`. Failures go to stderr, as for TCP.
    fn send(&mut self, message: &[u8]) {
        if let Some(backend) = &mut self.backend {
            // One `write` per message: on a stream socket it also appends
            // the NUL that ends the message.
            if backend.write(message).is_ok() {
                return;
            }
            self.backend = None;
        } else if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        match connect_unix(&self.path) {
            Ok(mut backend) => {
                // The message that found the socket dead is sent again. If
                // it fails on the new one as well it is the message - too
                // long for a datagram - and not the socket, which is kept.
                if let Err(e) = backend.write(message) {
                    eprintln!("syslog message dropped: {e}");
                }
                self.backend = Some(backend);
                self.retry_at = None;
            },
            Err(e) => {
                self.retry_at = Some(Instant::now() + RETRY_INTERVAL);
                eprintln!(
                    "syslog socket {} is unreachable, dropping messages for {}s: {e}",
                    if self.path.is_empty() {
                        "of the local daemon"
                    } else {
                        &self.path
                    },
                    RETRY_INTERVAL.as_secs()
                );
            },
        }
    }
}

enum Transport {
    /// A unix socket of the local syslog daemon.
    Unix(UnixTransport),
    Udp {
        socket: UdpSocket,
        server: SocketAddr,
    },
    Tcp(TcpTransport),
}

/// Sends each line it is given to syslog as one message, at severity info.
pub(crate) struct SyslogSender {
    formatter: Formatter,
    transport: Transport,
    buf: Vec<u8>,
}

impl SyslogSender {
    pub(crate) fn send(&mut self, line: &[u8]) -> io::Result<()> {
        // syslog ends the message itself
        let line = line.trim_ascii_end();
        if line.is_empty() {
            return Ok(());
        }
        self.buf.clear();
        self.formatter
            .format(&mut self.buf, &String::from_utf8_lossy(line))
            .map_err(io::Error::other)?;
        match &mut self.transport {
            Transport::Unix(unix) => {
                unix.send(&self.buf);
                Ok(())
            },
            Transport::Udp { socket, server } => {
                socket.send_to(&self.buf, *server).map(|_| ())
            },
            Transport::Tcp(tcp) => {
                // Newline framing (RFC 6587), which every syslog server
                // reads; a newline inside would end the message early.
                for b in self.buf.iter_mut().filter(|b| **b == b'\n') {
                    *b = b' ';
                }
                self.buf.push(b'\n');
                tcp.send(&self.buf);
                Ok(())
            },
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct SyslogParams {
    format: Option<String>,
    process: Option<String>,
    facility: Option<String>,
    protocol: Option<String>,
}

/// `host` or `host:port`, an IPv6 address in brackets.
fn with_default_port(host: &str) -> String {
    let has_port = match host.rfind(']') {
        Some(end) => host[end..].contains(':'),
        None => host.contains(':'),
    };
    if has_port {
        host.to_string()
    } else {
        format!("{host}:{DEFAULT_PORT}")
    }
}

fn new_transport(location: &str, protocol: Option<&str>) -> Result<Transport> {
    let invalid = |message: String| Error::Invalid { message };
    // `syslog://` or `syslog:///`: the local daemon at its usual socket;
    // `syslog:///run/syslog.sock`: the socket at that path.
    if location.is_empty() || location.starts_with('/') {
        if protocol.is_some_and(|protocol| !protocol.is_empty()) {
            return Err(invalid(
                "syslog protocol only applies to a remote server".to_string(),
            ));
        }
        // Connected now, so a socket that is not there fails at startup.
        let path = if location.len() <= 1 { "" } else { location };
        let backend = connect_unix(path).map_err(|e| invalid(e.to_string()))?;
        return Ok(Transport::Unix(UnixTransport {
            path: path.to_string(),
            backend: Some(backend),
            retry_at: None,
        }));
    }
    let server = with_default_port(location.trim_end_matches('/'));
    let resolve = || {
        server
            .to_socket_addrs()
            .map_err(|e| invalid(format!("syslog server {server}: {e}")))?
            .next()
            .ok_or_else(|| {
                invalid(format!("syslog server {server}: no address"))
            })
    };
    match protocol.unwrap_or_default() {
        "" | "udp" => {
            let server = resolve()?;
            let local = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(local)
                .map_err(|e| invalid(format!("syslog udp socket: {e}")))?;
            Ok(Transport::Udp { socket, server })
        },
        "tcp" => {
            // Resolved now, so a typo fails at startup; connected on the
            // first message, so a server that is down does not keep pingap
            // from starting.
            resolve()?;
            Ok(Transport::Tcp(TcpTransport {
                server,
                stream: None,
                retry_at: None,
            }))
        },
        protocol => Err(invalid(format!(
            "syslog protocol {protocol} is invalid, expected udp or tcp"
        ))),
    }
}

/// `syslog://[host[:port]][/socket][?format=3164|5424&process=pingap&facility=LOG_USER&protocol=udp|tcp]`.
/// Without a host it is the local daemon; with one, a remote server over
/// UDP (default) or TCP, port 514 unless given. A parameter that does not
/// parse is an error, not silently the default.
pub(crate) fn new_syslog_sender(value: &str) -> Result<SyslogSender> {
    let (location, query) = value.split_once('?').unwrap_or((value, ""));
    let params: SyslogParams =
        serde_qs::from_str(query).map_err(|e| Error::Invalid {
            message: format!("syslog params {value} is invalid: {e}"),
        })?;

    let process = params.process.unwrap_or("pingap".to_string());
    let facility = match params.facility.as_deref() {
        None | Some("") => Facility::default(),
        Some(facility) => {
            Facility::from_str(facility).map_err(|_| Error::Invalid {
                message: format!("syslog facility {facility} is invalid"),
            })?
        },
    };
    let hostname = Some(get_hostname().to_string());
    let formatter = match params.format.as_deref() {
        Some("5424") => Formatter::Rfc5424(Formatter5424 {
            process,
            facility,
            hostname,
            ..Default::default()
        }),
        None | Some("") | Some("3164") => Formatter::Rfc3164(Formatter3164 {
            process,
            facility,
            hostname,
            ..Default::default()
        }),
        Some(format) => {
            return Err(Error::Invalid {
                message: format!(
                    "syslog format {format} is invalid, expected 3164 or 5424"
                ),
            });
        },
    };
    let location = location.strip_prefix("syslog://").unwrap_or(location);
    Ok(SyslogSender {
        formatter,
        transport: new_transport(location, params.protocol.as_deref())?,
        buf: Vec::with_capacity(256),
    })
}

/// The application log's writer: each event the subscriber writes is one
/// message.
struct SyslogWriter(Mutex<SyslogSender>);

struct SyslogWriterGuard<'a>(MutexGuard<'a, SyslogSender>);

impl<'a> MakeWriter<'a> for SyslogWriter {
    type Writer = SyslogWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        // A panic while holding the lock poisons it; the sender inside is
        // still usable.
        SyslogWriterGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl io::Write for SyslogWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn new_syslog_writer(value: &str) -> Result<BoxMakeWriter> {
    let sender = new_syslog_sender(value)?;
    Ok(BoxMakeWriter::new(SyslogWriter(Mutex::new(sender))))
}

#[cfg(test)]
mod tests {
    use super::{new_syslog_sender, new_syslog_writer, with_default_port};
    use pretty_assertions::assert_eq;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn test_invalid_params_are_rejected() {
        let err = new_syslog_writer("syslog://?format=9999")
            .expect_err("error")
            .to_string();
        assert_eq!(
            "Invalid syslog format 9999 is invalid, expected 3164 or 5424",
            err
        );
        let err = new_syslog_writer("syslog://?facility=LOG_NOPE")
            .expect_err("error")
            .to_string();
        assert_eq!("Invalid syslog facility LOG_NOPE is invalid", err);
        let err = new_syslog_writer("syslog://127.0.0.1?protocol=quic")
            .expect_err("error")
            .to_string();
        assert_eq!(
            "Invalid syslog protocol quic is invalid, expected udp or tcp",
            err
        );
        let err = new_syslog_writer("syslog://?protocol=tcp")
            .expect_err("error")
            .to_string();
        assert_eq!(
            "Invalid syslog protocol only applies to a remote server",
            err
        );
        // a socket path that does not exist
        assert_eq!(
            true,
            new_syslog_writer("syslog:///nonexistent/pingap.sock").is_err()
        );
    }

    #[test]
    fn test_with_default_port() {
        assert_eq!("10.0.0.1:514", with_default_port("10.0.0.1"));
        assert_eq!("10.0.0.1:1514", with_default_port("10.0.0.1:1514"));
        assert_eq!(
            "logs.example.com:514",
            with_default_port("logs.example.com")
        );
        assert_eq!("[::1]:514", with_default_port("[::1]"));
        assert_eq!("[::1]:1514", with_default_port("[::1]:1514"));
    }

    /// One datagram per line, priority user.info (14), RFC 5424 header.
    #[test]
    fn test_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let mut sender = new_syslog_sender(&format!(
            "syslog://127.0.0.1:{port}?format=5424&process=access"
        ))
        .unwrap();
        sender.send(b"GET / 200\n").unwrap();
        let mut buf = [0; 1024];
        let size = server.recv(&mut buf).unwrap();
        let message = std::str::from_utf8(&buf[..size]).unwrap();
        assert_eq!(true, message.starts_with("<14>1 "), "{message}");
        assert_eq!(true, message.contains(" access "), "{message}");
        assert_eq!(true, message.ends_with(" GET / 200"), "{message}");
    }

    /// Newline framed, with a newline inside a message turned into a
    /// space so it cannot split it.
    #[test]
    fn test_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut sender = new_syslog_sender(&format!(
            "syslog://127.0.0.1:{port}?protocol=tcp"
        ))
        .unwrap();
        sender.send(b"first\nline").unwrap();
        sender.send(b"second").unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut lines = BufReader::new(stream).lines();
        let first = lines.next().unwrap().unwrap();
        assert_eq!(true, first.starts_with("<14>"), "{first}");
        assert_eq!(true, first.ends_with("]: first line"), "{first}");
        let second = lines.next().unwrap().unwrap();
        assert_eq!(true, second.ends_with("]: second"), "{second}");
    }

    /// Regression: after the syslog daemon was restarted the socket was
    /// connected to nothing, every write failed, and nothing connected
    /// again.
    #[cfg(unix)]
    #[test]
    fn test_unix_socket_is_connected_again() {
        use std::os::unix::net::UnixDatagram;

        // Short on purpose: a socket path is capped at about 100 bytes.
        let path = format!("/tmp/pingap-syslog-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&path);
        let receive = |server: &UnixDatagram| {
            server
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut buf = [0u8; 512];
            let size = server.recv(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[..size]).into_owned()
        };

        let server = UnixDatagram::bind(&path).unwrap();
        let mut sender =
            new_syslog_sender(&format!("syslog://{path}")).unwrap();
        sender.send(b"first").unwrap();
        assert_eq!(true, receive(&server).ends_with("first"));

        // The daemon goes away and comes back at the same path.
        drop(server);
        std::fs::remove_file(&path).unwrap();
        // Nobody there: the message is dropped, the send does not fail.
        sender.send(b"lost").unwrap();
        let server = UnixDatagram::bind(&path).unwrap();
        // Inside the retry interval nothing is tried.
        sender.send(b"dropped").unwrap();
        let super::Transport::Unix(unix) = &mut sender.transport else {
            panic!("not a unix transport");
        };
        assert_eq!(true, unix.backend.is_none());
        unix.retry_at = None;
        sender.send(b"second").unwrap();
        assert_eq!(true, receive(&server).ends_with("second"));
        // And the connection is kept for what follows.
        sender.send(b"third").unwrap();
        assert_eq!(true, receive(&server).ends_with("third"));

        drop(server);
        let _ = std::fs::remove_file(&path);
    }

    /// A TCP server that is down does not fail startup or a send; messages
    /// are dropped until the retry delay has passed.
    #[test]
    fn test_tcp_unreachable() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut sender = new_syslog_sender(&format!(
            "syslog://127.0.0.1:{port}?protocol=tcp"
        ))
        .unwrap();
        sender.send(b"dropped").unwrap();
        let super::Transport::Tcp(tcp) = &sender.transport else {
            panic!("tcp transport");
        };
        assert_eq!(true, tcp.stream.is_none());
        assert_eq!(true, tcp.retry_at.is_some());
    }
}
