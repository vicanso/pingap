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

/// The absolute path of a `unix:` address, or `None` when `addr` is not one.
///
/// `addr` is the address alone, without a weight and without surrounding
/// whitespace. A socket is written `unix:/absolute/path`. `unix:80` is not
/// one: that is the host `unix` on port 80, and it is left to the TCP
/// parser. A path must be absolute. An abstract name (`unix:@name`) and a
/// path that contains whitespace are rejected. On a build without unix
/// sockets every `unix:/` address is rejected.
///
/// # Errors
///
/// A `unix:` address this build cannot use, with the reason.
pub fn unix_socket_path(addr: &str) -> Result<Option<&str>, String> {
    let Some(path) = addr.strip_prefix("unix:") else {
        return Ok(None);
    };
    if path.starts_with('@') {
        return Err("abstract unix sockets are not supported".to_string());
    }
    // `unix:80` and any other relative spelling stay TCP addresses.
    if !path.starts_with('/') {
        return Ok(None);
    }
    if path.contains(char::is_whitespace) {
        return Err("unix socket path contains whitespace".to_string());
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err("unix sockets are not available on this build".to_string());
    }
    #[cfg(unix)]
    {
        std::os::unix::net::SocketAddr::from_pathname(path)
            .map_err(|e| format!("unix socket path is invalid: {e}"))?;
        Ok(Some(path))
    }
}

#[cfg(test)]
mod tests {
    use super::unix_socket_path;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_unix_socket_path() {
        assert_eq!(Ok(None), unix_socket_path("127.0.0.1:8080"));
        assert_eq!(Ok(None), unix_socket_path("[::1]:8080"));
        // The host `unix`, not a socket.
        assert_eq!(Ok(None), unix_socket_path("unix:80"));
        assert_eq!(Ok(None), unix_socket_path("unix:./app.sock"));
        assert_eq!(Ok(None), unix_socket_path(""));

        match unix_socket_path("unix:@app") {
            Err(message) => {
                assert_eq!("abstract unix sockets are not supported", message);
            },
            Ok(path) => panic!("abstract socket accepted: {path:?}"),
        }
        match unix_socket_path("unix:/tmp/my app.sock") {
            Err(message) => {
                assert_eq!("unix socket path contains whitespace", message);
            },
            Ok(path) => panic!("path with a space accepted: {path:?}"),
        }

        #[cfg(unix)]
        match unix_socket_path("unix:/tmp/pingap.sock") {
            Ok(Some(path)) => assert_eq!("/tmp/pingap.sock", path),
            other => panic!("expected the path, got {other:?}"),
        }
        #[cfg(not(unix))]
        match unix_socket_path("unix:/tmp/pingap.sock") {
            Err(message) => assert_eq!(
                "unix sockets are not available on this build",
                message
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
