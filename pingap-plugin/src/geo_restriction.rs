// Copyright 2026 Zsombor Gegesy.
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

use super::{
    Error, get_duration_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_verified_client_ip, now_sec, protect_from_connection_header,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, SystemTime};
use tor_geoip::GeoipDb;
use tracing::{debug, info, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "geo_restriction";

static GEO_DB: LazyLock<Arc<GeoipDb>> = LazyLock::new(GeoipDb::new_embedded);

/// How often a database file is looked at for a change, where nothing
/// else is said.
const DEFAULT_DATABASE_REFRESH: Duration = Duration::from_secs(60);

/// A database of the MaxMind DB format (`.mmdb`), read from a file and
/// read again when the file changes.
///
/// The data that is built into the binary is as old as the release. A
/// file is as new as whoever provides it keeps it: `geoipupdate`, a cron
/// job, a volume that is mounted.
struct DatabaseFile {
    path: String,
    reader: ArcSwap<maxminddb::Reader<Vec<u8>>>,
    /// When the file that is loaded was written.
    modified: Mutex<Option<SystemTime>>,
    /// The file was not there when it was last looked at: said in the
    /// log when that begins, not at every look.
    missing: AtomicBool,
}

/// When a plugin looks at its database file: every so often, by a count
/// of its own.
///
/// Not kept with the file, which the plugins that name it share. An
/// interval kept there was that of whoever opened the file last, and a
/// plugin that is only built to check a configuration - the admin does
/// that before it saves, a reload before it applies - opened it too: a
/// value that was never put into effect became the interval of the
/// plugins that run, and each such check put the next look off again.
struct Refresh {
    /// In seconds.
    interval: u64,
    /// The time, in seconds, of the next look.
    next: AtomicU64,
}

impl Refresh {
    fn new(interval: Duration) -> Self {
        let interval = interval.as_secs().max(1);
        Self {
            interval,
            next: AtomicU64::new(now_sec() + interval),
        }
    }

    /// Whether the file is to be looked at now: once for each interval,
    /// whoever asks first.
    fn is_due(&self, now: u64) -> bool {
        let next = self.next.load(Ordering::Relaxed);
        now >= next
            && self
                .next
                .compare_exchange(
                    next,
                    now + self.interval,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }
}

/// The database files that are loaded, by path: the plugins that name
/// the same file read the same copy of it, however many there are.
static DATABASES: LazyLock<Mutex<AHashMap<String, Weak<DatabaseFile>>>> =
    LazyLock::new(|| Mutex::new(AHashMap::new()));

fn modified_of(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

impl DatabaseFile {
    /// The database at `path`: the one that is loaded already, or a new
    /// one. An error says what is wrong with the file.
    fn open(path: &str) -> Result<Arc<Self>, String> {
        let mut databases = DATABASES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        databases.retain(|_, database| database.strong_count() > 0);
        if let Some(database) =
            databases.get(path).and_then(|database| database.upgrade())
        {
            return Ok(database);
        }
        let modified = modified_of(path);
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| format!("database {path} can not be read: {e}"))?;
        let database = Arc::new(Self {
            path: path.to_string(),
            reader: ArcSwap::from_pointee(reader),
            modified: Mutex::new(modified),
            missing: AtomicBool::new(false),
        });
        databases.insert(path.to_string(), Arc::downgrade(&database));
        Ok(database)
    }

    /// The country of `addr`, in upper case. A record names it as
    /// `country.iso_code` (MaxMind, DB-IP), or flat, as `country_code` or
    /// `country`.
    fn country(&self, addr: IpAddr) -> Option<String> {
        let reader = self.reader.load();
        let record = reader.lookup(addr).ok()?;
        if !record.has_data() {
            return None;
        }
        let paths: [&[maxminddb::PathElement]; 3] = [
            &maxminddb::path!["country", "iso_code"],
            &maxminddb::path!["country_code"],
            &maxminddb::path!["country"],
        ];
        paths.iter().find_map(|path| {
            // An error is a value of another kind there: a `country`
            // that is a map of names, say.
            record
                .decode_path::<String>(path)
                .ok()
                .flatten()
                .filter(|code| {
                    code.len() == 2
                        && code.bytes().all(|c| c.is_ascii_alphabetic())
                })
                .map(|code| code.to_ascii_uppercase())
        })
    }

    /// Reads the file again where it has changed. A file that can not
    /// be read - one that is being written, or is no database - leaves
    /// the one that is loaded in place, and is tried again next time.
    fn reload_if_changed(&self) {
        let modified = modified_of(&self.path);
        let mut loaded = self
            .modified
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if modified.is_none() {
            // Once, when it goes missing: looked at every second, it
            // would be a line a second for as long as it is gone.
            if !self.missing.swap(true, Ordering::Relaxed) {
                warn!(
                    category = CATEGORY,
                    path = self.path,
                    "geo database is not there, the loaded one is kept"
                );
            }
            return;
        }
        self.missing.store(false, Ordering::Relaxed);
        if modified == *loaded {
            return;
        }
        match maxminddb::Reader::open_readfile(&self.path) {
            Ok(reader) => {
                info!(
                    category = CATEGORY,
                    path = self.path,
                    build_epoch = reader.metadata().build_epoch,
                    "geo database reloaded"
                );
                self.reader.store(Arc::new(reader));
                *loaded = modified;
            },
            Err(e) => {
                warn!(
                    category = CATEGORY,
                    path = self.path,
                    error = %e,
                    "geo database can not be reloaded, the loaded one is kept"
                );
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionCategory {
    Deny,
    Allow,
    Reporting,
}

impl TryFrom<&str> for RestrictionCategory {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "deny" => Ok(RestrictionCategory::Deny),
            "allow" => Ok(RestrictionCategory::Allow),
            "reporting" => Ok(RestrictionCategory::Reporting),
            _ => Err(format!("invalid restriction category: {value}")),
        }
    }
}

pub struct GeoRestriction {
    plugin_step: PluginStep,
    country_codes: Vec<String>,
    restriction_category: RestrictionCategory,
    forbidden_resp: HttpResponse,
    /// The database of a file, in place of the one that is built in.
    database: Option<Arc<DatabaseFile>>,
    /// When this plugin looks at that file for a change.
    refresh: Refresh,
    /// The request header the upstream is told the country in.
    header: Option<HeaderName>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for GeoRestriction {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

        let raw_codes = get_str_slice_conf(value, "country_codes");
        let country_codes: Vec<String> = raw_codes
            .iter()
            .flat_map(|s| s.split([' ', ',']))
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_uppercase())
            .collect();

        for code in &country_codes {
            if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic())
            {
                return Err(Error::Invalid {
                    category: "geo_restriction".to_string(),
                    message: format!(
                        "invalid country code '{}': must be exactly 2 ASCII letters",
                        code
                    ),
                });
            }
        }

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Access from your country is not allowed".to_string();
        }

        let category_str = get_str_conf(value, "type");
        let restriction_category =
            category_str.as_str().try_into().map_err(|e: String| {
                Error::Invalid {
                    category: "geo_restriction".to_string(),
                    message: e,
                }
            })?;

        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let header = get_str_conf(value, "header");
        let header = if header.trim().is_empty() {
            None
        } else {
            Some(HeaderName::from_bytes(header.trim().as_bytes()).map_err(
                |_| invalid(format!("header: {header:?} is not a header name")),
            )?)
        };
        let refresh = get_duration_conf(value, "database_refresh")
            .unwrap_or(DEFAULT_DATABASE_REFRESH);
        if refresh < Duration::from_secs(1) {
            return Err(invalid(
                "database_refresh should be at least 1s".to_string(),
            ));
        }
        let database = get_str_conf(value, "database");
        let database = if database.trim().is_empty() {
            None
        } else {
            let path = pingap_util::resolve_path(database.trim());
            Some(DatabaseFile::open(&path).map_err(invalid)?)
        };

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            country_codes,
            restriction_category,
            database,
            refresh: Refresh::new(refresh),
            header,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };

        Ok(params)
    }
}

impl GeoRestriction {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new geo restriction plugin"
        );
        let result = Self::try_from(params)?;
        // The data that is built in is unpacked once, and not at all
        // where a file is read in its place.
        if result.database.is_none() {
            LazyLock::force(&GEO_DB);
        }
        info!(
            country_codes = ?result.country_codes,
            restriction_category = ?result.restriction_category,
            "geo restriction plugin configured"
        );
        Ok(result)
    }
}

#[async_trait]
impl Plugin for GeoRestriction {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // By an address the client cannot choose, see `ip_restriction`:
        // the country of whatever `X-Forwarded-For` claimed was the
        // country the client picked.
        let ip = ensure_verified_client_ip(session, ctx);

        // `::ffff:1.2.3.4` is looked up as `1.2.3.4`: as an IPv6 address
        // it has no country. Something that is no address has none either,
        // and is judged like any other unknown: it used to be let through
        // whatever the list said, an allow list included.
        let addr = ip.parse::<IpAddr>().ok().map(|addr| addr.to_canonical());
        let country_code: Option<Cow<'_, str>> = match &self.database {
            Some(database) => {
                // The file is looked at now and then, off the request:
                // reading a database takes its time.
                if self.refresh.is_due(now_sec()) {
                    let database = database.clone();
                    tokio::task::spawn_blocking(move || {
                        database.reload_if_changed()
                    });
                }
                addr.and_then(|addr| database.country(addr)).map(Cow::Owned)
            },
            None => addr
                .and_then(|addr| GEO_DB.lookup_country_code(addr))
                .map(|code| Cow::Borrowed(code.as_ref())),
        };
        let country_code_str = country_code.as_deref().unwrap_or("??");

        // What the upstream is told is what was found here and nothing
        // else: a header of that name the client sent is taken off, also
        // where no country is known, and the client can not have it
        // taken off again by naming it in `Connection`.
        if let Some(name) = &self.header {
            let req_header = session.req_header_mut();
            req_header.remove_header(name);
            if let Some(code) = &country_code {
                let _ = req_header.insert_header(name.clone(), code.as_ref());
                protect_from_connection_header(
                    req_header,
                    std::slice::from_ref(name),
                );
            }
        }

        if self.restriction_category == RestrictionCategory::Reporting {
            info!(ip = %ip, country = %country_code_str, "geoip lookup");
            return Ok(RequestPluginResult::Continue);
        }

        let found = self.country_codes.iter().any(|cc| cc == country_code_str);

        let allow = if self.restriction_category == RestrictionCategory::Deny {
            !found
        } else {
            found
        };

        if !allow {
            return Ok(RequestPluginResult::Respond(
                self.forbidden_resp.clone(),
            ));
        }

        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("geo_restriction", GeoRestriction);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::Ctx;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_geo_restriction_params() {
        let params = GeoRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
country_codes = ["CN", "US"]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(vec!["CN", "US"], params.country_codes);
        assert_eq!(RestrictionCategory::Deny, params.restriction_category);
    }

    #[tokio::test]
    async fn test_geo_restriction_continue() {
        let geo = GeoRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "deny"
country_codes = ["CN", "RU"]
message = "Country not allowed"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert!(allowed(&geo, "8.8.8.8").await);
    }

    /// Whether a request from the peer `peer` is let through. No trusted
    /// proxies are configured in a unit test, so the peer's address is the
    /// one that is looked up.
    async fn allowed(geo: &GeoRestriction, peer: &str) -> bool {
        allowed_with(geo, peer, "").await
    }

    async fn allowed_with(
        geo: &GeoRestriction,
        peer: &str,
        headers: &str,
    ) -> bool {
        let input = format!("GET /vicanso/pingap HTTP/1.1\r\n{headers}\r\n");
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some(peer.to_string());
        let result = geo
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        result == RequestPluginResult::Continue
    }

    /// Regression: without trusted proxies the country was that of
    /// whatever address the request claimed, so the client picked it.
    #[tokio::test]
    async fn test_geo_restriction_ignores_a_forged_address() {
        // 8.8.8.8 is in the US; 127.0.0.1 has no country.
        let allow = new_geo("allow");
        for headers in
            ["X-Forwarded-For: 8.8.8.8\r\n", "X-Real-IP: 8.8.8.8\r\n"]
        {
            assert!(
                !allowed_with(&allow, "127.0.0.1", headers).await,
                "{headers}"
            );
        }
        let deny = new_geo("deny");
        assert!(
            !allowed_with(&deny, "8.8.8.8", "X-Forwarded-For: 127.0.0.1\r\n")
                .await
        );
    }

    fn new_geo(kind: &str) -> GeoRestriction {
        GeoRestriction::new(
            &toml::from_str::<PluginConf>(&format!(
                "type = \"{kind}\"\ncountry_codes = [\"US\"]"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// Regression: an IPv4 client of a dual-stack listener has the address
    /// `::ffff:a.b.c.d`. Looked up as an IPv6 address it had no country,
    /// so a deny list let it in.
    #[tokio::test]
    async fn test_geo_restriction_ipv4_mapped_address() {
        let deny = new_geo("deny");
        assert!(!allowed(&deny, "8.8.8.8").await);
        assert!(!allowed(&deny, "::ffff:8.8.8.8").await);
        let allow = new_geo("allow");
        assert!(allowed(&allow, "8.8.8.8").await);
        assert!(allowed(&allow, "::ffff:8.8.8.8").await);
    }

    /// Regression: a client ip that is no address was let through whatever
    /// the list said. It has no country, like any address the database
    /// does not know: outside an allow list, and not on a deny list.
    #[tokio::test]
    async fn test_geo_restriction_unparsable_address() {
        let allow = new_geo("allow");
        for client_ip in ["unknown", "", "8.8.8.8, 1.1.1.1"] {
            assert!(!allowed(&allow, client_ip).await, "{client_ip}");
        }
        assert!(allowed(&new_geo("deny"), "unknown").await);
    }

    /// A test database: `1.2.3.0/24` is AU (NZ in the second file),
    /// `9.9.9.0/24` US, `2001:db8::/32` DE, as `country.iso_code`;
    /// `203.0.113.0/24` FR as `country_code`; `198.51.100.0/24` jp as
    /// `country`; `192.0.2.0/24` has a record without a country. Written
    /// with github.com/maxmind/mmdbwriter.
    fn fixture(name: &str) -> String {
        format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Whether a request from `peer` is let through, and the country the
    /// upstream is told. The request comes with a country of its own
    /// making, and asks for it to be dropped on the way.
    async fn judged(
        geo: &GeoRestriction,
        peer: &str,
    ) -> (bool, Option<String>) {
        let input = "GET /vicanso/pingap HTTP/1.1\r\nX-Geo-Country: XX\r\nConnection: x-geo-country\r\n\r\n";
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some(peer.to_string());
        let result = geo
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        let header = session.req_header();
        let country = header
            .headers
            .get("x-geo-country")
            .map(|value| value.to_str().unwrap().to_string());
        // What is set is not on the list of what the client wants gone.
        if country.is_some() {
            let connection = header
                .headers
                .get("connection")
                .map(|value| value.to_str().unwrap().to_lowercase())
                .unwrap_or_default();
            assert_eq!(false, connection.contains("x-geo-country"));
        }
        (result == RequestPluginResult::Continue, country)
    }

    /// `database`: the countries of a file, in place of those that are
    /// built in. `header`: the upstream is told the country.
    #[tokio::test]
    async fn test_geo_restriction_database_and_header() {
        let geo = GeoRestriction::new(
            &toml::from_str::<PluginConf>(&format!(
                "type = \"allow\"\ncountry_codes = [\"AU\", \"DE\", \"FR\", \"JP\"]\ndatabase = \"{}\"\nheader = \"X-Geo-Country\"",
                fixture("geo-test.mmdb")
            ))
            .unwrap(),
        )
        .unwrap();
        for (peer, allowed, country) in [
            ("1.2.3.4", true, Some("AU")),
            ("::ffff:1.2.3.4", true, Some("AU")),
            ("2001:db8::1", true, Some("DE")),
            // a flat record, and one in lower case
            ("203.0.113.9", true, Some("FR")),
            ("198.51.100.9", true, Some("JP")),
            ("9.9.9.9", false, Some("US")),
            // a record that names no country, an address the file does
            // not have (the data that is built in does), and no address
            ("192.0.2.1", false, None),
            ("8.8.8.8", false, None),
            ("unknown", false, None),
        ] {
            assert_eq!(
                (allowed, country.map(str::to_string)),
                judged(&geo, peer).await,
                "{peer}"
            );
        }

        // With the data that is built in the header is set the same way.
        let geo = GeoRestriction::new(
            &toml::from_str::<PluginConf>(
                "type = \"reporting\"\nheader = \"x-geo-country\"",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (true, Some("US".to_string())),
            judged(&geo, "8.8.8.8").await
        );
        assert_eq!((true, None), judged(&geo, "127.0.0.1").await);

        for (conf, message) in [
            ("type = \"deny\"\nheader = \"x y\"", "is not a header name"),
            (
                "type = \"deny\"\ndatabase = \"/nowhere/geo.mmdb\"",
                "database /nowhere/geo.mmdb can not be read",
            ),
            (
                "type = \"deny\"\ndatabase_refresh = \"100ms\"",
                "database_refresh should be at least 1s",
            ),
        ] {
            let error = GeoRestriction::new(
                &toml::from_str::<PluginConf>(conf).unwrap(),
            )
            .err()
            .unwrap()
            .to_string();
            assert_eq!(true, error.contains(message), "{conf}: {error}");
        }
    }

    /// The file is read again when it has changed, and one that can not
    /// be read leaves the database that is loaded where it is.
    #[test]
    fn test_geo_database_follows_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geo.mmdb");
        let path_text = path.to_str().unwrap();
        std::fs::copy(fixture("geo-test.mmdb"), &path).unwrap();
        let database = DatabaseFile::open(path_text).unwrap();
        let country = |database: &DatabaseFile| {
            database.country("1.2.3.4".parse().unwrap())
        };
        assert_eq!(Some("AU".to_string()), country(&database));
        // Whoever names the same file reads the same copy of it.
        assert_eq!(
            true,
            Arc::ptr_eq(&database, &DatabaseFile::open(path_text).unwrap())
        );

        // Looked at once for each interval, by the count of the plugin
        // that looks: another plugin on the same file, with another
        // interval, has a count of its own. Kept with the file, the
        // interval was that of whoever had opened it last - a plugin
        // that was only built to check a configuration among them.
        let now = now_sec();
        let minute = Refresh::new(Duration::from_secs(60));
        assert_eq!(false, minute.is_due(now));
        assert_eq!(true, minute.is_due(now + 60));
        assert_eq!(false, minute.is_due(now + 61));
        assert_eq!(true, minute.is_due(now + 120));
        let day = Refresh::new(Duration::from_secs(86400));
        assert_eq!(false, day.is_due(now + 3600));
        assert_eq!(true, minute.is_due(now + 180));
        // less than a second is a second
        assert_eq!(1, Refresh::new(Duration::from_millis(1)).interval);

        // A file that has not changed is not read.
        database.reload_if_changed();
        assert_eq!(Some("AU".to_string()), country(&database));
        // Its time is set by hand: a second write may come within the
        // tick of the clock the first one has.
        let written = |seconds: u64| {
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(SystemTime::now() + Duration::from_secs(seconds))
                .unwrap();
        };
        // What is no database - a file half written - changes nothing.
        std::fs::write(&path, b"not a database").unwrap();
        written(10);
        database.reload_if_changed();
        assert_eq!(Some("AU".to_string()), country(&database));
        // The new one.
        std::fs::copy(fixture("geo-test-2.mmdb"), &path).unwrap();
        written(20);
        database.reload_if_changed();
        assert_eq!(Some("NZ".to_string()), country(&database));

        // A file that is gone leaves it as it is too.
        std::fs::remove_file(&path).unwrap();
        database.reload_if_changed();
        assert_eq!(Some("NZ".to_string()), country(&database));
        std::fs::copy(fixture("geo-test-2.mmdb"), &path).unwrap();

        // Let go of by everyone, it is read anew by whoever comes next.
        drop(database);
        assert_eq!(
            Some("NZ".to_string()),
            country(&DatabaseFile::open(path_text).unwrap())
        );
    }
}
