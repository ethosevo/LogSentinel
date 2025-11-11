use chrono::{DateTime, FixedOffset, NaiveDateTime};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str::FromStr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    #[serde(other)]
    OTHER,
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s {
            "GET" => Self::GET,
            "POST" => Self::POST,
            "PUT" => Self::PUT,
            "PATCH" => Self::PATCH,
            "DELETE" => Self::DELETE,
            "HEAD" => Self::HEAD,
            "OPTIONS" => Self::OPTIONS,
            "TRACE" => Self::TRACE,
            "CONNECT" => Self::CONNECT,
            _ => Self::OTHER,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    HTTP10,
    HTTP11,
    HTTP20,
    HTTP30,
    Other(String),
}

impl From<&str> for Protocol {
    fn from(s: &str) -> Self {
        match s {
            "HTTP/1.0" => Self::HTTP10,
            "HTTP/1.1" => Self::HTTP11,
            "HTTP/2.0" | "HTTP/2" => Self::HTTP20,
            "HTTP/3.0" | "HTTP/3" => Self::HTTP30,
            other => Self::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accesslog {
    pub ip: IpAddr,

    pub ts: DateTime<FixedOffset>,

    pub method: HttpMethod,
    pub route: String,
    pub query: Option<String>,
    pub protocol: Protocol,

    pub status: u16,
    pub bytes: u64,

    pub referer: Option<String>,
    pub url: Option<String>,
    pub user_agent_raw: Option<String>,
    pub user_agent: Option<UserAgent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserAgent {
    pub engine: String,
    pub os: String,
    pub webkit: Option<String>,
    pub like_gecko: bool,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub safari: Option<String>,
    pub edge: Option<String>,
}

static ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<off>[+\-]\d{4})\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d(?:\.\d)?)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"$"#).unwrap()
});

static UA_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^(?P<engine>Mozilla/\d+\.\d+)\s+\((?P<os>[^)]*)\)\s+AppleWebKit/(?P<webkit>[\d\.]+)\s+\(KHTML,\s+like\s+Gecko\)\s+(?P<browser>\w+)/(?P<b_ver>[\d\.]+)\s+Safari/(?P<safari>[\d\.]+)(?:\s+(?P<edge>Edg)/(?P<e_ver>[\d\.]+))?"#).unwrap()
});

fn mon_to_num(mon: &str) -> Option<u32> {
    match mon {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

pub fn parse_user_agent(s: &str) -> Option<UserAgent> {
    if s.trim().is_empty() {
        return None;
    }
    if let Some(c) = UA_RE.captures(s) {
        let like_gecko = true;
        let mut ua = UserAgent {
            engine: c
                .name("engine")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
            os: c
                .name("os")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
            webkit: c.name("webkit").map(|m| m.as_str().to_string()),
            like_gecko,
            browser: c.name("browser").map(|m| m.as_str().to_string()),
            browser_version: c.name("b_ver").map(|m| m.as_str().to_string()),
            safari: c.name("safari").map(|m| m.as_str().to_string()),
            edge: c.name("e_ver").map(|m| m.as_str().to_string()),
        };
        Some(ua)
    } else {
        Some(UserAgent {
            engine: "Mozilla/5.0".into(),
            os: "".into(),
            webkit: None,
            like_gecko: s.contains("like Gecko"),
            browser: None,
            browser_version: None,
            safari: None,
            edge: None,
        })
    }
}

pub fn parse_access_log(line: &str) -> Option<Accesslog> {
    let caps = ACCESS_RE.captures(line)?;
    let ip = IpAddr::from_str(caps.name("ip")?.as_str()).ok()?;

    let day: u32 = caps.name("day")?.as_str().parse().ok()?;
    let mon = mon_to_num(caps.name("mon")?.as_str())?;
    let year: i32 = caps.name("year")?.as_str().parse().ok()?;
    let h: u32 = caps.name("h")?.as_str().parse().ok()?;
    let m: u32 = caps.name("m")?.as_str().parse().ok()?;
    let s: u32 = caps.name("s")?.as_str().parse().ok()?;
    let off = caps.name("off")?.as_str();

    let naive = NaiveDateTime::from_timestamp_opt(
        chrono::NaiveDate::from_ymd_opt(year, mon, day)?
            .and_hms_opt(h, m, s)?
            .timestamp(),
        0,
    )?;
    let off_fmt = format!("{}:{}", &off[0..3], &off[3..]);
    let offset = FixedOffset::from_str(&off_fmt).ok()?;
    let ts = DateTime::<FixedOffset>::from_naive_utc_and_offset(naive, offset);

    let method = HttpMethod::from(caps.name("method")?.as_str());
    let path_full = caps.name("path")?.as_str();

    let (route, query) = if let Some(pos) = path_full.find('?') {
        (
            path_full[..pos].to_string(),
            Some(path_full[pos + 1..].to_string()),
        )
    } else {
        (path_full.to_string(), None)
    };

    let protocol = Protocol::from(caps.name("proto")?.as_str());
    let status: u16 = caps.name("status")?.as_str().parse().ok()?;
    let bytes: u64 = match caps.name("bytes")?.as_str() {
        "-" => 0,
        v => v.parse().unwrap_or(0),
    };
    let referer = {
        let r = caps
            .name("ref")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if r == "-" || r.is_empty() {
            None
        } else {
            Some(r)
        }
    };
    let ua_raw = {
        let u = caps
            .name("ua")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if u.is_empty() { None } else { Some(u) }
    };
    let ua = ua_raw.as_deref().and_then(parse_user_agent);

    let url = Some(if let Some(q) = &query {
        format!("{route}?{q}")
    } else {
        route.clone()
    });

    Some(Accesslog {
        ip,
        ts,
        method,
        route,
        query,
        protocol,
        status,
        bytes,
        referer,
        url,
        user_agent_raw: ua_raw,
        user_agent: ua,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLog {
    pub ts: DateTime<FixedOffset>,
    pub level: String,
    pub pid: u32,
    pub worker: u32,
    pub conn: u64,
    pub message: String,
    pub client: Option<IpAddr>,
    pub server: Option<String>,
    pub request: Option<String>,
    pub upstream: Option<String>,
    pub host: Option<String>,
}

static ERR_RE_HEAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\[(?P<lvl>[a-z]+)\]\s+(?P<pid>\d+)#(?P<wrk>\d+):\s+\*(?P<conn>\d+)\s+(?P<msg>.*?)(?:,\s|$)"#).unwrap()
});
static KV_IP: Lazy<Regex> = Lazy::new(|| Regex::new(r#"client:\s*(?P<ip>[^,]+)"#).unwrap());
static KV_SERVER: Lazy<Regex> = Lazy::new(|| Regex::new(r#"server:\s*(?P<val>[^,]+)"#).unwrap());
static KV_REQUEST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"request:\s*"(?P<val>[^"]+)""#).unwrap());
static KV_UPSTREAM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"upstream:\s*"(?P<val>[^"]+)""#).unwrap());
static KV_HOST: Lazy<Regex> = Lazy::new(|| Regex::new(r#"host:\s*"?(?P<val>[^",]+)"?"#).unwrap());

pub fn parse_error_log(line: &str, tz: FixedOffset) -> Option<ErrorLog> {
    let caps = ERR_RE_HEAD.captures(line)?;

    let date = caps.name("date")?.as_str(); // 2025/11/11
    let time = caps.name("time")?.as_str(); // 04:50:36
    let lvl = caps.name("lvl")?.as_str().to_string();
    let pid: u32 = caps.name("pid")?.as_str().parse().ok()?;
    let worker: u32 = caps.name("wrk")?.as_str().parse().ok()?;
    let conn: u64 = caps.name("conn")?.as_str().parse().ok()?;
    let msg = caps.name("msg")?.as_str().to_string();

    let naive =
        NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%Y/%m/%d %H:%M:%S").ok()?;
    let ts = DateTime::<FixedOffset>::from_local(naive, tz);

    let client = KV_IP
        .captures(line)
        .and_then(|c| c.name("ip"))
        .and_then(|m| IpAddr::from_str(m.as_str()).ok());

    let server = KV_SERVER
        .captures(line)
        .and_then(|c| c.name("val"))
        .map(|m| m.as_str().to_string());

    let request = KV_REQUEST
        .captures(line)
        .and_then(|c| c.name("val"))
        .map(|m| m.as_str().to_string());

    let upstream = KV_UPSTREAM
        .captures(line)
        .and_then(|c| c.name("val"))
        .map(|m| m.as_str().to_string());

    let host = KV_HOST
        .captures(line)
        .and_then(|c| c.name("val"))
        .map(|m| m.as_str().to_string());

    Some(ErrorLog {
        ts,
        level: lvl,
        pid,
        worker,
        conn,
        message: msg,
        client,
        server,
        request,
        upstream,
        host,
    })
}
