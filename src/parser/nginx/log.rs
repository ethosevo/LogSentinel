use chrono::{DateTime, FixedOffset, NaiveDateTime};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, str::FromStr};

use crate::parser::nginx::constants::{
    self as c, DATETIME_FORMAT, HttpMethodStr, MONTHS,
    cap::{LIKE_GECKO, MOZILLA},
};

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
            x if x == HttpMethodStr::GET.as_str() => Self::GET,
            x if x == HttpMethodStr::POST.as_str() => Self::POST,
            x if x == HttpMethodStr::PUT.as_str() => Self::PUT,
            x if x == HttpMethodStr::PATCH.as_str() => Self::PATCH,
            x if x == HttpMethodStr::DELETE.as_str() => Self::DELETE,
            x if x == HttpMethodStr::HEAD.as_str() => Self::HEAD,
            x if x == HttpMethodStr::OPTIONS.as_str() => Self::OPTIONS,
            x if x == HttpMethodStr::TRACE.as_str() => Self::TRACE,
            x if x == HttpMethodStr::CONNECT.as_str() => Self::CONNECT,
            _ => Self::OTHER,
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::GET => write!(f, "GET"),
            HttpMethod::POST => write!(f, "POST"),
            HttpMethod::PUT => write!(f, "PUT"),
            HttpMethod::PATCH => write!(f, "PATCH"),
            HttpMethod::DELETE => write!(f, "DELETE"),
            HttpMethod::HEAD => write!(f, "HEAD"),
            HttpMethod::OPTIONS => write!(f, "OPTIONS"),
            HttpMethod::TRACE => write!(f, "TRACE"),
            HttpMethod::CONNECT => write!(f, "CONNECT"),
            HttpMethod::OTHER => write!(f, "OTHER"),
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

impl Protocol {
    pub fn from_enum(s: &str) -> Self {
        match s {
            x if x == c::ProtocolStr::HTTP10.as_str() => Self::HTTP10,
            x if x == c::ProtocolStr::HTTP11.as_str() => Self::HTTP11,
            x if x == c::ProtocolStr::HTTP20.as_str() => Self::HTTP20,
            x if x == c::ProtocolStr::HTTP30.as_str() => Self::HTTP30,
            other => Self::Other(other.to_string()),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::HTTP10 => write!(f, "HTTP/1.0"),
            Protocol::HTTP11 => write!(f, "HTTP/1.1"),
            Protocol::HTTP20 => write!(f, "HTTP/2.0"),
            Protocol::HTTP30 => write!(f, "HTTP/3.0"),
            Protocol::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessLog {
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
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

static ACCESS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(c::ACCESS_REGEX).unwrap());
static UA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(c::UA_REGEX).unwrap());
static ERR_RE_HEAD: Lazy<Regex> = Lazy::new(|| Regex::new(c::ERR_RE_HEAD_REGEX).unwrap());
static KV_IP: Lazy<Regex> = Lazy::new(|| Regex::new(c::KV_IP_REGEX).unwrap());
static KV_SERVER: Lazy<Regex> = Lazy::new(|| Regex::new(c::KV_SERVER_REGEX).unwrap());
static KV_REQUEST: Lazy<Regex> = Lazy::new(|| Regex::new(c::KV_REQUEST_REGEX).unwrap());
static KV_UPSTREAM: Lazy<Regex> = Lazy::new(|| Regex::new(c::KV_UPSTREAM_REGEX).unwrap());
static KV_HOST: Lazy<Regex> = Lazy::new(|| Regex::new(c::KV_HOST_REGEX).unwrap());

pub fn mon_to_num(mon: &str) -> Option<u32> {
    for (m, num) in MONTHS {
        if *m == mon {
            return Some(*num);
        }
    }
    None
}

pub fn parse_user_agent(s: &str) -> Option<UserAgent> {
    if s.trim().is_empty() {
        return None;
    }
    if let Some(caps) = UA_RE.captures(s) {
        Some(UserAgent {
            engine: caps
                .name(c::cap::UA_ENGINE)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
            os: caps
                .name(c::cap::UA_OS)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
            webkit: caps.name(c::cap::UA_WEBKIT).map(|m| m.as_str().to_string()),
            like_gecko: true,
            browser: caps
                .name(c::cap::UA_BROWSER)
                .map(|m| m.as_str().to_string()),
            browser_version: caps
                .name(c::cap::UA_BROWSER_VER)
                .map(|m| m.as_str().to_string()),
            safari: caps.name(c::cap::UA_SAFARI).map(|m| m.as_str().to_string()),
            edge: caps.name(c::cap::UA_EDGE).map(|m| m.as_str().to_string()),
        })
    } else {
        Some(UserAgent {
            engine: MOZILLA.into(),
            os: c::EMPTY.into(),
            webkit: None,
            like_gecko: s.contains(LIKE_GECKO),
            browser: None,
            browser_version: None,
            safari: None,
            edge: None,
        })
    }
}

pub fn parse_access_log(line: &str) -> Option<AccessLog> {
    let caps = ACCESS_RE.captures(line)?;
    let ip = IpAddr::from_str(caps.name(c::cap::IP)?.as_str()).ok()?;

    let day: u32 = caps.name(c::cap::DAY)?.as_str().parse().ok()?;
    let mon = mon_to_num(caps.name(c::cap::MON)?.as_str())?;
    let year: i32 = caps.name(c::cap::YEAR)?.as_str().parse().ok()?;
    let h: u32 = caps.name(c::cap::H)?.as_str().parse().ok()?;
    let m: u32 = caps.name(c::cap::M)?.as_str().parse().ok()?;
    let s: u32 = caps.name(c::cap::S)?.as_str().parse().ok()?;
    let off = caps.name(c::cap::OFF)?.as_str();

    let naive = NaiveDateTime::from_timestamp_opt(
        chrono::NaiveDate::from_ymd_opt(year, mon, day)?
            .and_hms_opt(h, m, s)?
            .timestamp(),
        0,
    )?;
    let offset = FixedOffset::from_str(&format!("{}:{}", &off[0..3], &off[3..])).ok()?;
    let ts = DateTime::<FixedOffset>::from_naive_utc_and_offset(naive, offset);

    let method = HttpMethod::from(caps.name(c::cap::METHOD)?.as_str());
    let path_full = caps.name(c::cap::PATH)?.as_str();

    let (route, query) = if let Some(pos) = path_full.find(c::QUESTION_MARK) {
        (
            path_full[..pos].to_string(),
            Some(path_full[pos + 1..].to_string()),
        )
    } else {
        (path_full.to_string(), None)
    };

    let protocol = Protocol::from_enum(caps.name(c::cap::PROTO)?.as_str());
    let status: u16 = caps.name(c::cap::STATUS)?.as_str().parse().ok()?;
    let bytes: u64 = match caps.name(c::cap::BYTES)?.as_str() {
        c::DASH => 0,
        v => v.parse().unwrap_or(0),
    };

    let referer = caps
        .name(c::cap::REF)
        .map(|m| m.as_str().to_string())
        .filter(|r| !r.is_empty() && r != c::DASH);

    let ua_raw = caps
        .name(c::cap::UA)
        .map(|m| m.as_str().to_string())
        .filter(|s| !s.is_empty());

    let ua = ua_raw.as_deref().and_then(parse_user_agent);

    let url = Some(match &query {
        Some(q) => format!("{route}?{q}"),
        None => route.clone(),
    });

    Some(AccessLog {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

pub fn parse_error_log(line: &str, tz: FixedOffset) -> Option<ErrorLog> {
    let caps = ERR_RE_HEAD.captures(line)?;

    let date = caps.name(c::cap::ERR_DATE)?.as_str();
    let time = caps.name(c::cap::ERR_TIME)?.as_str();
    let lvl = caps.name(c::cap::ERR_LVL)?.as_str().to_string();
    let pid: u32 = caps.name(c::cap::ERR_PID)?.as_str().parse().ok()?;
    let worker: u32 = caps.name(c::cap::ERR_WRK)?.as_str().parse().ok()?;
    let conn: u64 = caps.name(c::cap::ERR_CONN)?.as_str().parse().ok()?;
    let msg = caps.name(c::cap::ERR_MSG)?.as_str().to_string();

    let naive = NaiveDateTime::parse_from_str(&format!("{date} {time}"), DATETIME_FORMAT).ok()?;
    let ts = DateTime::<FixedOffset>::from_local(naive, tz);

    let client = KV_IP
        .captures(line)
        .and_then(|c| c.name(c::cap::ERR_CLIENT))
        .and_then(|m| IpAddr::from_str(m.as_str()).ok());
    let server = KV_SERVER
        .captures(line)
        .and_then(|c| c.name(c::cap::ERR_SERVER))
        .map(|m| m.as_str().to_string());
    let request = KV_REQUEST
        .captures(line)
        .and_then(|c| c.name(c::cap::ERR_REQUEST))
        .map(|m| m.as_str().to_string());
    let upstream = KV_UPSTREAM
        .captures(line)
        .and_then(|c| c.name(c::cap::ERR_UPSTREAM))
        .map(|m| m.as_str().to_string());
    let host = KV_HOST
        .captures(line)
        .and_then(|c| c.name(c::cap::ERR_HOST))
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
