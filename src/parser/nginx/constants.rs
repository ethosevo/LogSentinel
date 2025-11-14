pub const EMPTY: &str = "";
pub const DASH: &str = "-";
pub const QUESTION_MARK: &str = "?";

pub mod cap {
    pub const IP: &str = "ip";
    pub const DAY: &str = "day";
    pub const MON: &str = "mon";
    pub const YEAR: &str = "year";
    pub const H: &str = "h";
    pub const M: &str = "m";
    pub const S: &str = "s";
    pub const OFF: &str = "off";
    pub const METHOD: &str = "method";
    pub const PATH: &str = "path";
    pub const PROTO: &str = "proto";
    pub const STATUS: &str = "status";
    pub const BYTES: &str = "bytes";
    pub const REF: &str = "ref";
    pub const UA: &str = "ua";

    pub const UA_ENGINE: &str = "engine";
    pub const UA_OS: &str = "os";
    pub const UA_WEBKIT: &str = "webkit";
    pub const UA_BROWSER: &str = "browser";
    pub const UA_BROWSER_VER: &str = "b_ver";
    pub const UA_SAFARI: &str = "safari";
    pub const UA_EDGE: &str = "e_ver";

    pub const ERR_DATE: &str = "date";
    pub const ERR_TIME: &str = "time";
    pub const ERR_LVL: &str = "lvl";
    pub const ERR_PID: &str = "pid";
    pub const ERR_WRK: &str = "wrk";
    pub const ERR_CONN: &str = "conn";
    pub const ERR_MSG: &str = "msg";
    pub const ERR_CLIENT: &str = "ip";
    pub const ERR_SERVER: &str = "val";
    pub const ERR_REQUEST: &str = "val";
    pub const ERR_UPSTREAM: &str = "val";
    pub const ERR_HOST: &str = "val";

    pub const MOZILLA: &str = "Mozilla/5.0";
    pub const LIKE_GECKO: &str = "like Gecko";
}

pub const MONTHS: &[(&str, u32)] = &[
    ("Jan", 1),
    ("Feb", 2),
    ("Mar", 3),
    ("Apr", 4),
    ("May", 5),
    ("Jun", 6),
    ("Jul", 7),
    ("Aug", 8),
    ("Sep", 9),
    ("Oct", 10),
    ("Nov", 11),
    ("Dec", 12),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethodStr {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    OTHER,
}

impl HttpMethodStr {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::PATCH => "PATCH",
            Self::DELETE => "DELETE",
            Self::HEAD => "HEAD",
            Self::OPTIONS => "OPTIONS",
            Self::TRACE => "TRACE",
            Self::CONNECT => "CONNECT",
            Self::OTHER => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolStr {
    HTTP10,
    HTTP11,
    HTTP20,
    HTTP30,
    OTHER,
}

impl ProtocolStr {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HTTP10 => "HTTP/1.0",
            Self::HTTP11 => "HTTP/1.1",
            Self::HTTP20 => "HTTP/2.0",
            Self::HTTP30 => "HTTP/3.0",
            Self::OTHER => "",
        }
    }
}

pub const ACCESS_REGEX: &str = r#"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<off>[+\-]\d{4})\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d(?:\.\d)?)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"$"#;
pub const UA_REGEX: &str = r#"^(?P<engine>Mozilla/\d+\.\d+)\s+\((?P<os>[^)]*)\)\s+AppleWebKit/(?P<webkit>[\d\.]+)\s+\(KHTML,\s+like\s+Gecko\)\s+(?P<browser>\w+)/(?P<b_ver>[\d\.]+)\s+Safari/(?P<safari>[\d\.]+)(?:\s+(?P<edge>Edg)/(?P<e_ver>[\d\.]+))?"#;

pub const ERR_RE_HEAD_REGEX: &str = r#"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\[(?P<lvl>[a-z]+)\]\s+(?P<pid>\d+)#(?P<wrk>\d+):\s+\*(?P<conn>\d+)\s+(?P<msg>.*?)(?:,\s|$)"#;
pub const KV_IP_REGEX: &str = r#"client:\s*(?P<ip>[^,]+)"#;
pub const KV_SERVER_REGEX: &str = r#"server:\s*(?P<val>[^,]+)"#;
pub const KV_REQUEST_REGEX: &str = r#"request:\s*"(?P<val>[^"]+)""#;
pub const KV_UPSTREAM_REGEX: &str = r#"upstream:\s*"(?P<val>[^"]+)""#;
pub const KV_HOST_REGEX: &str = r#"host:\s*"?(?P<val>[^",]+)"?"#;

pub const DATETIME_FORMAT: &str = "%Y/%m/%d %H:%M:%S";
