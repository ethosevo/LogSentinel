use once_cell::sync::Lazy;
use regex::Regex;

pub const DEFAULT_FACILITY: u8 = 1;
pub const DEFAULT_SEVERITY: u8 = 6;

pub static FACILITY_NAMES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "logaudit", "logalert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

pub static SEVERITY_NAMES: [&str; 8] = [
    "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
];

pub static MONTHS: [(&str, u32); 12] = [
    ("Jan", 1), ("Feb", 2), ("Mar", 3), ("Apr", 4), ("May", 5), ("Jun", 6),
    ("Jul", 7), ("Aug", 8), ("Sep", 9), ("Oct", 10), ("Nov", 11), ("Dec", 12),
];


pub static JOURNAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:\.\+\-]+)\s+(?P<host>\S+)\s+(?P<app>[^\[\:\s]+)(?:\[(?P<pid>[^\]]+)\])?:\s*(?P<msg>.*)$"#,
    )
    .unwrap()
});

pub static RFC5424_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>(?:-|\[.*?\]))\s*(?P<msg>.*)$"#,
    )
    .unwrap()
});

pub static BSD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(?:\s*<(?P<pri>\d{1,3})>)?\s*(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<host>\S+)?\s*(?P<app>[A-Za-z0-9_\-./]+)?(?:\[(?P<pid>[^\]]+)\])?(?:[:\s-]+)?(?P<msg>.*)$"#,
    )
    .unwrap()
});


pub const NEWLINE: &str = "\n";
pub const CARRIAGE_RETURN: &str = "\r";
pub const EMPTY: &str = "";
pub const CAP_TS: &str = "ts";
pub const CAP_HOST: &str = "host";
pub const CAP_APP: &str = "app";
pub const CAP_PID: &str = "pid";
pub const CAP_MSG: &str = "msg";



pub const CRON: &str = "cron";
pub const SYSTEMD: &str = "systemd";
pub const SERVICE: &str = "service";
pub const KERNEL: &str = "kernel";
pub const KERN: &str = "kern";
pub const SSHD: &str = "sshd";
pub const SSH: &str = "ssh";
pub const AUTH: &str = "auth";
pub const SUDO: &str = "sudo";
pub const RSYSLOG: &str = "rsyslog";
pub const SYSLOG: &str = "syslog";
pub const APT: &str = "apt";
pub const DPKG: &str = "dpkg";
pub const NGINX: &str = "nginx";
pub const HTTPD: &str = "httpd";
pub const APACHE: &str = "apache";
pub const DOCKER: &str = "docker";
pub const CONTAINERD: &str = "containerd";
pub const KUBELET: &str = "kubelet";


pub const PANIC: &str = "panic";
pub const EMERG: &str = "emerg";
pub const ALERT: &str = "alert";
pub const CRIT: &str = "crit";
pub const CRITICAL: &str = "critical";
pub const FAIL: &str = "fail";
pub const FAILED: &str = "failed";
pub const ERROR: &str = "error";
pub const DENIED: &str = "denied";
pub const WARN: &str = "warn";
pub const WARNING: &str = "warning";
pub const NOTICE: &str = "notice";
pub const INFO: &str = "info";
pub const STARTED: &str = "started";
pub const FINISHED: &str = "finished";
pub const ACCEPTED: &str = "accepted";
pub const DEBUG: &str = "debug";
