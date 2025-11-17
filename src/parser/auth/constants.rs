pub const DEFAULT_FACILITY: u8 = 4;
pub const DEFAULT_SEVERITY: u8 = 5;

pub static FACILITY_NAMES: [&str; 24] = [
    "kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
];

pub static SEVERITY_NAMES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

pub static MONTHS: [(&str, u32); 12] = [
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

pub const SSHD: &str = "sshd";
pub const SUDO: &str = "sudo";
pub const PAM: &str = "pam";
pub const LOGIN: &str = "login";
pub const CRON: &str = "cron";

pub const PANIC: &str = "panic";
pub const EMERG: &str = "emerg";
pub const ALERT: &str = "alert";
pub const CRIT: &str = "crit";
pub const ERROR: &str = "error";
pub const FAIL: &str = "fail";
pub const FAILED: &str = "failed";
pub const DENIED: &str = "denied";
pub const WARN: &str = "warn";
pub const WARNING: &str = "warning";
pub const NOTICE: &str = "notice";
pub const INFO: &str = "info";
pub const STARTED: &str = "started";
pub const FINISHED: &str = "finished";
pub const ACCEPTED: &str = "accepted";
pub const DEBUG: &str = "debug";
pub const UNKNOWN:&str = "unknow";

pub const AUTH_LOG:&str = r"^(?P<mon>\w{3}) +(?P<day>\d{1,2}) +(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2}) +(?P<host>\S+) +(?P<app>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$";


pub const MONTH:&str = "mon";
pub const DAY:&str = "day";
pub const HOUR:&str = "hour";
pub const MINUTE:&str = "min";
pub const SECOND:&str = "sec";

pub const HOST:&str = "host";
pub const APPNAME:&str = "app";
pub const PROCESSID:&str = "pid";
pub const MESSAGE:&str = "msg";