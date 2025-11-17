use crate::parser::auth::constants::*;
use chrono::Datelike;
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

pub fn mon_to_num(mon: &str) -> Option<u32> {
    for (name, num) in MONTHS {
        if mon.eq_ignore_ascii_case(name) {
            return Some(num);
        }
    }
    None
}

fn pri_to_facility_severity(pri: u8) -> (u8, u8) {
    (pri >> 3, pri & 0x7)
}

fn infer_facility_from_app(appname: Option<&str>) -> Option<u8> {
    let a = appname?.to_ascii_lowercase();
    if a.contains(SSHD) || a.contains(SUDO) || a.contains(PAM) || a.contains(LOGIN) {
        Some(4)
    } else if a.contains(CRON) {
        Some(9)
    } else {
        None
    }
}

fn infer_severity_from_msg(msg: &str) -> Option<u8> {
    let m = msg.to_ascii_lowercase();
    if m.contains(PANIC) || m.contains(EMERG) {
        Some(0)
    } else if m.contains(ALERT) {
        Some(1)
    } else if m.contains(CRIT) {
        Some(2)
    } else if m.contains(FAIL) || m.contains(FAILED) || m.contains(ERROR) || m.contains(DENIED) {
        Some(3)
    } else if m.contains(WARN) || m.contains(WARNING) {
        Some(4)
    } else if m.contains(NOTICE) {
        Some(5)
    } else if m.contains(INFO)
        || m.contains(STARTED)
        || m.contains(FINISHED)
        || m.contains(ACCEPTED)
    {
        Some(6)
    } else if m.contains(DEBUG) {
        Some(7)
    } else {
        None
    }
}

fn fill_facility_severity(
    pri_opt: Option<u8>,
    appname_opt: Option<&str>,
    msg: &str,
) -> (u8, u8, String, String, String) {
    if let Some(pri) = pri_opt {
        let (f, s) = pri_to_facility_severity(pri);
        let fnm = FACILITY_NAMES
            .get(f as usize)
            .unwrap_or(&UNKNOWN)
            .to_string();
        let snm = SEVERITY_NAMES
            .get(s as usize)
            .unwrap_or(&UNKNOWN)
            .to_string();
        let raw = format!("{}.{}", fnm, snm);
        return (f, s, fnm, snm, raw);
    }

    let facility = infer_facility_from_app(appname_opt).unwrap_or(DEFAULT_FACILITY);
    let severity = infer_severity_from_msg(msg).unwrap_or(DEFAULT_SEVERITY);
    let fnm = FACILITY_NAMES[facility as usize].to_string();
    let snm = SEVERITY_NAMES[severity as usize].to_string();
    let raw = format!("{}.{}", fnm, snm);

    (facility, severity, fnm, snm, raw)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthLogEntry {
    pub pri: Option<u8>,
    pub facility: u8,
    pub severity: u8,
    pub facility_name: String,
    pub severity_name: String,
    pub ts: DateTime<FixedOffset>,
    pub host: String,
    pub appname: String,
    pub procid: Option<String>,
    pub message: String,
    pub facility_severity_raw: String,
}

static AUTH_LOG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(AUTH_LOG).unwrap());

pub fn parse_auth_log_multiline(lines: &[String], tz: FixedOffset) -> Vec<AuthLogEntry> {
    let mut entries = vec![];
    let mut buffer = String::new();

    for line in lines {
        if AUTH_LOG_RE.is_match(line) {
            if !buffer.is_empty() {
                if let Some(entry) = parse_auth_log(&buffer, tz) {
                    entries.push(entry);
                }
            }
            buffer = line.clone();
        } else {
            buffer.push_str("\n");
            buffer.push_str(line);
        }
    }

    if !buffer.is_empty() {
        if let Some(entry) = parse_auth_log(&buffer, tz) {
            entries.push(entry);
        }
    }

    entries
}

pub fn parse_auth_log(line: &str, tz: FixedOffset) -> Option<AuthLogEntry> {
    if let Some(caps) = AUTH_LOG_RE.captures(line) {
        let mon = caps.name(MONTH)?.as_str();
        let day: u32 = caps.name(DAY)?.as_str().parse().ok()?;
        let hour: u32 = caps.name(HOUR)?.as_str().parse().ok()?;
        let min: u32 = caps.name(MINUTE)?.as_str().parse().ok()?;
        let sec: u32 = caps.name(SECOND)?.as_str().parse().ok()?;

        let year = Utc::now().year();
        let month = mon_to_num(mon)?;
        let naive = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, month, day)?,
            chrono::NaiveTime::from_hms_opt(hour, min, sec)?,
        );
        let ts = DateTime::<FixedOffset>::from_local(naive, tz);

        let host = caps.name(HOST)?.as_str().to_string();
        let appname = caps.name(APPNAME)?.as_str().to_string();
        let procid = caps.name(PROCESSID).map(|m| m.as_str().to_string());
        let message = caps.name(MESSAGE)?.as_str().to_string();

        let (facility, severity, facility_name, severity_name, facility_severity_raw) =
            fill_facility_severity(None, Some(&appname), &message);

        return Some(AuthLogEntry {
            pri: None,
            facility,
            severity,
            facility_name,
            severity_name,
            ts,
            host,
            appname,
            procid,
            message,
            facility_severity_raw,
        });
    }

    None
}
