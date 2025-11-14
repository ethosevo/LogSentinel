use chrono::{DateTime, FixedOffset, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::parser::syslog::constants::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogEntry {
    pub pri: Option<u8>,

    pub facility: u8,
    pub severity: u8,
    pub facility_name: String,
    pub severity_name: String,

    pub ts: DateTime<FixedOffset>,
    pub host: Option<String>,
    pub appname: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub structured_data: Option<String>,
    pub message: String,
    pub facility_severity_raw: String,
}

pub fn facility_name_from_code(code: u8) -> &'static str {
    FACILITY_NAMES.get(code as usize).unwrap_or(&"unknown")
}

pub fn severity_name_from_code(code: u8) -> &'static str {
    SEVERITY_NAMES.get(code as usize).unwrap_or(&"unknown")
}

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
    if a.contains(CRON) {
        Some(9)
    } else if a.contains(SYSTEMD) || a.contains(SERVICE) {
        Some(3)
    } else if a.contains(KERNEL) || a.contains(KERN) {
        Some(0)
    } else if a.contains(SSHD) || a.contains(SSH) || a.contains(AUTH) || a.contains(SUDO) {
        Some(4)
    } else if a.contains(RSYSLOG) || a.contains(SYSLOG) {
        Some(5)
    } else if a.contains(APT) || a.contains(DPKG) {
        Some(3)
    } else if a.contains(NGINX) || a.contains(HTTPD) || a.contains(APACHE) {
        Some(3)
    } else if a.contains(DOCKER) || a.contains(CONTAINERD) || a.contains(KUBELET) {
        Some(3)
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
    } else if m.contains(CRIT) || m.contains(CRITICAL) {
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
        let fnm = facility_name_from_code(f).to_string();
        let snm = severity_name_from_code(s).to_string();
        let raw = format!("{}.{}", fnm, snm);
        return (f, s, fnm, snm, raw);
    }

    let facility = infer_facility_from_app(appname_opt).unwrap_or(DEFAULT_FACILITY);
    let severity = infer_severity_from_msg(msg).unwrap_or(DEFAULT_SEVERITY);

    let fnm = facility_name_from_code(facility).to_string();
    let snm = severity_name_from_code(severity).to_string();
    let raw = format!("{}.{}", fnm, snm);

    (facility, severity, fnm, snm, raw)
}

pub fn parse_syslog(line: &str, tz: FixedOffset) -> Option<SyslogEntry> {
    let line = line
        .trim_end_matches(|c| {
            c == NEWLINE.chars().next().unwrap() || c == CARRIAGE_RETURN.chars().next().unwrap()
        })
        .trim();

    if let Some(caps) = JOURNAL_RE.captures(line) {
        let ts_parsed = caps
            .name(CAP_TS)
            .and_then(|m| chrono::DateTime::parse_from_rfc3339(m.as_str()).ok())
            .unwrap_or_else(|| DateTime::<FixedOffset>::from_local(Utc::now().naive_utc(), tz));
        let ts = ts_parsed.with_timezone(&tz);

        let host = caps.name(CAP_HOST).map(|m| m.as_str().to_string());
        let appname = caps.name(CAP_APP).map(|m| m.as_str().to_string());
        let procid = caps.name(CAP_PID).map(|m| m.as_str().to_string());
        let message = caps
            .name(CAP_MSG)
            .map(|m| m.as_str().to_string())
            .unwrap_or(EMPTY.to_string());

        let (facility, severity, facility_name, severity_name, facility_severity_raw) =
            fill_facility_severity(None, appname.as_deref(), &message);

        return Some(SyslogEntry {
            pri: None,
            facility,
            severity,
            facility_name,
            severity_name,
            ts,
            host,
            appname,
            procid,
            msgid: None,
            structured_data: None,
            message,
            facility_severity_raw,
        });
    }

    None
}
