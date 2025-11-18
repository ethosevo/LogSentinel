use chrono::{DateTime, FixedOffset, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_value};

use crate::parser::docker::constants::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerState {
    pub dead: bool,
    pub error: String,
    pub exit_code: i32,
    pub finished_at: String,
    pub oomkilled: bool,
    pub paused: bool,
    pub pid: u32,
    pub restarting: bool,
    pub running: bool,
    pub started_at: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerNetwork {
    pub aliases: Vec<String>,
    pub dnsnames: Vec<String>,
    pub driver_opts: Option<serde_json::Value>,
    pub endpoint_id: String,
    pub gateway: String,
    pub global_ipv6_address: String,
    pub global_ipv6_prefix_len: u32,
    pub gw_priority: u32,
    pub ipamconfig: Option<serde_json::Value>,
    pub ipaddress: String,
    pub ipprefix_len: u32,
    pub ipv6_gateway: String,
    pub links: Option<serde_json::Value>,
    pub mac_address: String,
    pub network_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerPortMapping {
    pub host_ip: String,
    pub host_port: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerLogEntry {
    pub ts: DateTime<FixedOffset>,
    pub container_id: Option<String>,
    pub image: Option<String>,
    pub labels: Option<serde_json::Value>,
    pub exit_code: Option<i32>,
    pub restart_count: Option<u32>,
    pub health_status: Option<String>,
    pub state: Option<DockerState>,
    pub network: Option<DockerNetwork>,
    pub ports: Option<serde_json::Map<String, serde_json::Value>>,
    pub mounts: Option<serde_json::Value>,
    pub env_vars: Option<Vec<String>>,
    pub driver: Option<String>,
    pub size: Option<u64>,
    pub message: Option<String>,
}

static DOCKER_LOG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(DOCKER_LOG_PATTERN).expect("Invalid Docker log regex pattern"));

pub fn parse_docker_log(line: &str, tz: FixedOffset) -> Option<DockerLogEntry> {
    let v: Value = serde_json::from_str(line).ok()?;

    let ts_str = v.get("t")?.get("$date")?.as_str()?;
    let ts_parsed = DateTime::parse_from_rfc3339(ts_str)
        .unwrap_or_else(|_| DateTime::<FixedOffset>::from_local(Utc::now().naive_utc(), tz));
    let ts = ts_parsed.with_timezone(&tz);

    let attr = v.get("attr");
    let message = attr
        .and_then(|a| a.get("message"))
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());

    let container_id = v
        .get("container_id")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());
    let image = v
        .get("image")
        .and_then(|i| i.as_str())
        .map(|s| s.to_string());
    let labels = v
        .get("labels")
        .and_then(|l| l.as_str())
        .map(|s| s.to_string());
    let exit_code = v
        .get("exit_code")
        .and_then(|e| e.as_i64())
        .map(|v| v as i32);
    let restart_count = v
        .get("restart_count")
        .and_then(|r| r.as_u64())
        .map(|v| v as u32);
    let health_status = v
        .get("health_status")
        .and_then(|h| h.as_str())
        .map(|s| s.to_string());
    let state = v.get("state").and_then(|s| from_value(s.clone()).ok());
    let network = v.get("network").and_then(|n| from_value(n.clone()).ok());
    let ports = v.get("ports").and_then(|p| from_value(p.clone()).ok());
    let labels = v.get("labels").cloned();
    let mounts = v.get("mounts").cloned();
    let env_vars = v.get("env_vars").and_then(|e| {
        e.as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
    });
    let driver = v
        .get("driver")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string());
    let size = v.get("size").and_then(|s| s.as_u64());

    Some(DockerLogEntry {
        ts,
        container_id,
        image,
        labels,
        exit_code,
        restart_count,
        health_status,
        state,
        network,
        ports,
        mounts,
        env_vars,
        driver,
        size,
        message,
    })
}

pub fn parse_docker_log_multiline(lines: &[String], tz: FixedOffset) -> Vec<DockerLogEntry> {
    let mut entries = vec![];
    let mut buffer = String::new();

    for line in lines {
        if DOCKER_LOG_RE.is_match(line) {
            if !buffer.is_empty() {
                if let Some(entry) = parse_docker_log(&buffer, tz) {
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
        if let Some(entry) = parse_docker_log(&buffer, tz) {
            entries.push(entry);
        }
    }

    entries
}
