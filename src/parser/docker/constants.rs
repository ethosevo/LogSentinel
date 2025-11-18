pub const DOCKER_LOG_PATTERN: &str = r#"^(?P<timestamp>\S+) (?P<container_id>\S+) (?P<image>\S+)(?: (?P<labels>\{.*\}))?(?: exit=(?P<exit_code>\d+))?(?: restart=(?P<restart_count>\d+))?(?: health=(?P<health_status>\S+))?(?: state=(?P<state>\S+))?(?: network=(?P<network>\S+))?(?: ports=(?P<ports>\S+))?(?: mounts=(?P<mounts>\S+))?(?: env=(?P<env>\S+))?(?: driver=(?P<driver>\S+))?(?: size=(?P<size>\S+))? (?P<message>.*)$"#;

pub const TIMESTAMP: &str = "timestamp";
pub const CONTAINER_ID: &str = "container_id";
pub const IMAGE: &str = "image";
pub const LABELS: &str = "labels";
pub const EXIT_CODE: &str = "exit_code";
pub const RESTART_COUNT: &str = "restart_count";
pub const HEALTH_STATUS: &str = "health_status";
pub const STATE: &str = "state";
pub const NETWORK: &str = "network";
pub const PORTS: &str = "ports";
pub const MOUNTS: &str = "mounts";
pub const ENV_VARS: &str = "env";
pub const DRIVER: &str = "driver";
pub const SIZE: &str = "size";
pub const MESSAGE: &str = "message";