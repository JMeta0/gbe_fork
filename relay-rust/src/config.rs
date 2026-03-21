use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

#[derive(Clone, Copy, Debug)]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
    #[serde(default = "default_session_timeout", deserialize_with = "duration_nanos")]
    pub session_timeout: Duration,
    #[serde(default = "default_cleanup_interval", deserialize_with = "duration_nanos")]
    pub cleanup_interval: Duration,
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,
    #[serde(default = "default_rate_limit_per_second")]
    pub rate_limit_per_second: u32,
    #[serde(default = "default_rate_burst")]
    pub rate_burst: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format", deserialize_with = "log_format")]
    pub log_format: LogFormat,
}

pub fn load_config(path: Option<&str>) -> Result<Config, ConfigError> {
    let cfg = if let Some(path) = path {
        let bytes = fs::read(path)?;
        serde_json::from_slice::<Config>(&bytes)?
    } else {
        Config::default()
    };
    cfg.validate()?;
    Ok(cfg)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_address: default_listen_address(),
            tcp_port: default_tcp_port(),
            udp_port: default_udp_port(),
            session_timeout: default_session_timeout(),
            cleanup_interval: default_cleanup_interval(),
            max_packet_size: default_max_packet_size(),
            rate_limit_per_second: default_rate_limit_per_second(),
            rate_burst: default_rate_burst(),
            log_level: default_log_level(),
            log_format: LogFormat::Json,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        IpAddr::from_str(&self.listen_address)
            .map_err(|err| ConfigError::Message(format!("invalid listen_address: {err}")))?;
        if self.max_packet_size < 64 || self.max_packet_size > 65_507 {
            return Err(ConfigError::Message(
                "max_packet_size must be between 64 and 65507".to_string(),
            ));
        }
        if self.rate_limit_per_second == 0 || self.rate_burst == 0 {
            return Err(ConfigError::Message(
                "rate limit settings must be positive".to_string(),
            ));
        }
        if self.session_timeout.is_zero() || self.cleanup_interval.is_zero() {
            return Err(ConfigError::Message(
                "timeouts and cleanup interval must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Message(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Message(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

fn duration_nanos<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let nanos = u64::deserialize(deserializer)?;
    Ok(Duration::from_nanos(nanos))
}

fn log_format<'de, D>(deserializer: D) -> Result<LogFormat, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match raw.to_ascii_lowercase().as_str() {
        "json" => Ok(LogFormat::Json),
        "text" => Ok(LogFormat::Text),
        _ => Err(serde::de::Error::custom("unsupported log format")),
    }
}

fn default_listen_address() -> String {
    "0.0.0.0".to_string()
}

fn default_tcp_port() -> u16 {
    23010
}

fn default_udp_port() -> u16 {
    23011
}

fn default_session_timeout() -> Duration {
    Duration::from_secs(120)
}

fn default_cleanup_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_max_packet_size() -> usize {
    4096
}

fn default_rate_limit_per_second() -> u32 {
    5000
}

fn default_rate_burst() -> u32 {
    10000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> LogFormat {
    LogFormat::Json
}
