use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{
    Config, PLATFORM_CORPLINK, PLATFORM_LARK, PLATFORM_LDAP, PLATFORM_OIDC,
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MACHINE_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Login,
    RefreshCookie,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    LoginUrl,
    Waiting,
    Success,
    RefreshStarted,
    RefreshSucceeded,
    AuthRequired,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MachineRequest {
    pub protocol_version: u32,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_select_strategy: Option<String>,
}

impl MachineRequest {
    pub fn into_client_config(self) -> Result<MachineClientConfig> {
        let server = required(self.server)?;
        let company_name = required(self.company_name)?;
        let username = required(self.username)?;
        let auth_file = required(self.auth_file)?;
        let cookie_file = required(self.cookie_file)?;
        validate_server(&server)?;
        let platform = self.platform.filter(|platform| !platform.is_empty());
        if let Some(platform) = &platform {
            validate_platform(platform)?;
        }

        Ok(MachineClientConfig {
            cookie_file: PathBuf::from(cookie_file),
            config: Config {
                company_name,
                username,
                password: self.password,
                platform,
                code: None,
                device_name: self
                    .device_name
                    .or_else(|| Some("OpenWrt-CorpLink-RS".to_string())),
                device_id: self.device_id,
                public_key: self.public_key,
                private_key: self.private_key,
                server: Some(server),
                interface_name: self.interface_name.or_else(|| Some("corplink".to_string())),
                debug_wg: None,
                conf_file: Some(auth_file),
                state: None,
                vpn_server_name: self.vpn_server_name,
                vpn_select_strategy: self.vpn_select_strategy,
                use_vpn_dns: None,
                log_directory: None,
                check_config_path: None,
                log_level: None,
                intranet_domain: None,
                vpn_server_ip_bypass: None,
                origin_dns: None,
                protocol_mode: None,
                performance: None,
            },
        })
    }
}

pub struct MachineClientConfig {
    pub config: Config,
    pub cookie_file: PathBuf,
}

fn required(value: Option<String>) -> Result<String> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing required machine configuration"))
}

fn validate_server(server: &str) -> Result<()> {
    let url = reqwest::Url::from_str(server)
        .map_err(|_| anyhow!("invalid machine server configuration"))?;
    if !matches!(url.scheme(), "http" | "https") || url.domain().is_none() {
        return Err(anyhow!("invalid machine server configuration"));
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<()> {
    if matches!(
        platform,
        PLATFORM_CORPLINK | PLATFORM_LDAP | PLATFORM_LARK | PLATFORM_OIDC
    ) {
        Ok(())
    } else {
        Err(anyhow!("invalid machine platform configuration"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MachineEvent {
    pub protocol_version: u32,
    pub event: Event,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_written: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_written: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_updated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

impl MachineEvent {
    pub fn new(event: Event) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            event,
            url: None,
            expires_at: None,
            cookie_written: None,
            auth_written: None,
            cookie_updated: None,
            code: None,
            message: None,
            retryable: None,
        }
    }

    pub fn error(code: &'static str, message: &'static str) -> Self {
        let mut event = Self::new(Event::Error);
        event.code = Some(code.to_string());
        event.message = Some(message.to_string());
        event.retryable = Some(false);
        event
    }
}

pub fn write_event<W: Write>(writer: &mut W, event: &MachineEvent) -> Result<()> {
    serde_json::to_writer(&mut *writer, event)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    TooLarge,
    Invalid,
    UnsupportedProtocol,
    UnknownAction,
}

impl RequestError {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "REQUEST_TOO_LARGE",
            Self::Invalid => "INVALID_REQUEST",
            Self::UnsupportedProtocol => "UNSUPPORTED_PROTOCOL_VERSION",
            Self::UnknownAction => "UNKNOWN_ACTION",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "Machine request exceeds the 64 KiB limit.",
            Self::Invalid => "Machine request is invalid.",
            Self::UnsupportedProtocol => "Machine protocol version is unsupported.",
            Self::UnknownAction => "Machine action is unsupported.",
        }
    }
}

pub fn parse_request(bytes: &[u8]) -> std::result::Result<MachineRequest, RequestError> {
    if bytes.len() > MAX_MACHINE_REQUEST_BYTES {
        return Err(RequestError::TooLarge);
    }

    let value: Value = serde_json::from_slice(bytes).map_err(|_| RequestError::Invalid)?;
    let object = value.as_object().ok_or(RequestError::Invalid)?;

    match object.get("protocol_version").and_then(Value::as_u64) {
        Some(version) if version == u64::from(PROTOCOL_VERSION) => {}
        Some(_) => return Err(RequestError::UnsupportedProtocol),
        None => return Err(RequestError::Invalid),
    }

    match object.get("action").and_then(Value::as_str) {
        Some("login") | Some("refresh_cookie") => {}
        Some(_) => return Err(RequestError::UnknownAction),
        None => return Err(RequestError::Invalid),
    }

    serde_json::from_value(value).map_err(|_| RequestError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_login_request_accepts_omitted_platform_and_preserves_password() {
        let request = br#"{
            "protocol_version": 1,
            "action": "login",
            "server": "https://feilian.example.test",
            "company_name": "Bettbox",
            "username": "alice",
            "password": "secret",
            "auth_file": "/data/user/0/app/files/config.json",
            "cookie_file": "/data/user/0/app/files/cookies.json"
        }"#;

        let request = parse_request(request).expect("request should parse");
        let client = request
            .into_client_config()
            .expect("password login should not require a platform hint");
        assert_eq!(client.config.password.as_deref(), Some("secret"));
        assert_eq!(client.config.platform, None);
    }
}
