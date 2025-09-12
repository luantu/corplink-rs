use std::fmt;
use tokio::fs;
use std::fs as std_fs;

use serde::{Deserialize, Serialize};
use log::{warn};

use crate::state::State;
use crate::utils;

const DEFAULT_DEVICE_NAME: &str = "DollarOS";
const DEFAULT_INTERFACE_NAME: &str = "corplink";

pub const PLATFORM_LDAP: &str = "ldap";
pub const PLATFORM_CORPLINK: &str = "feilian";
pub const PLATFORM_OIDC: &str = "OIDC";
// aka feishu
pub const PLATFORM_LARK: &str = "lark";
#[allow(dead_code)]
pub const PLATFORM_WEIXIN: &str = "weixin";
// aka dingding
#[allow(dead_code)]
pub const PLATFORM_DING_TALK: &str = "dingtalk";
// unknown
#[allow(dead_code)]
pub const PLATFORM_AAD: &str = "aad";

pub const STRATEGY_LATENCY: &str = "latency";
pub const STRATEGY_DEFAULT: &str = "default";

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub company_name: String,
    pub username: String,
    pub password: Option<String>,
    pub platform: Option<String>,
    pub code: Option<String>,
    pub device_name: Option<String>,
    pub device_id: Option<String>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub server: Option<String>,
    pub interface_name: Option<String>,
    pub debug_wg: Option<bool>,
    #[serde(skip_serializing)]
    pub conf_file: Option<String>,
    pub state: Option<State>,
    pub vpn_server_name: Option<String>,
    pub vpn_select_strategy: Option<String>,
    pub use_vpn_dns: Option<bool>,
    pub log_directory: Option<String>,
    pub check_config_path: Option<String>,
    pub log_level: Option<String>,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = serde_json::to_string_pretty(self).unwrap();
        write!(f, "{}", s)
    }
}

impl Config {
    pub async fn from_file(file: &str) -> Config {
        let conf_str = fs::read_to_string(file)
            .await
            .unwrap_or_else(|e| panic!("failed to read config file {}: {}", file, e));

        let mut conf: Config = serde_json::from_str(&conf_str[..])
            .unwrap_or_else(|e| panic!("failed to parse config file {}: {}", file, e));

        conf.conf_file = Some(file.to_string());
        let mut update_conf = false;
        if conf.interface_name.is_none() {
            conf.interface_name = Some(DEFAULT_INTERFACE_NAME.to_string());
            update_conf = true;
        }
        if conf.device_name.is_none() {
            conf.device_name = Some(DEFAULT_DEVICE_NAME.to_string());
            update_conf = true;
        }
        if conf.device_id.is_none() {
            conf.device_id = Some(format!(
                "{:x}",
                md5::compute(conf.device_name.clone().unwrap())
            ));
            update_conf = true;
        }
        match &conf.private_key {
            Some(private_key) => match conf.public_key {
                Some(_) => {
                    // both keys exist, do nothing
                }
                None => {
                    // only private key exists, generate public from private
                    let public_key = utils::gen_public_key_from_private(private_key).unwrap();
                    conf.public_key = Some(public_key);
                    update_conf = true;
                }
            },
            None => {
                // no key exists, generate new
                let (public_key, private_key) = utils::gen_wg_keypair();
                (conf.public_key, conf.private_key) = (Some(public_key), Some(private_key));
                update_conf = true;
            }
        }
        if update_conf {
            conf.save().await;
        }
        conf
    }

    pub async fn save(&self) {
        let file = self.conf_file.as_ref().unwrap();
        let data = format!("{}", &self);
        fs::write(file, data).await.unwrap();
    }
}

#[derive(Serialize, Clone)]
pub struct WgConf {
    // standard wg conf
    pub address: String,
    pub address6: String,
    pub peer_address: String,
    pub mtu: u32,
    pub public_key: String,
    pub private_key: String,
    pub peer_key: String,
    pub route: Vec<String>,

    // extra confs
    pub dns: String,

    // corplink confs
    pub protocol: i32,
}

// 检查配置结构体
#[derive(Deserialize)]
pub struct CheckConfig {
    pub feishu_webhook_url: String,
    // 可选字段，提供默认值
    #[serde(default = "default_config_yaml_path")]
    pub config_yaml_path: String,
    #[serde(default = "default_proxy_name")]
    pub proxy_name_to_update: String,
    // SVN认证信息
    #[serde(default = "default_svn_username")]
    pub svn_username: String,
    #[serde(default = "default_svn_password")]
    pub svn_password: String,
}

fn default_config_yaml_path() -> String {
    String::from("")
}

fn default_proxy_name() -> String {
    String::from("")
}

fn default_svn_username() -> String {
    String::from("")
}

fn default_svn_password() -> String {
    String::from("")
}

/// 读取check_config.json配置文件
pub fn read_check_config(config_path: Option<&str>) -> CheckConfig {
    // 如果没有提供路径，使用默认路径
    let config_path = config_path.unwrap_or("/Users/luantu/corplink/check_config.json");
    match std_fs::read_to_string(config_path) {
        Ok(content) => {
            match serde_json::from_str(&content) {
                Ok(config) => config,
                Err(e) => {
                    warn!("Failed to parse check_config.json: {}, using default values", e);
                    CheckConfig {
                        feishu_webhook_url: String::from("https://open.feishu.cn/open-apis/bot/v2/hook/d8a2f118-30db-4453-b141-9570dcd8ad20"),
                        config_yaml_path: default_config_yaml_path(),
                        proxy_name_to_update: default_proxy_name(),
                        svn_username: default_svn_username(),
                        svn_password: default_svn_password(),
                    }
                }
            }
        },
        Err(e) => {
            warn!("Failed to read check_config.json: {}, using default values", e);
            CheckConfig {
                feishu_webhook_url: String::from("https://open.feishu.cn/open-apis/bot/v2/hook/d8a2f118-30db-4453-b141-9570dcd8ad20"),
                config_yaml_path: default_config_yaml_path(),
                proxy_name_to_update: default_proxy_name(),
                svn_username: default_svn_username(),
                svn_password: default_svn_password(),
            }
        }
    }
}
