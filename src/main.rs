mod api;
mod client;
mod config;
mod dns;
mod qrcode;
mod resp;
mod state;
mod template;
mod totp;
mod utils;
mod wg;

use std::io::Write;
use std::time::Duration;

#[cfg(windows)]
use is_elevated;

#[cfg(target_os = "macos")]
use dns::DNSManager;

use env_logger;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{exit, Command};
use serde::{Deserialize};

use client::Client;
use config::{Config, WgConf};
use utils::{get_interface_address, send_feishu_message};

fn print_usage_and_exit(name: &str, conf: &str) {
    println!("usage:\n\t{} {}", name, conf);
    exit(1);
}

fn parse_arg() -> String {
    let mut conf_file = String::from("config.json");
    let mut args = env::args();
    // pop name
    let name = args.next().unwrap();
    match args.len() {
        0 => {}
        1 => {
            // pop arg
            let arg = args.next().unwrap();
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage_and_exit(&name, &conf_file);
                }
                _ => {
                    conf_file = arg;
                }
            }
        }
        _ => {
            print_usage_and_exit(&name, &conf_file);
        }
    }
    conf_file
}

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ETIMEDOUT: i32 = 110;

// 检查配置结构体
#[derive(Deserialize)]
struct CheckConfig {
    feishu_webhook_url: String,
    // 可选字段，提供默认值
    #[serde(default = "default_config_yaml_path")]
    config_yaml_path: String,
    #[serde(default = "default_proxy_name")]
    proxy_name_to_update: String,
}

fn default_config_yaml_path() -> String {
    String::from("/Users/luantu/corplink/Pavadan/config.yaml")
}

fn default_proxy_name() -> String {
    String::from("Home-Mac(7897)")
}

// 读取check_config.json配置文件
fn read_check_config() -> CheckConfig {
    let config_path = "/Users/luantu/corplink/check_config.json";
    match fs::read_to_string(config_path) {
        Ok(content) => {
            match serde_json::from_str(&content) {
                Ok(config) => config,
                Err(e) => {
                    log::warn!("Failed to parse check_config.json: {}, using default values", e);
                    CheckConfig {
                        feishu_webhook_url: String::from("https://open.feishu.cn/open-apis/bot/v2/hook/d8a2f118-30db-4453-b141-9570dcd8ad20"),
                        config_yaml_path: default_config_yaml_path(),
                        proxy_name_to_update: default_proxy_name(),
                    }
                }
            }
        },
        Err(e) => {
            log::warn!("Failed to read check_config.json: {}, using default values", e);
            CheckConfig {
                feishu_webhook_url: String::from("https://open.feishu.cn/open-apis/bot/v2/hook/d8a2f118-30db-4453-b141-9570dcd8ad20"),
                config_yaml_path: default_config_yaml_path(),
                proxy_name_to_update: default_proxy_name(),
            }
        }
    }
}

use chrono::{Local, DateTime, Utc};

#[tokio::main]
async fn main() {
    // 初始化日志系统，默认输出info及以上级别的日志到控制台
    // 使用本地时区来显示时间戳
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let local_time: DateTime<Local> = Utc::now().into();
            writeln!(
                buf,
                "{} [{}] {}",
                local_time.format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.args()
            )
        })
        .init();

    // 读取check_config.json配置
    let check_config = read_check_config();
    log::info!("Using feishu webhook URL: {}", check_config.feishu_webhook_url);
    log::info!("Using config.yaml path: {}", check_config.config_yaml_path);
    log::info!("Using proxy name: {}", check_config.proxy_name_to_update);

    print_version();
    check_privilege();

    let conf_file = parse_arg();
    let mut conf = Config::from_file(&conf_file).await;
    let name = conf.interface_name.clone().unwrap();

    #[cfg(target_os = "macos")]
    let use_vpn_dns = conf.use_vpn_dns.unwrap_or(false);

    match conf.server {
        Some(_) => {}
        None => match client::get_company_url(conf.company_name.as_str()).await {
            Ok(resp) => {
                log::info!(
                    "company name is {}(zh)/{}(en) server is {}",
                    resp.zh_name,
                    resp.en_name,
                    resp.domain
                );
                conf.server = Some(resp.domain);
                conf.save().await;
            }
            Err(err) => {
                log::error!(
                    "failed to fetch company server from company name {}: {}",
                    conf.company_name,
                    err
                );
                exit(EPERM);
            }
        },
    }

    let with_wg_log = conf.debug_wg.unwrap_or_default();
    let mut c = Client::new(conf).unwrap();
    let mut logout_retry = true;
    let mut should_exit = false;

    // 全局重试参数：最长重试时间为120分钟，初始重试间隔为5秒
    const MAX_RETRY_TIME_MINUTES: u64 = 120;
    const INITIAL_RETRY_INTERVAL_SECONDS: u64 = 5;
    const MAX_RETRY_INTERVAL_SECONDS: u64 = 60;

    // 外层循环用于支持VPN重连
    loop {
        let wg_conf: Option<WgConf>;
        
        // 登录和连接VPN的逻辑 - 添加全局重试机制
        let start_retry_time = std::time::Instant::now();
        let mut retry_interval = INITIAL_RETRY_INTERVAL_SECONDS;
        let mut connection_attempts = 0;
        
        loop {
            // 检查是否达到最大重试时间
            if start_retry_time.elapsed().as_secs() > MAX_RETRY_TIME_MINUTES * 60 {
                log::error!("Maximum retry time ({} minutes) reached. Exiting...", MAX_RETRY_TIME_MINUTES);
                exit(ETIMEDOUT);
            }
            
            connection_attempts += 1;
            
            if c.need_login() {
                log::info!("not login yet, try to login (attempt {})", connection_attempts);
                match c.login().await {
                    Ok(_) => log::info!("login success"),
                    Err(e) => {
                        log::warn!("Login failed: {}", e);
                        log::info!("Waiting {} seconds before retrying...", retry_interval);
                        tokio::time::sleep(Duration::from_secs(retry_interval)).await;
                        retry_interval = std::cmp::min(retry_interval * 2, MAX_RETRY_INTERVAL_SECONDS);
                        continue;
                    }
                };
            }
            
            log::info!("try to connect (attempt {})", connection_attempts);
            match c.connect_vpn().await {
                Ok(conf) => {
                    wg_conf = Some(conf);
                    break;
                }
                Err(e) => {
                    if logout_retry && e.to_string().contains("logout") {
                        // e contains detail message, so just print it out
                        log::warn!("{}", e);
                        logout_retry = false;
                        continue;
                    } else {
                        // 处理连接失败，进行重试
                        log::warn!("Connection failed: {}", e);
                        log::info!("Waiting {} seconds before retrying... (attempt {})", 
                                retry_interval, connection_attempts);
                        
                        // 发送飞书通知
                        let feishu_url = check_config.feishu_webhook_url.clone();
                        let retry_msg = format!("⚠️ VPN连接失败！\n错误信息: {}\n将在 {} 秒后重试 (第 {} 次尝试)", 
                                           e, retry_interval, connection_attempts);
                        log::info!("{}", retry_msg);
                        
                        if let Err(msg_err) = send_feishu_message(&feishu_url, &retry_msg).await {
                            log::warn!("Failed to send feishu message: {}", msg_err);
                        }
                        
                        // 等待重试间隔时间
                        tokio::time::sleep(Duration::from_secs(retry_interval)).await;
                        // 指数退避重试间隔，但不超过最大间隔
                        retry_interval = std::cmp::min(retry_interval * 2, MAX_RETRY_INTERVAL_SECONDS);
                        
                        // 重建Client，避免状态问题
                        let new_conf = Config::from_file(&conf_file).await;
                        c = Client::new(new_conf).unwrap();
                        logout_retry = true;
                    }
                }
            };
        }
        
        // 在每次循环迭代中克隆name，避免借用问题
        let name_clone = name.clone();
        log::info!("start wg-corplink for {}", &name_clone);
        let wg_conf = wg_conf.unwrap();
        let protocol = wg_conf.protocol;
        if !wg::start_wg_go(&name_clone, protocol, with_wg_log) {
            log::warn!("failed to start wg-corplink for {}", name_clone);
            exit(EPERM);
        }
        let mut uapi = wg::UAPIClient { name: name_clone.clone() };
        match uapi.config_wg(&wg_conf).await {
            Ok(_) => {
                // 获取接口地址并发送飞书消息
                    let name_async = name_clone.clone();
                    let feishu_url = check_config.feishu_webhook_url.clone();
                    let config_yaml_path = check_config.config_yaml_path.clone();
                    let proxy_name = check_config.proxy_name_to_update.clone();
                    tokio::spawn(async move {
                        match get_interface_address(&name_async) {
                            Ok(ip_address) => {
                                let message = format!("✅ [VPN连接成功] IP地址: {}", ip_address);
                                log::info!("{}", message);
                                
                                // 更新配置文件中的代理server地址
                                if let Err(e) = update_config_yaml(&config_yaml_path, &ip_address, &proxy_name) {
                                    log::warn!("Failed to update config.yaml: {}", e);
                                } else {
                                    log::info!("Successfully updated {} server address to {}", proxy_name, ip_address);
                                }
                                
                                if let Err(e) = send_feishu_message(&feishu_url, &message).await {
                                    log::warn!("Failed to send feishu message: {}", e);
                                }
                            },
                            Err(e) => {
                                // 将错误转换为字符串，确保Send安全
                                let err_str = format!("{}", e);
                                log::warn!("Failed to get interface address: {}", err_str);
                                let message = format!("✅ [VPN连接成功] 未能获取IP地址: {}", err_str);
                                log::warn!("{}", message);
                                if let Err(msg_err) = send_feishu_message(&feishu_url, &message).await {
                                    // 将错误转换为字符串，确保Send安全
                                    let msg_err_str = format!("{}", msg_err);
                                    log::warn!("Failed to send feishu message: {}", msg_err_str);
                                }
                            }
                        }
                    });
            },
            Err(err) => {
                log::error!("failed to config interface with uapi for {}: {}", name_clone, err);
                exit(EPERM);
            }
        }

        #[cfg(target_os = "macos")]
        let mut dns_manager = DNSManager::new();

        #[cfg(target_os = "macos")]
        if use_vpn_dns {
            match dns_manager.set_dns(vec![&wg_conf.dns], vec![]) {
                Ok(_) => {}
                Err(err) => {
                    log::warn!("failed to set dns: {}", err);
                }
            }
        }

        let mut exit_code = 0;
        tokio::select! {
            // handle signal
            _ = async {
                match tokio::signal::ctrl_c().await {
                    Ok(_) => {},
                    Err(e) => {
                        log::warn!("failed to receive signal: {}",e);
                    },
                }
                log::info!("ctrl+c received");
                should_exit = true;
            } => {},

            // keep alive
            _ = c.keep_alive_vpn(&wg_conf, 60) => {
                exit_code = ETIMEDOUT;
                log::warn!("VPN keep alive failed, try to reconnect...");
            },

            // check wg handshake and exit if timeout
            _ = async {
                uapi.check_wg_connection().await;
                log::warn!("last handshake timeout, try to reconnect...");
            } => {
                exit_code = ETIMEDOUT;
            },
        }

        // shutdown
        log::info!("disconnecting vpn...");
        match c.disconnect_vpn(&wg_conf).await {
            Ok(_) => {}
            Err(e) => log::warn!("failed to disconnect vpn: {}", e),
        };

        wg::stop_wg_go();

        #[cfg(target_os = "macos")]
        if use_vpn_dns {
            match dns_manager.restore_dns() {
                Ok(_) => {}
                Err(err) => {
                    log::warn!("failed to delete dns: {}", err);
                }
            }
        }

        // 如果是用户主动退出，则退出程序
        if should_exit {
            log::info!("reach exit");
            exit(exit_code);
        }
        
        // 短暂延迟后重新尝试连接
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        log::info!("preparing to reconnect VPN...");
        
        // 发送重连通知到飞书
        let feishu_url = check_config.feishu_webhook_url.clone();
        tokio::spawn(async move {
            let message = format!("❌ [VPN连接断开] 正在尝试重连...");
            if let Err(e) = send_feishu_message(&feishu_url, &message).await {
                // 将错误转换为字符串，确保Send安全
                let err_str = format!("{}", e);
                log::warn!("Failed to send feishu message: {}", err_str);
            }
        });
        
        // 重置登出重试标志
        logout_retry = true;
    }
}

/// 更新Pavadan/config.yaml文件中Home-Mac(7897)的server地址
fn update_config_yaml(config_path: &str, new_server: &str, proxy_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 检查文件是否存在
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Config file not found: {}", config_path)
        )));
    }
    
    // 执行svn update命令
    if let Some(dir) = Path::new(config_path).parent() {
        let output = Command::new("svn")
            .arg("update")
            .current_dir(dir)
            .output()?;
        
        if output.status.success() {
            log::info!("Successfully updated SVN working copy");
        } else {
            let error_message = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to update SVN working copy: {}", error_message);
        }
    }

    // 读取YAML文件内容
    let yaml_content = fs::read_to_string(config_path)?;
    
    // 解析YAML内容
    let mut config: serde_yaml::Value = serde_yaml::from_str(&yaml_content)?;
    
    // 查找proxies数组
    if let Some(proxies) = config.get_mut("proxies").and_then(serde_yaml::Value::as_sequence_mut) {
        // 遍历proxies数组，找到指定名称的项
        for proxy in proxies {
            if let Some(proxy_map) = proxy.as_mapping_mut() {
                // 获取name字段
                if let Some(serde_yaml::Value::String(name)) = proxy_map.get(&serde_yaml::Value::String("name".to_string())) {
                    if name == proxy_name {
                        // 更新server字段
                        proxy_map.insert(
                            serde_yaml::Value::String("server".to_string()),
                            serde_yaml::Value::String(new_server.to_string())
                        );
                        log::info!("Found and updated {} with new server address: {}", proxy_name, new_server);
                        break;
                    }
                }
            }
        }
    }
    
    // 将修改后的内容写回文件
    fs::write(config_path, serde_yaml::to_string(&config)?)?;
    log::info!("Successfully wrote updated config to {}", config_path);
    
    // 自动提交SVN变更
    let config_dir = match Path::new(config_path).parent() {
        Some(dir) => dir,
        None => {
            log::warn!("Failed to get parent directory of config file");
            return Ok(());
        }
    };
    
    // 执行svn commit命令
    let output = Command::new("svn")
        .arg("commit")
        .arg("-m")
        .arg(format!("Update {} server address to {}", proxy_name, new_server))
        .current_dir(config_dir)
        .output()?;
    
    if output.status.success() {
        log::info!("Successfully committed changes to SVN");
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to commit changes to SVN: {}", error_message);
    }
    
    Ok(())
}

fn check_privilege() {
    #[cfg(unix)]
    match sudo::escalate_if_needed() {
        Ok(_) => {}
        Err(_) => {
            log::error!("please run as root");
            exit(EPERM);
        }
    }

    #[cfg(windows)]
    if !is_elevated::is_elevated() {
        log::error!("please run as administrator");
        exit(EPERM);
    }
}

fn print_version() {
    let pkg_name = env!("CARGO_PKG_NAME");
    let pkg_version = env!("CARGO_PKG_VERSION");
    log::info!("running {}@{}", pkg_name, pkg_version);
}
