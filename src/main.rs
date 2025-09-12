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
mod yaml;

use std::time::Duration;
use log;
use chrono::{DateTime, Local};
use flexi_logger::{Logger, FileSpec, WriteMode, DeferredNow, Record, LoggerHandle, FlexiLoggerError};
use std::path::PathBuf;

/// 自定义日志格式
fn log_format(writer: &mut dyn std::io::Write, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
    let local_time: DateTime<Local> = (*now.now()).into();
    write!(
        writer,
        "{} [{}] {}",
        local_time.format("%Y-%m-%d %H:%M:%S%.3f"),
        record.level(),
        record.args()
    )
}

/// 初始化日志系统，使用指定的日志目录和日志级别或默认值
fn initialize_logger(log_directory: Option<&str>, log_level: Option<&str>) -> LoggerHandle {
    // 从配置中获取log_directory
    let log_dir = if let Some(dir) = log_directory {
        PathBuf::from(dir)
    } else {
        PathBuf::from(".")
    };
    
    // 使用指定的日志级别或默认级别"info"
    let log_level = log_level.unwrap_or("info");
    
    // 使用Box<dyn FnOnce()>统一闭包类型
    let loggers: Vec<Box<dyn FnOnce() -> Result<LoggerHandle, FlexiLoggerError>>> = vec![
        // 1. 配置文件指定的目录
        Box::new(move || {
            let log_file_path = FileSpec::default()
                .directory(&log_dir)  // 使用配置文件中的日志目录
                .basename("corplink")  // 日志文件基础名称
                .suffix("log");  // 日志文件后缀
            Logger::try_with_env_or_str(log_level)
                .unwrap()
                .log_to_file(log_file_path)
                .write_mode(WriteMode::BufferAndFlush)
                .format(log_format)
                .duplicate_to_stderr(flexi_logger::Duplicate::All)
                .start()
        }),
        // 2. 当前目录
        Box::new(|| {
            let log_file_path = FileSpec::default()
                .directory(".")  // 日志文件放在程序当前目录
                .basename("corplink")  // 日志文件基础名称
                .suffix("log");  // 日志文件后缀
            Logger::try_with_env_or_str(log_level)
                .unwrap()
                .log_to_file(log_file_path)
                .write_mode(WriteMode::BufferAndFlush)
                .format(log_format)
                .duplicate_to_stderr(flexi_logger::Duplicate::All)
                .start()
        }),
        // 3. 临时目录
        Box::new(|| {
            let temp_dir = std::env::temp_dir();
            let log_file_path = FileSpec::default()
                .directory(temp_dir)
                .basename("corplink")
                .suffix("log");
            Logger::try_with_env_or_str(log_level)
                .unwrap()
                .log_to_file(log_file_path)
                .write_mode(WriteMode::BufferAndFlush)
                .format(log_format)
                .duplicate_to_stderr(flexi_logger::Duplicate::All)
                .start()
        }),
        // 4. 仅控制台输出（作为最后的备选）
        Box::new(|| {
            Logger::try_with_env_or_str(log_level)
                .unwrap()
                .format(log_format)
                .duplicate_to_stderr(flexi_logger::Duplicate::All)
                .start()
        })
    ];
    
    // 尝试初始化日志系统，使用第一个成功的配置
    for logger in loggers {
        if let Ok(handle) = logger() {
            return handle;
        }
    }
    
    // 如果所有日志配置都失败，至少在控制台打印错误信息
    eprintln!("[ERROR] Failed to initialize logger with all configurations. Continuing without file logging.");
    // 使用基本的控制台日志作为最后的备选
    Logger::try_with_env_or_str("info")
        .unwrap()
        .log_to_stdout()
        .format(log_format)
        .start()
        .expect("Failed to initialize basic console logging")
}

#[cfg(windows)]
use is_elevated;

#[cfg(target_os = "macos")]
use dns::DNSManager;

use std::env;
use std::process::exit;

use client::Client;
use config::{Config, WgConf, read_check_config};
use utils::{check_privilege, get_interface_address, print_version, send_feishu_message};

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



#[tokio::main]
async fn main() {
    // 先解析命令行参数获取配置文件路径
    let conf_file = parse_arg();
    // 提前克隆conf_file以避免借用问题
    let conf_file_clone = conf_file.clone();
    
    // 尝试加载配置文件，即使失败也继续运行
    let mut conf = match std::panic::catch_unwind(|| {
        let file = conf_file.clone();
        async move {
            Config::from_file(&file).await
        }
    }) {
        Ok(future) => future.await,
        Err(_) => {
            eprintln!("[ERROR] Failed to load config file, using default configuration");
            Config {
                company_name: String::from("default"),
                username: String::from("user"),
                password: None,
                platform: None,
                code: None,
                device_name: Some(DEFAULT_DEVICE_NAME.to_string()),
                device_id: None,
                public_key: None,
                private_key: None,
                server: None,
                interface_name: Some(DEFAULT_INTERFACE_NAME.to_string()),
                debug_wg: None,
                conf_file: Some(conf_file_clone),
                state: None,
                vpn_server_name: None,
                vpn_select_strategy: None,
                use_vpn_dns: None,
                log_directory: None,
                check_config_path: None,
                log_level: None,
            }
        }
    };
    
    // 初始化日志系统，使用配置文件中的log_directory和log_level设置
    // 如果配置中没有提供，使用默认值
    let _logger = initialize_logger(conf.log_directory.as_deref(), conf.log_level.as_deref());
    
    log::info!("CorpLink start...");
    // 读取check_config.json配置，使用Config中定义的路径
    let check_config = read_check_config(conf.check_config_path.as_deref());
    log::info!("Feishu URL  : {}", check_config.feishu_webhook_url);
    log::info!("Config Path : {}", check_config.config_yaml_path);
    log::info!("Proxy Name  : {}", check_config.proxy_name_to_update);

    print_version();
    check_privilege();

    let name = conf.interface_name.clone().unwrap_or_else(|| DEFAULT_INTERFACE_NAME.to_string());

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

const DEFAULT_DEVICE_NAME: &str = "wg-corplink";
const DEFAULT_INTERFACE_NAME: &str = "wg-corplink";

// 全局重试参数：最长重试时间为120分钟，初始重试间隔为5秒
const MAX_RETRY_TIME_MINUTES: u64 = 120;
const INITIAL_RETRY_INTERVAL_SECONDS: u64 = 5;
const MAX_RETRY_INTERVAL_SECONDS: u64 = 60;



// Config结构体的实现已经在config.rs中定义

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
                        let retry_msg = format!("⚠️ [VPN连接失败] 将在 {} 秒后重试 (第 {} 次尝试)", 
                                           retry_interval, connection_attempts);
                        log::info!("{}\n{}", retry_msg, e);
                        
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
                    let svn_username = check_config.svn_username.clone();
                    let svn_password = check_config.svn_password.clone();
                    tokio::spawn(async move {
                        match get_interface_address(&name_async) {
                            Ok(ip_address) => {
                                let message = format!("✅ [VPN连接成功] IP地址: {}", ip_address);
                                log::info!("{}", message);
                                
                                // 更新配置文件中的代理server地址
                                if let Err(e) = yaml::update_config_yaml(&config_yaml_path, &ip_address, &proxy_name, &svn_username, &svn_password) {
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
