mod api;
mod client;
mod config;
mod dns;
mod performance;
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

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

use client::Client;
use config::{Config, WgConf, read_check_config};
use utils::{get_interface_address, print_version, send_feishu_message};
use serde_json::Value;

fn print_usage_and_exit(name: &str, conf: &str) {
    println!("usage:\n\t{} {}", name, conf);
    exit(1);
}

/// 生成账号信息前缀，用于飞书通知中标识账号
fn account_info(conf: &Config) -> String {
    format!("账号: {}\n", conf.username)
}

/// 检查cookie的过期时间，并在到期前一天通过飞书发送通知
async fn check_cookie_expiry(conf: &Config, feishu_webhook_url: &str) {
    // 构建cookie文件路径
    if let Some(conf_file) = &conf.conf_file {
        let dir = match std::path::Path::new(conf_file).parent() {
            Some(dir) => dir,
            None => std::path::Path::new("."),
        };
        let cookie_file = dir.join(format!(
            "{}_{}",
            conf.interface_name.clone().unwrap_or_else(|| "corplink".to_string()),
            "cookies.json"
        ));
        
        // 读取cookie文件
        if let Ok(cookie_content) = std::fs::read_to_string(&cookie_file) {
            // 解析JSON内容
            if let Ok(cookies) = serde_json::from_str::<Value>(&cookie_content) {
                if let Some(cookies_array) = cookies.as_array() {
                    let now = chrono::Utc::now();
                    let one_day = chrono::Duration::days(1);
                    
                    for cookie in cookies_array {
                        if let Some(expires) = cookie.get("expires").and_then(|e| e.get("AtUtc")) {
                            if let Some(expires_str) = expires.as_str() {
                                if let Ok(expires_time) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                                    let expires_utc = expires_time.with_timezone(&chrono::Utc);
                                    let time_left = expires_utc - now;
                                    
                                    // 检查是否在到期前一天
                                    if time_left <= one_day && time_left > chrono::Duration::zero() {
                                        let cookie_name = cookie.get("raw_cookie")
                                            .and_then(|rc| rc.as_str())
                                            .unwrap_or("unknown");
                                        let days_left = time_left.num_days();
                                        let hours_left = time_left.num_hours() % 24;
                                        
                                        let message = format!(
                                            "[Cookie即将到期]\n{}Cookie将在 {} 天 {} 小时后到期\nCookie: {}",
                                            account_info(conf),
                                            days_left, hours_left, cookie_name
                                        );
                                        
                                        log::info!("{}", message);
                                        if let Err(err) = send_feishu_message(feishu_webhook_url, &message).await {
                                            log::warn!("Failed to send cookie expiry notification: {}", err);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
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
async fn main() -> anyhow::Result<()> {
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
                Ok(Config {
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
                    intranet_domain: None,
                    vpn_server_ip_bypass: None,
                    origin_dns: None,
                    protocol_mode: None,
                    performance: None,
                })
            }
    }?;
    
    // 初始化日志系统，使用配置文件中的log_directory和log_level设置
    // 如果配置中没有提供，使用默认值
    let _logger = initialize_logger(conf.log_directory.as_deref(), conf.log_level.as_deref());
    
    log::info!("CorpLink start...");
    // 读取check_config.json配置，使用Config中定义的路径。
    // 文件不存在时返回 None，跳过所有飞书通知/yaml更新操作。
    let check_config = read_check_config(conf.check_config_path.as_deref());
    if let Some(cc) = &check_config {
        log::info!("Feishu URL  : {}", cc.feishu_webhook_url);
        log::info!("Config Path : {}", cc.config_yaml_path);
        log::info!("Proxy Name  : {}", cc.proxy_name_to_update);
    } else {
        log::info!("check_config.json not found, notification/yaml operations are disabled");
    }
    
    // 保存飞书webhook_url到变量，用于异常退出时发送通知
    let feishu_webhook_url = check_config.as_ref().map(|c| c.feishu_webhook_url.clone()).unwrap_or_default();
    let feishu_webhook_url_clone_panic = feishu_webhook_url.clone();

    // 账号信息前缀，用于所有飞书通知
    let account_str = account_info(&conf);
    let account_str_clone_panic = account_str.clone();
    let account_str_clone = account_str.clone();
    
    // 启动一个异步任务，每天检查一次cookie的过期时间
    let conf_clone = conf.clone();
    let feishu_webhook_url_clone = feishu_webhook_url.clone();
    tokio::spawn(async move {
        loop {
            // 检查cookie的过期时间
            if !feishu_webhook_url_clone.is_empty() {
                check_cookie_expiry(&conf_clone, &feishu_webhook_url_clone).await;
            }
            // 等待24小时后再次检查
            tokio::time::sleep(tokio::time::Duration::from_secs(24 * 60 * 60)).await;
        }
    });
    
    // 设置全局panic钩子，捕获所有未处理的panic并发送飞书通知
    std::panic::set_hook(Box::new(move |panic_info| {
        let reason = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => s.to_string(),
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => s.to_string(),
                None => "未知错误".to_string(),
            },
        };
        let message = format!(
            "[VPN应用异常崩溃]\n{}原因: {}\n位置: {:?}",
            account_str_clone_panic, reason, panic_info.location()
        );

        log::error!("{}", message);

        // panic 前若已修改过系统 DNS，先恢复到启动时的原始值，避免污染系统
        #[cfg(target_os = "macos")]
        dns::DNSManager::global_restore_dns();
        
        // 同步方式发送飞书通知，避免在panic时创建新的运行时
        // 注意：这里使用block_on可能会在某些环境下失败，但在大多数情况下应该可以工作
        // 如果失败，我们也不需要处理，因为程序已经在panic中
        if !feishu_webhook_url_clone_panic.is_empty() {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() {
                let _ = rt.block_on(utils::send_feishu_message(&feishu_webhook_url_clone_panic, &message));
            }
        }
    }));

    print_version();
    
    // 检查权限
    if let Err(_) = utils::check_privilege() {
        log::error!("permission denied, try to run with sudo or as root");
        // 权限不足，发送飞书通知
        let message = format!("[VPN应用异常退出]\n{}权限不足，请使用sudo或管理员权限运行", account_str);
        if !feishu_webhook_url.is_empty() {
            let _ = utils::send_feishu_message(&feishu_webhook_url, &message).await;
        }
        exit(EPERM);
    }

    let name = conf.interface_name.clone().unwrap_or_else(|| DEFAULT_INTERFACE_NAME.to_string());

    #[cfg(target_os = "macos")]
    let use_vpn_dns = conf.use_vpn_dns.unwrap_or(false);

    // 在 VPN 修改 DNS 之前先抓取"原始系统 DNS"作为后续 restore 的基准。
    // 用户若在配置中指定了 origin_dns，则优先使用配置值；否则动态从系统抓取。
    #[cfg(target_os = "macos")]
    if use_vpn_dns {
        if let Err(e) = DNSManager::init_origin_dns(conf.origin_dns.as_deref()) {
            log::warn!(
                "failed to capture origin dns, dns restore may not work correctly: {}",
                e
            );
        }
    }

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
                let _ = conf.save().await;
            }
            Err(err) => {
                log::error!(
                    "failed to fetch company server from company name {}: {}",
                    conf.company_name,
                    err
                );
                // 获取公司服务器失败，发送飞书通知
                let message = format!("[VPN应用异常退出]\n{}获取公司服务器失败: {}", account_str, err);
                if !feishu_webhook_url.is_empty() {
                    let _ = utils::send_feishu_message(&feishu_webhook_url, &message).await;
                }
                exit(EPERM);
            }
        },
    }

    let with_wg_log = conf.debug_wg.unwrap_or_default();
    let mut c = Client::new(conf)?;
    let mut logout_retry = true;
    let mut should_exit = false;

const DEFAULT_DEVICE_NAME: &str = "wg-corplink";
const DEFAULT_INTERFACE_NAME: &str = "wg-corplink";

// 全局重试参数：初始重试间隔为5秒
const INITIAL_RETRY_INTERVAL_SECONDS: u64 = 5;
const MAX_RETRY_INTERVAL_SECONDS: u64 = 10;



// Config结构体的实现已经在config.rs中定义

    // 外层循环用于支持VPN重连
    loop {
        let wg_conf: Option<WgConf>;
        
        // 登录和连接VPN的逻辑 - 添加全局重试机制
        let mut retry_interval = INITIAL_RETRY_INTERVAL_SECONDS;
        let mut connection_attempts = 0;
        let mut dns_restored = false;
        
        loop {
            // 移除最大重试时间限制，改为一直重试
            // if start_retry_time.elapsed().as_secs() > MAX_RETRY_TIME_MINUTES * 60 {
            //     log::error!("Maximum retry time ({} minutes) reached. Exiting...", MAX_RETRY_TIME_MINUTES);
            //     exit(ETIMEDOUT);
            // }
            
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
                        
                        // 检查是否是连接超时或DNS解析错误
                        if e.to_string().contains("operation timed out") || e.to_string().contains("dns error") {
                            // 尝试解析服务器域名的DNS
                            if let Some(server) = &c.conf.server {
                                // 提取域名部分
                                let domain = server
                                    .trim_start_matches("https://")
                                    .trim_start_matches("http://")
                                    .split_once(':')
                                    .map(|(d, _)| d)
                                    .unwrap_or(server);
                                
                                log::info!("Checking DNS resolution for domain: {}", domain);
                                if !utils::resolve_dns(domain) {
                                    log::warn!("DNS resolution failed for domain: {}", domain);

                                    // 在macOS上恢复 DNS 到启动时抓取的"原始系统 DNS"
                                    // （若配置了 origin_dns，init 时已使用其作为恢复目标）
                                    #[cfg(target_os = "macos")]
                                    if use_vpn_dns && !dns_restored {
                                        log::info!("Attempting to restore default DNS settings");
                                        DNSManager::global_restore_dns();
                                        dns_restored = true;

                                        // 恢复后立即再次尝试解析域名
                                        log::info!("Checking DNS resolution again after restoring default DNS");
                                        if utils::resolve_dns(domain) {
                                            log::info!("DNS resolution succeeded after restoring default DNS");
                                        } else {
                                            log::warn!("DNS resolution still failed after restoring default DNS");
                                        }
                                    }
                                }
                            }
                        }
                        
                        log::info!("Waiting {} seconds before retrying... (attempt {})", 
                                retry_interval, connection_attempts);
                        
                        // 发送飞书通知
                        let feishu_url = check_config.as_ref().map(|c| c.feishu_webhook_url.clone()).unwrap_or_default();
                        let retry_msg = format!("[VPN连接失败]\n{}将在 {} 秒后重试 (第 {} 次尝试)", 
                                           account_str_clone, retry_interval, connection_attempts);
                        log::info!("{}", retry_msg);
                        
                        if !feishu_url.is_empty() {
                            if let Err(msg_err) = send_feishu_message(&feishu_url, &retry_msg).await {
                                log::warn!("Failed to send feishu message: {}", msg_err);
                            }
                        }
                        
                        // 等待重试间隔时间
                        tokio::time::sleep(Duration::from_secs(retry_interval)).await;
                        // 指数退避重试间隔，但不超过最大间隔
                        retry_interval = std::cmp::min(retry_interval * 2, MAX_RETRY_INTERVAL_SECONDS);
                        
                        // 重建Client，避免状态问题
                        let new_conf = Config::from_file(&conf_file).await?;
                        c = Client::new(new_conf)?;
                        logout_retry = true;
                    }
                }
            };
        }
        
        // 在每次循环迭代中克隆name，避免借用问题
        let name_clone = name.clone();
        let wg_conf = wg_conf.unwrap();
        let mut exit_code = 0;
        
        // 检查是否在内网环境
        if wg_conf.use_intranet {
            log::info!("在内网环境，跳过WireGuard启动和配置");
            
            // 获取接口地址并发送飞书消息
            let intranet_ip = wg_conf.address.split('/').next().unwrap_or("unknown");
            let message = format!("[内网连接成功]\n{}检测到内网环境\nIP地址: {}", account_str, intranet_ip);
            log::info!("{}", message);
            
            // 更新配置文件中的代理server地址
            if let Some(cc) = &check_config {
                if !cc.config_yaml_path.is_empty() {
                    if let Err(e) = yaml::update_config_yaml(&cc.config_yaml_path, intranet_ip, &cc.proxy_name_to_update, &cc.svn_username, &cc.svn_password) {
                        log::warn!("Failed to update config.yaml: {}", e);
                    } else {
                        log::info!("Successfully updated {} server address to {}", cc.proxy_name_to_update, intranet_ip);
                    }
                }
                if !cc.feishu_webhook_url.is_empty() {
                    if let Err(e) = send_feishu_message(&cc.feishu_webhook_url, &message).await {
                        log::warn!("Failed to send feishu message: {}", e);
                    }
                }
            }
            
            // 仅运行保活逻辑
            tokio::select! {
                // handle signal
                _ = async {
                    // 处理SIGINT和SIGTERM信号
                    #[cfg(unix)]
                    {
                        let mut sigint = signal(SignalKind::interrupt()).unwrap();
                        let mut sigterm = signal(SignalKind::terminate()).unwrap();
                        
                        tokio::select! {
                            _ = sigint.recv() => {
                                log::info!("SIGINT received");
                            },
                            _ = sigterm.recv() => {
                                log::info!("SIGTERM received");
                            },
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        match tokio::signal::ctrl_c().await {
                            Ok(_) => {},
                            Err(e) => {
                                log::warn!("failed to receive signal: {}",e);
                            },
                        }
                        log::info!("ctrl+c received");
                    }
                    should_exit = true;
                } => {},

                // keep alive
                _ = c.keep_alive_vpn(&wg_conf, 10) => {
                    exit_code = ETIMEDOUT;
                    log::warn!("VPN keep alive failed, try to reconnect...");
                },
            }
        } else {
            // 非内网环境，执行正常的VPN启动和配置逻辑
            log::info!("start wg-corplink for {}", &name_clone);
            let protocol = wg_conf.protocol;
            wg::start_wg_go(&name_clone, protocol, with_wg_log)?;
            let mut uapi = wg::UAPIClient { name: name_clone.clone() };
            let perf_conf = c.conf.performance.as_ref();
            uapi.config_wg(&wg_conf, perf_conf).await?;
            
            // 获取接口地址并发送飞书消息
            let name_async = name_clone.clone();
            let feishu_url = check_config.as_ref().map(|c| c.feishu_webhook_url.clone()).unwrap_or_default();
            let config_yaml_path = check_config.as_ref().map(|c| c.config_yaml_path.clone()).unwrap_or_default();
            let proxy_name = check_config.as_ref().map(|c| c.proxy_name_to_update.clone()).unwrap_or_default();
            let svn_username = check_config.as_ref().map(|c| c.svn_username.clone()).unwrap_or_default();
            let svn_password = check_config.as_ref().map(|c| c.svn_password.clone()).unwrap_or_default();
            let account_str2 = account_str_clone.clone();
            tokio::spawn(async move {
                match get_interface_address(&name_async) {
                    Ok(ip_address) => {
                        let message = format!("[VPN连接成功]\n{}IP地址: {}", account_str2, ip_address);
                        // log::info!("{}", message);
                        
                        // 更新配置文件中的代理server地址
                        if !config_yaml_path.is_empty() {
                            if let Err(e) = yaml::update_config_yaml(&config_yaml_path, &ip_address, &proxy_name, &svn_username, &svn_password) {
                                log::warn!("Failed to update config.yaml: {}", e);
                            } else {
                                log::info!("Successfully updated {} server address to {}", proxy_name, ip_address);
                            }
                        }
                        
                        if !feishu_url.is_empty() {
                            if let Err(e) = send_feishu_message(&feishu_url, &message).await {
                                log::warn!("Failed to send feishu message: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        // 将错误转换为字符串，确保Send安全
                        let err_str = format!("{}", e);
                        log::warn!("Failed to get interface address: {}", err_str);
                        let message = format!("[VPN连接成功]\n{}未能获取IP地址: {}", account_str2, err_str);
                        log::warn!("{}", message);
                        if !feishu_url.is_empty() {
                            if let Err(msg_err) = send_feishu_message(&feishu_url, &message).await {
                                // 将错误转换为字符串，确保Send安全
                                let msg_err_str = format!("{}", msg_err);
                                log::warn!("Failed to send feishu message: {}", msg_err_str);
                            }
                        }
                    }
                }
            });

            #[cfg(target_os = "macos")]
            if use_vpn_dns {
                if let Err(err) = DNSManager::global_apply_dns(vec![&wg_conf.dns], vec![]) {
                    log::warn!("failed to set dns: {}", err);
                }
            }

            tokio::select! {
                // handle signal
                _ = async {
                    // 处理SIGINT和SIGTERM信号
                    #[cfg(unix)]
                    {
                        let mut sigint = signal(SignalKind::interrupt()).unwrap();
                        let mut sigterm = signal(SignalKind::terminate()).unwrap();
                        
                        tokio::select! {
                            _ = sigint.recv() => {
                                log::info!("SIGINT received");
                            },
                            _ = sigterm.recv() => {
                                log::info!("SIGTERM received");
                            },
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        match tokio::signal::ctrl_c().await {
                            Ok(_) => {},
                            Err(e) => {
                                log::warn!("failed to receive signal: {}",e);
                            },
                        }
                        log::info!("ctrl+c received");
                    }
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
            // 先停止WireGuard服务，再断开VPN连接
            // 这样可以避免在断开连接时产生网络连接已关闭的错误
            wg::stop_wg_go();
            
            // 短暂延迟，确保WireGuard服务已经完全停止
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            
            // 断开VPN连接
            match c.disconnect_vpn(&wg_conf).await {
                Ok(_) => {}
                Err(e) => log::warn!("failed to disconnect vpn: {}", e),
            };

            #[cfg(target_os = "macos")]
            if use_vpn_dns {
                DNSManager::global_restore_dns();
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
        
        // 发送重连通知到飞书（如果配置允许）
        if let Some(cc) = &check_config {
            if cc.send_disconnect_notification && !cc.feishu_webhook_url.is_empty() {
                let feishu_url = cc.feishu_webhook_url.clone();
                let account_str3 = account_str_clone.clone();
                tokio::spawn(async move {
                    let message = format!("[VPN连接断开]\n{}正在尝试重连...", account_str3);
                    if let Err(e) = send_feishu_message(&feishu_url, &message).await {
                        // 将错误转换为字符串，确保Send安全
                        let err_str = format!("{}", e);
                        log::warn!("Failed to send feishu message: {}", err_str);
                    }
                });
            } else {
                log::info!("VPN断开重连通知已禁用");
            }
        } else {
            log::info!("check_config.json 不存在，跳过断开重连通知");
        }
        
        // 重置登出重试标志
        logout_retry = true;
    }
}
