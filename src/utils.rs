use std::io::{self, BufRead};
use std::process::Command;


use anyhow::{anyhow, Context, Result};
use base32::Alphabet;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64;
use rand::rngs::OsRng;
use reqwest;
use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};
use log;

#[cfg(unix)]
use sudo;
#[cfg(windows)]
use is_elevated;



pub async fn read_line() -> Result<String> {
    io::stdin()
        .lock()
        .lines()
        .next()
        .context("stdin closed")?
        .context("failed to read line")
}

pub fn b32_decode(s: &str) -> Result<Vec<u8>> {
    base32::decode(Alphabet::RFC4648 { padding: true }, s)
        .context("failed to decode base32")
}

pub fn gen_wg_keypair() -> (String, String) {
    let csprng = OsRng {};
    let sk = StaticSecret::random_from_rng(csprng);
    let pk = PublicKey::from(&sk);
    (base64.encode(pk.to_bytes()), base64.encode(sk.to_bytes()))
}

pub fn gen_public_key_from_private(private_key: &String) -> Result<String> {
    let key = base64
        .decode(private_key)
        .with_context(|| format!("failed to base64 decode private key {private_key}"))?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("private key has invalid length"))?;
    let sk = StaticSecret::from(key);
    let public_key = PublicKey::from(&sk);
    Ok(base64.encode(public_key.to_bytes()))
}

pub fn b64_decode_to_hex(s: &str) -> Result<String> {
    let data = base64
        .decode(s)
        .with_context(|| format!("failed to base64 decode string {s}"))?;
    let mut hex = String::new();
    for c in data {
        hex.push_str(format!("{c:02x}").as_str());
    }
    Ok(hex)
}

/// 发送消息到飞书机器人
pub async fn send_feishu_message(robot_url: &str, message: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let payload = json!({
        "msg_type": "text",
        "content": {
            "text": message
        }
    });
    
    client
        .post(robot_url)
        .json(&payload)
        .send()
        .await
        .context("failed to send feishu message")?;
    
    Ok(())
}

/// 获取指定网络接口的IP地址
pub fn get_interface_address(interface_name: &str) -> Result<String, String> {
    // 执行ifconfig命令获取接口信息
    let output = match Command::new("ifconfig")
        .arg(interface_name)
        .output() {
            Ok(output) => output,
            Err(e) => return Err(format!("Failed to execute ifconfig: {}", e))
        };
    
    // 将输出转换为字符串
    let output_str = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to parse ifconfig output: {}", e))
    };
    
    // 遍历输出的每一行，查找inet地址
    for line in output_str.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "inet" && !parts[1].starts_with("127.") {
            // 返回不带掩码的IP地址
            let ip_with_mask = parts[1];
            let ip_address = ip_with_mask.split('/').next().unwrap_or(ip_with_mask);
            return Ok(ip_address.to_string());
        }
    }

    Err("Interface address not found".to_string())
}

/// 检测域名是否可ping通，返回是否可通
pub fn ping_domain(domain: &str) -> bool {
    // 执行ping命令，发送1个包，超时1秒
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "1", domain])
        .output();
    
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false
    }
}

/// 获取默认路由出口的IP地址
pub fn get_default_route_ip() -> Result<String, String> {
    // 执行route命令获取默认路由
    let output = match Command::new("route")
        .args(["-n", "get", "default"])
        .output() {
            Ok(output) => output,
            Err(e) => return Err(format!("Failed to execute route: {}", e))
        };
    
    // 将输出转换为字符串
    let output_str = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to parse route output: {}", e))
    };
    
    // 遍历输出的每一行，查找接口名称
    let mut interface_name = "";
    for line in output_str.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "interface:" {
            interface_name = parts[1];
            break;
        }
    }
    
    if interface_name.is_empty() {
        return Err("Default route interface not found".to_string());
    }
    
    // 获取该接口的IP地址
    get_interface_address(interface_name)
}

/// 检测是否在内网环境，返回是否在内网
/// 简化版本：只需ping通域名即可认为在内网环境
pub fn is_in_intranet(intranet_domain: &Option<String>) -> bool {
    if let Some(domain) = intranet_domain {
        if ping_domain(domain) {
            log::info!("域名 {} 可ping通，检测到内网环境", domain);
            return true;
        } else {
            log::info!("域名 {} 不可ping通，非内网环境或网络不可达", domain);
            return false;
        }
    } else {
        false
    }
}

/// 检查用户权限
pub fn check_privilege() -> Result<(), ()> {
    #[cfg(unix)]
    match sudo::escalate_if_needed() {
        Ok(_) => Ok(()),
        Err(_) => {
            log::error!("please run as root");
            Err(())
        }
    }

    #[cfg(windows)]
    if !is_elevated::is_elevated() {
        log::error!("please run as administrator");
        Err(())
    } else {
        Ok(())
    }
}

/// 打印版本信息
pub fn print_version() {
    let pkg_name = env!("CARGO_PKG_NAME");
    let pkg_version = env!("CARGO_PKG_VERSION");
    log::info!("running {}@{}", pkg_name, pkg_version);
}

/// 解析域名的DNS，返回是否能正常解析
pub fn resolve_dns(domain: &str) -> bool {
    // 使用dig命令解析域名
    let output = Command::new("dig")
        .args(["+short", domain])
        .output();
    
    match output {
        Ok(output) => {
            // 检查输出是否为空
            let output_str = String::from_utf8_lossy(&output.stdout);
            !output_str.is_empty() && output.status.success()
        },
        Err(_) => false
    }
}
