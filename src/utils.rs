use std::error::Error;
use std::io::{self, BufRead};
use std::process::Command;

use base32::Alphabet;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64;
use rand::rngs::OsRng;
use reqwest;
use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn read_line() -> String {
    io::stdin().lock().lines().next().unwrap().unwrap()
}

pub fn b32_decode(s: &str) -> Vec<u8> {
    base32::decode(Alphabet::RFC4648 { padding: true }, s).unwrap()
}

pub fn gen_wg_keypair() -> (String, String) {
    let csprng = OsRng {};
    let sk = StaticSecret::random_from_rng(csprng);
    let pk = PublicKey::from(&sk);
    (base64.encode(pk.to_bytes()), base64.encode(sk.to_bytes()))
}

pub fn gen_public_key_from_private(private_key: &String) -> Result<String, Box<dyn Error>> {
    match base64.decode(private_key) {
        Ok(key) => {
            let key: [u8; 32] = key.try_into().unwrap();
            let sk = StaticSecret::from(key);
            let public_key = PublicKey::from(&sk);
            Ok(base64.encode(public_key.to_bytes()))
        }
        Err(e) => Err(format!("failed to base64 decode {}: {}", private_key, e).into()),
    }
}

pub fn b64_decode_to_hex(s: &str) -> String {
    let data = base64.decode(s).unwrap();
    let mut hex = String::new();
    for c in data {
        hex.push_str(format!("{c:02x}").as_str());
    }
    hex
}

/// 发送消息到飞书机器人
pub async fn send_feishu_message(robot_url: &str, message: &str) -> Result<(), Box<dyn Error>> {
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
        .await?;
    
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
