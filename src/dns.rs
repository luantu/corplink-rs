use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};

pub struct DNSManager {
    service_dns: HashMap<String, String>,
    service_dns_search: HashMap<String, String>,
}

/// 全局单例：保存程序启动时抓取的原始系统 DNS。
/// 整个程序生命周期内只 init 一次，所有 restore 都用它，
/// 避免在 VPN DNS 已被写入后再 collect 导致"原始值"被污染。
static ORIGIN_DNS_MANAGER: OnceLock<Mutex<DNSManager>> = OnceLock::new();

impl DNSManager {
    pub fn new() -> DNSManager {
        DNSManager {
            service_dns: HashMap::new(),
            service_dns_search: HashMap::new(),
        }
    }

    fn collect_new_service_dns(&mut self) -> Result<()> {
        let output = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()
            .context("failed to list network services")?;

        let services = String::from_utf8_lossy(&output.stdout);
        let lines = services.lines();
        // Skip the first line's legend
        for service in lines.skip(1) {
            // Remove leading '*' and trim whitespace
            let service = service.trim_start_matches('*').trim();
            if service.is_empty() {
                continue;
            }

            // get DNS servers
            let dns_output = Command::new("networksetup")
                .arg("-getdnsservers")
                .arg(service)
                .output()
                .with_context(|| format!("failed to get dns servers for {service}"))?;
            let dns_response = String::from_utf8_lossy(&dns_output.stdout)
                .trim()
                .to_string();
            // if dns config for this service is not empty, output should be ip addresses seperated in lines without space
            // otherwise, output should be "There aren't any DNS Servers set on xxx", use "Empty" instead, which can be recognized in 'networksetup -setdnsservers'
            let dns_response = if dns_response.contains(" ") {
                "Empty".to_string()
            } else {
                dns_response
            };

            self.service_dns
                .insert(service.to_string(), dns_response.clone());

            // get search domain
            let search_output = Command::new("networksetup")
                .arg("-getsearchdomains")
                .arg(service)
                .output()
                .with_context(|| format!("failed to get search domains for {service}"))?;
            let search_response = String::from_utf8_lossy(&search_output.stdout)
                .trim()
                .to_string();
            let search_response = if search_response.contains(" ") {
                "Empty".to_string()
            } else {
                search_response
            };

            self.service_dns_search
                .insert(service.to_string(), search_response.clone());

            log::debug!(
                "DNS collected for {}, dns servers: {}, search domain: {}",
                service,
                dns_response,
                search_response
            )
        }
        Ok(())
    }

    /// 仅写入 DNS，不抓取当前系统 DNS。
    /// 与 `set_dns` 的区别：不会污染已保存的"原始 DNS"。
    pub fn apply_dns(&self, dns_servers: Vec<&str>, dns_search: Vec<&str>) -> Result<()> {
        if dns_servers.is_empty() {
            return Ok(());
        }
        for service in self.service_dns.keys() {
            Command::new("networksetup")
                .arg("-setdnsservers")
                .arg(service)
                .args(&dns_servers)
                .status()
                .with_context(|| format!("failed to set dns servers for {service}"))?;

            if !dns_search.is_empty() {
                Command::new("networksetup")
                    .arg("-setsearchdomains")
                    .arg(service)
                    .args(&dns_search)
                    .status()
                    .with_context(|| format!("failed to set search domains for {service}"))?;
            }
            log::debug!("DNS set for {} with {}", service, dns_servers.join(","));
        }

        Ok(())
    }

    pub fn restore_dns(&self) -> Result<()> {
        for (service, dns) in &self.service_dns {
            Command::new("networksetup")
                .arg("-setdnsservers")
                .arg(service)
                .args(dns.lines())
                .status()
                .with_context(|| format!("failed to reset dns servers for {service}"))?;

            log::debug!("DNS server reset for {} with {}", service, dns);
        }
        for (service, search_domain) in &self.service_dns_search {
            Command::new("networksetup")
                .arg("-setsearchdomains")
                .arg(service)
                .args(search_domain.lines())
                .status()
                .with_context(|| format!("failed to reset search domains for {service}"))?;
            log::debug!(
                "DNS search domain reset for {} with {}",
                service,
                search_domain
            )
        }
        log::debug!("DNS reset");
        Ok(())
    }

    /// 在程序启动时（VPN 修改 DNS 之前）调用一次，抓取原始系统 DNS。
    /// 后续所有 restore 都以此为基准，确保能恢复到真正的"系统默认"。
    ///
    /// - 若 `origin_dns` 提供（用户在配置文件里预设的"原系统默认 DNS"），
    ///   则对每个网络服务统一保存该值作为"原始 DNS"。
    /// - 否则动态从系统抓取当前每个网络服务的 DNS 配置。
    pub fn init_origin_dns(origin_dns: Option<&[String]>) -> Result<()> {
        let mut manager = DNSManager::new();
        match origin_dns {
            Some(dns_list) if !dns_list.is_empty() => {
                let dns_value = dns_list.join("\n");
                // 先列出所有网络服务，对每个服务统一保存同一组 origin_dns
                let output = Command::new("networksetup")
                    .arg("-listallnetworkservices")
                    .output()
                    .context("failed to list network services")?;
                let services = String::from_utf8_lossy(&output.stdout);
                for service in services.lines().skip(1) {
                    let service = service.trim_start_matches('*').trim();
                    if service.is_empty() {
                        continue;
                    }
                    manager.service_dns.insert(service.to_string(), dns_value.clone());
                    // search domain 不在 origin_dns 配置范围内，置为 Empty 表示清空
                    manager
                        .service_dns_search
                        .insert(service.to_string(), "Empty".to_string());
                    log::debug!(
                        "origin dns (from config) for {}: {}",
                        service,
                        dns_value.replace('\n', ",")
                    );
                }
                log::info!(
                    "origin dns captured from config: {}",
                    dns_value.replace('\n', ",")
                );
            }
            _ => {
                manager.collect_new_service_dns()?;
                log::info!("origin dns captured from system");
            }
        }
        match ORIGIN_DNS_MANAGER.get() {
            Some(mtx) => {
                // 已经初始化过（例如配置重载），覆盖之
                *mtx.lock().unwrap() = manager;
            }
            None => {
                ORIGIN_DNS_MANAGER
                    .set(Mutex::new(manager))
                    .map_err(|_| anyhow::anyhow!("failed to set origin dns manager"))?;
            }
        }
        Ok(())
    }

    /// 通过全局单例应用 VPN DNS（不影响已保存的原始 DNS）。
    pub fn global_apply_dns(dns_servers: Vec<&str>, dns_search: Vec<&str>) -> Result<()> {
        let mtx = ORIGIN_DNS_MANAGER
            .get()
            .ok_or_else(|| anyhow::anyhow!("origin dns manager not initialized"))?;
        let manager = mtx
            .lock()
            .map_err(|e| anyhow::anyhow!("origin dns manager lock poisoned: {}", e))?;
        manager.apply_dns(dns_servers, dns_search)
    }

    /// 通过全局单例恢复到程序启动时的原始 DNS。
    /// 用于 VPN 断开、连接失败重试、panic 等所有需要"还原"的场景。
    /// 即使锁中毒或未初始化也只记日志，不返回错误，便于在 panic hook 中调用。
    pub fn global_restore_dns() {
        let mtx = match ORIGIN_DNS_MANAGER.get() {
            Some(mtx) => mtx,
            None => {
                log::warn!("origin dns manager not initialized, skip global restore");
                return;
            }
        };
        let manager = match mtx.lock() {
            Ok(g) => g,
            Err(e) => {
                // 锁中毒（持锁线程 panic），仍尝试访问内部数据
                log::warn!("origin dns manager lock poisoned, force accessing: {}", e);
                e.into_inner()
            }
        };
        match manager.restore_dns() {
            Ok(_) => log::info!("global restore_dns succeeded"),
            Err(e) => log::error!("global restore_dns failed: {}", e),
        }
    }
}
