use serde_yaml;
use std::error::Error;
use std::fs::{self, canonicalize};
use std::process::Command;
use log::{debug, error, info, warn};

/// 更新Pavadan/config.yaml文件中指定代理的server地址
pub fn update_config_yaml(config_path: &str, new_server: &str, proxy_name: &str, svn_username: &str, svn_password: &str) -> Result<(), Box<dyn Error>> {
    // 打印调试信息：函数调用及参数
    debug!("update_config_yaml called with config_path: '{0}', new_server: '{1}', proxy_name: '{2}'", 
                config_path, new_server, proxy_name);
    
    // 获取绝对路径，确保路径解析正确
    let absolute_path = canonicalize(config_path).map_err(|e| {
        error!("Failed to get absolute path for '{0}': {1}", config_path, e);
        e
    })?;
    let absolute_path_str = absolute_path.to_string_lossy();
    debug!("Absolute path resolved to: '{0}'", absolute_path_str);
    
    // 检查文件是否存在
    let path = &absolute_path;
    debug!("Checking if config file exists at absolute path: '{0}'", absolute_path_str);
    if !path.exists() {
        error!("Config file does not exist at absolute path: '{0}'", absolute_path_str);
        // 检查父目录是否存在
        if let Some(parent_dir) = path.parent() {
            debug!("Parent directory exists: {0}", parent_dir.exists());
            if parent_dir.exists() {
                debug!("Listing parent directory contents:");
                if let Ok(entries) = fs::read_dir(parent_dir) {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            debug!("- {0}", entry.file_name().to_string_lossy());
                        }
                    }
                }
            }
        }
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Config file not found: {0}", absolute_path_str)
        )));
    }
    debug!("Config file exists");
    
    // 检查文件是否可读
    if let Err(e) = fs::read(&path) {
        error!("Failed to read config file '{0}': {1}", absolute_path_str, e);
        // 检查文件权限
        match std::fs::metadata(&path) {
            Ok(metadata) => {
                debug!("File metadata: permissions: {0:?}, size: {1} bytes", 
                            metadata.permissions(), metadata.len());
            },
            Err(meta_err) => {
                error!("Failed to get file metadata: {0}", meta_err);
            }
        }
        return Err(Box::new(e));
    }
    debug!("Config file is readable");
    
    // 执行svn update命令
    if let Some(dir) = absolute_path.parent() {
        debug!("Attempting to run 'svn update' in directory: '{}'", dir.display());
        
        // 检查svn命令是否存在
        let which_output = Command::new("which").arg("svn").output();
        match which_output {
            Ok(which_res) if which_res.status.success() => {
                let svn_path = String::from_utf8_lossy(&which_res.stdout).trim().to_string();
                debug!("Found svn command at: '{}'", svn_path);
            },
            Ok(_) => warn!("svn command not found in PATH"),
            Err(e) => error!("Failed to execute 'which svn': {}", e)
        }
        
        // 创建SVN命令，根据是否提供了用户名和密码添加相应参数
        let mut svn_command = Command::new("svn");
        svn_command.arg("update");
        
        // 如果提供了用户名和密码，则添加认证参数
        if !svn_username.is_empty() && !svn_password.is_empty() {
            debug!("Using SVN authentication with username: {}", svn_username);
            svn_command.arg("--username").arg(svn_username);
            svn_command.arg("--password").arg(svn_password);
        }
        
        match svn_command
            .current_dir(dir)
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully updated SVN working copy");
                } else {
                    let error_message = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to update SVN working copy: {}", error_message);
                }
            },
            Err(e) => {
                error!("Failed to execute 'svn update' command: {}", e);
                // 尝试使用绝对路径执行svn命令
                    let possible_paths = ["/opt/homebrew/bin/svn", "/usr/bin/svn"];
                    for &path in &possible_paths {
                        if let Ok(svn_path) = canonicalize(path) {
                            debug!("Attempting to use svn at absolute path: '{}'", svn_path.display());
                            // 使用绝对路径的SVN命令，添加认证参数
                        let mut svn_command = Command::new(svn_path);
                        svn_command.arg("update");
                        
                        // 如果提供了用户名和密码，则添加认证参数
                        if !svn_username.is_empty() && !svn_password.is_empty() {
                            debug!("Using SVN authentication with username: {}", svn_username);
                            svn_command.arg("--username").arg(svn_username);
                            svn_command.arg("--password").arg(svn_password);
                        }
                        
                        if let Ok(output) = svn_command
                            .current_dir(dir)
                            .output()
                            {
                                if output.status.success() {
                                    info!("Successfully updated SVN working copy using absolute path");
                                    break;
                                } else {
                                    let error_message = String::from_utf8_lossy(&output.stderr);
                                    warn!("Failed to update SVN working copy with absolute path {}: {}", 
                                               path, error_message);
                                }
                            }
                        }
                    }
            }
        }
    } else {
        warn!("Could not determine parent directory for SVN update");
    }

    // 读取YAML文件内容
    debug!("Reading YAML file content from '{}'", config_path);
    let yaml_content = fs::read_to_string(config_path)?;
    debug!("Successfully read {} bytes from config file", yaml_content.len());
    
    // 解析YAML内容
    debug!("Parsing YAML content");
    let mut config: serde_yaml::Value = serde_yaml::from_str(&yaml_content)?;
    debug!("Successfully parsed YAML content");
    
    // 查找proxies数组
    debug!("Looking for 'proxies' array in config");
    if let Some(proxies) = config.get_mut("proxies").and_then(serde_yaml::Value::as_sequence_mut) {
        debug!("Found 'proxies' array with {} elements", proxies.len());
        // 遍历proxies数组，找到指定名称的项
        let mut found = false;
        for proxy in proxies {
            if let Some(proxy_map) = proxy.as_mapping_mut() {
                // 获取name字段
                if let Some(serde_yaml::Value::String(name)) = proxy_map.get(&serde_yaml::Value::String("name".to_string())) {
                    debug!("Checking proxy with name: '{}'", name);
                    if name == proxy_name {
                        // 更新server字段
                        debug!("Found matching proxy '{}', updating server to '{}'", proxy_name, new_server);
                        proxy_map.insert(
                            serde_yaml::Value::String("server".to_string()),
                            serde_yaml::Value::String(new_server.to_string())
                        );
                        info!("Found and updated {} with new server address: {}", proxy_name, new_server);
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            warn!("Proxy with name '{}' not found in config", proxy_name);
        }
    } else {
        warn!("'proxies' array not found in config");
    }
    
    // 将修改后的内容写回文件
    debug!("Serializing updated config back to YAML");
    let updated_yaml = serde_yaml::to_string(&config)?;
    debug!("Successfully serialized updated config ({} bytes)", updated_yaml.len());
    debug!("Writing updated config back to '{}'", config_path);
    fs::write(config_path, updated_yaml)?;
    info!("Successfully wrote updated config to {}", config_path);
    
    // 自动提交SVN变更
    debug!("Attempting to commit changes to SVN");
    let config_dir = match absolute_path.parent() {
        Some(dir) => {
            debug!("Config directory: '{}'", dir.display());
            dir
        },
        None => {
            warn!("Failed to get parent directory of config file");
            return Ok(());
        }
    };
    
    // 执行svn commit命令
    debug!("Running 'svn commit' in directory: '{}'", config_dir.display());
    
    // 创建SVN提交命令，根据是否提供了用户名和密码添加相应参数
    let mut svn_command = Command::new("svn");
    svn_command.arg("commit");
    svn_command.arg("-m");
    svn_command.arg(format!("Update {} server address to {}", proxy_name, new_server));
    
    // 如果提供了用户名和密码，则添加认证参数
    if !svn_username.is_empty() && !svn_password.is_empty() {
        debug!("Using SVN authentication with username: {}", svn_username);
        svn_command.arg("--username").arg(svn_username);
        svn_command.arg("--password").arg(svn_password);
    }
    
    match svn_command
        .current_dir(config_dir)
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                info!("Successfully committed changes to SVN");
            } else {
                let error_message = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to commit changes to SVN: {}", error_message);
            }
        },
        Err(e) => {
            error!("Failed to execute 'svn commit' command: {}", e);
            // 尝试使用绝对路径执行svn命令
                    let possible_paths = ["/opt/homebrew/bin/svn", "/usr/bin/svn"];
                    for &path in &possible_paths {
                        if let Ok(svn_path) = canonicalize(path) {
                            debug!("Attempting to use svn at absolute path: '{}' for commit", svn_path.display());
                            // 使用绝对路径的SVN提交命令，添加认证参数
                                let mut svn_command = Command::new(svn_path);
                                svn_command.arg("commit");
                                svn_command.arg("-m");
                                svn_command.arg(format!("Update {} server address to {}", proxy_name, new_server));
                                
                                // 如果提供了用户名和密码，则添加认证参数
                                if !svn_username.is_empty() && !svn_password.is_empty() {
                                    debug!("Using SVN authentication with username: {}", svn_username);
                                    svn_command.arg("--username").arg(svn_username);
                                    svn_command.arg("--password").arg(svn_password);
                                }
                                
                                if let Ok(output) = svn_command
                                    .current_dir(config_dir)
                                    .output()
                            {
                                if output.status.success() {
                                    info!("Successfully committed changes to SVN using absolute path");
                                    break;
                                } else {
                                    let error_message = String::from_utf8_lossy(&output.stderr);
                                    warn!("Failed to commit changes to SVN with absolute path {}: {}", 
                                               path, error_message);
                                }
                            }
                        }
                    }
        }
    }
    
    debug!("update_config_yaml completed successfully");
    Ok(())
}