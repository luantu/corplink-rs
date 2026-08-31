use chrono::Utc;
use std::collections::HashMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{self, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{fs, io};
use tokio::time::sleep;

use cookie::Cookie as RawCookie;
use cookie_store::{Cookie, CookieStore};
use reqwest::header;
use reqwest::{ClientBuilder, Response, Url};
use reqwest_cookie_store::CookieStoreMutex;
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::api::{ApiName, ApiUrl, URL_GET_COMPANY};
use crate::config::{
    Config, WgConf, PLATFORM_CORPLINK, PLATFORM_LARK, PLATFORM_LDAP, PLATFORM_OIDC,
    STRATEGY_DEFAULT, STRATEGY_LATENCY,
};
use crate::login_observer::LoginObserver;
#[cfg(feature = "full-client")]
use crate::login_observer::TerminalLoginObserver;
use crate::resp::*;
use crate::state::State;
use crate::totp::{totp_offset, TIME_STEP};
use crate::utils;

const COOKIE_FILE_SUFFIX: &str = "cookies.json";
const USER_AGENT: &str = "CorpLink/201000 (GooglePixel; Android 16; en)";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshOutcome {
    Updated,
    Verified,
    AuthRequired,
}

#[derive(Debug)]
pub enum Error {
    ReqwestError(reqwest::Error),
    Error(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ReqwestError(err) => err.fmt(f),
            Error::Error(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ReqwestError(err) => Some(err),
            Error::Error(_) => None,
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Error(err.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::ReqwestError(err)
    }
}

#[derive(Clone)]
pub struct Client {
    pub conf: Config,
    cookie: Arc<CookieStoreMutex>,
    c: reqwest::Client,
    api_url: ApiUrl,
    date_offset_sec: i32,
    cookie_file: PathBuf,
    cookie_written: bool,
    cookie_changed: bool,
    defer_cookie_persistence: bool,
    has_live_cookie: bool,
    server_auth_rejected: bool,
}

unsafe impl Send for Client {}

unsafe impl Sync for Client {}

pub async fn get_company_url(code: &str) -> Result<RespCompany, Error> {
    let c = ClientBuilder::new()
        // allow invalid certs because this cert is signed by corplink
        .danger_accept_invalid_certs(true)
        .build();
    if let Err(err) = c {
        return Err(Error::ReqwestError(err));
    }
    let c = c.unwrap();
    let mut m = Map::new();
    m.insert("code".to_string(), json!(code));
    let body = serde_json::to_string(&m).unwrap();

    let resp = c.post(URL_GET_COMPANY).body(body).send().await;
    if let Err(err) = resp {
        return Err(Error::ReqwestError(err));
    }
    let resp = resp.unwrap().json::<Resp<RespCompany>>().await;
    if let Err(err) = resp {
        return Err(Error::ReqwestError(err));
    }
    let resp = resp.unwrap();
    match resp.code {
        0 => Ok(resp.data.unwrap()),
        _ => {
            let msg = resp.message.unwrap();
            Err(Error::Error(msg))
        }
    }
}

impl Client {
    pub fn new(conf: Config) -> Result<Client, Error> {
        let cookie_file = Self::derived_cookie_file(&conf)?;
        Self::new_with_cookie_file(conf, cookie_file)
    }

    pub fn new_with_cookie_file(conf: Config, cookie_file: PathBuf) -> Result<Client, Error> {
        let mut cookie_store = Self::load_cookie_store(&cookie_file)?;
        let has_live_cookie = cookie_store.iter_any().any(|cookie| !cookie.is_expired());
        let has_expired = cookie_store.iter_any().any(|cookie| cookie.is_expired());
        if has_expired {
            log::info!("some cookies are expired");
        }

        let server = conf
            .server
            .as_deref()
            .ok_or_else(|| Error::Error("server configuration is missing".to_string()))?;
        let server_url = Url::from_str(server)
            .map_err(|_| Error::Error("server configuration is invalid".to_string()))?;
        if server_url.domain().is_none() {
            return Err(Error::Error("server configuration is invalid".to_string()));
        }

        let mut headers = header::HeaderMap::new();

        if let Some(device_id) = &conf.device_id {
            let _ = cookie_store.insert_raw(&RawCookie::new("device_id", device_id), &server_url);
        }
        if let Some(device_name) = &conf.device_name {
            let _ =
                cookie_store.insert_raw(&RawCookie::new("device_name", device_name), &server_url);
        }

        if let Some(csrf_token) = cookie_store.get(
            server_url
                .domain()
                .ok_or_else(|| Error::Error("server configuration is invalid".to_string()))?,
            "/",
            "csrf-token",
        ) {
            let csrf_token = header::HeaderValue::from_str(csrf_token.value())
                .map_err(|_| Error::Error("cookie store contains an invalid header".to_string()))?;
            headers.insert("csrf-token", csrf_token);
        }

        let cookie_store = Arc::new(CookieStoreMutex::new(cookie_store));

        let c = ClientBuilder::new()
            // allow invalid certs because this cert is signed by corplink
            .danger_accept_invalid_certs(true)
            .user_agent(USER_AGENT)
            .cookie_provider(Arc::clone(&cookie_store))
            .default_headers(headers)
            .timeout(Duration::from_millis(10000))
            .build()
            .map_err(Error::ReqwestError)?;
        let conf_bak = conf.clone();
        Ok(Client {
            conf,
            cookie: Arc::clone(&cookie_store),
            c,
            api_url: ApiUrl::new(&conf_bak),
            date_offset_sec: 0,
            cookie_file,
            cookie_written: false,
            cookie_changed: false,
            defer_cookie_persistence: false,
            has_live_cookie,
            server_auth_rejected: false,
        })
    }

    fn derived_cookie_file(conf: &Config) -> Result<PathBuf, Error> {
        let f = conf
            .conf_file
            .as_deref()
            .ok_or_else(|| Error::Error("configuration file path is missing".to_string()))?;
        let dir = match path::Path::new(&f).parent() {
            Some(dir) => dir,
            None => path::Path::new("."),
        };
        let interface_name = conf
            .interface_name
            .as_deref()
            .ok_or_else(|| Error::Error("interface name is missing".to_string()))?;
        Ok(dir.join(format!("{interface_name}_{COOKIE_FILE_SUFFIX}")))
    }

    fn load_cookie_store(cookie_file: &PathBuf) -> Result<CookieStore, Error> {
        log::info!("cookie file is: {}", cookie_file.display());
        match fs::File::open(cookie_file) {
            Ok(file) => match serde_json::from_reader(io::BufReader::new(file)) {
                Ok(store) => Ok(store),
                Err(_) => {
                    let file = fs::File::open(cookie_file)
                        .map_err(|_| Error::Error("cookie store could not be read".to_string()))?;
                    CookieStore::load_json_all(io::BufReader::new(file))
                        .map_err(|_| Error::Error("cookie store is invalid".to_string()))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CookieStore::default()),
            Err(_) => Err(Error::Error("cookie store could not be read".to_string())),
        }
    }

    async fn change_state(&mut self, state: State) -> Result<(), Error> {
        self.conf.state = Some(state);
        self.conf.save().await.map_err(Error::from)
    }

    fn save_cookie(&mut self) -> Result<bool, Error> {
        if !self.cookie_changed {
            return Ok(false);
        }

        let mut buffer = Vec::new();
        let c = self
            .cookie
            .lock()
            .map_err(|_| Error::Error("cookie store lock failed".to_string()))?;
        serde_json::to_writer(&mut buffer, &*c)
            .map_err(|_| Error::Error("cookie store serialization failed".to_string()))?;

        let parent = self
            .cookie_file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| Error::Error("cookie store parent directory is missing".to_string()))?;
        let name = self
            .cookie_file
            .file_name()
            .ok_or_else(|| Error::Error("cookie store file name is missing".to_string()))?;

        let mut random = [0_u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
        let random_suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temp_file = parent.join(format!(".{}.{}.tmp", name.to_string_lossy(), random_suffix));

        let write_result = (|| -> Result<(), Error> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_file).map_err(|_| {
                Error::Error("cookie store temporary file could not be created".to_string())
            })?;
            #[cfg(not(unix))]
            {
                let mut permissions = file
                    .metadata()
                    .map_err(|_| {
                        Error::Error("cookie store permissions could not be read".to_string())
                    })?
                    .permissions();
                permissions.set_readonly(false);
                file.set_permissions(permissions).map_err(|_| {
                    Error::Error("cookie store permissions could not be set".to_string())
                })?;
            }
            file.write_all(&buffer)
                .map_err(|_| Error::Error("cookie store write failed".to_string()))?;
            file.sync_all()
                .map_err(|_| Error::Error("cookie store sync failed".to_string()))?;
            drop(file);

            let validation_file = fs::File::open(&temp_file)
                .map_err(|_| Error::Error("cookie store validation read failed".to_string()))?;
            let _: CookieStore = serde_json::from_reader(io::BufReader::new(validation_file))
                .map_err(|_| Error::Error("cookie store validation failed".to_string()))?;

            fs::rename(&temp_file, &self.cookie_file)
                .map_err(|_| Error::Error("cookie store replace failed".to_string()))?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temp_file);
        }
        write_result?;
        self.cookie_changed = false;
        self.cookie_written = true;
        Ok(true)
    }

    async fn request<T: DeserializeOwned + fmt::Debug>(
        &mut self,
        api: ApiName,
        body: Option<Map<String, Value>>,
    ) -> Result<Resp<T>, Error> {
        let url = self.api_url.get_api_url(&api);

        let rb = match body {
            Some(body) => {
                let body = serde_json::to_string(&body).unwrap();
                self.c
                    .post(url)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(body)
            }
            None => self.c.get(url),
        };

        let resp = match rb.send().await {
            Ok(r) => r,
            Err(err) => return Err(Error::ReqwestError(err)),
        };
        // TODO: handle special cases
        if !resp.status().is_success() {
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                self.server_auth_rejected = true;
            }
            let msg = format!("logout because of bad resp code: {status}");
            return Err(self.handle_logout_err(msg).await);
        }

        self.parse_time_offset_from_date_header(&resp);

        let has_set_cookie = resp.headers().contains_key(header::SET_COOKIE);

        // 添加详细日志，输出原始响应内容，帮助定位JSON解析错误
        let raw_body = resp.text().await;
        match raw_body {
            Ok(body) => {
                log::debug!("api {:#?} raw resp: {}", api, body);
                let resp: Resp<T> = match serde_json::from_str(&body) {
                    Ok(r) => r,
                    Err(err) => {
                        log::error!("failed to parse response: {}", err);
                        log::error!("response body: {}", body);
                        return Err(Error::Error(format!("failed to parse response: {}", err)));
                    }
                };
                if resp.code == 101 {
                    self.server_auth_rejected = true;
                }
                if has_set_cookie {
                    self.cookie_changed = true;
                    if !self.defer_cookie_persistence {
                        self.save_cookie()?;
                    }
                }
                log::debug!("api {:#?} parsed resp: {:#?}", api, resp);
                Ok(resp)
            }
            Err(err) => {
                log::error!("failed to read response body: {}", err);
                return Err(Error::ReqwestError(err));
            }
        }
    }

    fn parse_time_offset_from_date_header(&mut self, resp: &Response) {
        let headers = resp.headers();
        if headers.contains_key("date") {
            let date = &headers["date"];
            match httpdate::parse_http_date(date.to_str().unwrap()) {
                Ok(date) => {
                    let now = SystemTime::now();
                    self.date_offset_sec = if now < date {
                        let date_offset = date.duration_since(now).unwrap();
                        date_offset.as_secs().try_into().unwrap()
                    } else {
                        let date_offset = now.duration_since(date).unwrap();
                        let offset: i32 = date_offset.as_secs().try_into().unwrap();
                        -offset
                    };
                }
                Err(e) => {
                    log::warn!("failed to parse date in header, ignore it: {}", e);
                }
            }
        }
    }

    pub fn need_login(&self) -> bool {
        return self.conf.state.is_none() || self.conf.state.as_ref().unwrap() == &State::Init;
    }

    async fn check_tps_token(&mut self, token: &String) -> Result<String, Error> {
        // tps confirmed, try to login with token
        let mut m = Map::new();
        m.insert("token".to_string(), json!(token));

        let resp = self
            .request::<RespLogin>(ApiName::TpsTokenCheck, Some(m))
            .await?;
        match resp.code {
            0 => resp.data.map(|data| data.url).ok_or_else(|| {
                Error::Error("third party token response is incomplete".to_string())
            }),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "third party token check failed".to_string());
                Err(Error::Error(msg))
            }
        }
    }

    async fn get_otp_uri_from_tps<O: LoginObserver>(
        &mut self,
        method: &str,
        url: &String,
        token: &String,
        observer: &mut O,
    ) -> Result<String, Error> {
        observer
            .login_url(url, Utc::now() + chrono::Duration::minutes(5))
            .map_err(Error::from)?;
        match method {
            PLATFORM_LARK | PLATFORM_OIDC => {
                // 轮询 check_tps_token 检测扫码是否完成：
                // 用户扫码后，服务端 token 校验成功，自动继续。
                // 无需人工输入 y/回车。
                observer.waiting().map_err(Error::from)?;

                let start = std::time::Instant::now();
                let timeout = Duration::from_secs(300); // 最长等待 5 分钟
                let mut last_err = String::new();
                loop {
                    match self.check_tps_token(token).await {
                        Ok(url) => {
                            return Ok(url);
                        }
                        Err(e) => {
                            last_err = e.to_string();
                            // 未扫码/未确认，继续轮询
                            if start.elapsed() > timeout {
                                log::warn!("扫码登录超时（5分钟）");
                                return Err(Error::Error(format!("扫码登录超时: {}", last_err)));
                            }
                            log::debug!("等待扫码完成: {}", last_err);
                            sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
            }
            _ => Err(Error::Error("unsupported third party platform".to_string())),
        }
    }

    async fn corplink_login(&mut self) -> Result<String, Error> {
        let resp = self.get_corplink_login_method().await?;
        for method in resp.auth {
            match method.as_str() {
                "password" => {
                    if let Some(password) = &self.conf.password {
                        if !password.is_empty() {
                            log::info!("try to login with password");
                            return self.login_with_password(PLATFORM_CORPLINK).await;
                        }
                    }
                    log::info!("no password provided, trying other methods");
                    continue;
                }
                "email" => {
                    log::info!("try to login with code from email");
                    return self.login_with_email().await;
                }
                _ => {
                    log::info!("unsupported method {method}, trying other methods");
                }
            }
        }
        Err(Error::Error(
            "no supported corplink login method".to_string(),
        ))
    }

    async fn ldap_login(&mut self) -> Result<String, Error> {
        // I don't know why but we must get login method before login
        let resp = self.get_corplink_login_method().await?;
        for method in resp.auth {
            if method != "password" {
                continue;
            }
            if let Some(password) = &self.conf.password {
                return if !password.is_empty() {
                    self.login_with_password(PLATFORM_LDAP).await
                } else {
                    Err(Error::Error("no password provided".to_string()))
                };
            }
        }
        Err(Error::Error("no supported ldap login method".to_string()))
    }

    fn is_platform_or_default(&self, platform: &str) -> bool {
        if let Some(p) = &self.conf.platform {
            return p.is_empty() || platform == p;
        }
        true
    }

    async fn request_otp_code(&mut self) -> Result<String, Error> {
        let m = Map::new();
        let resp = self.request::<RespOtp>(ApiName::Otp, Some(m)).await?;
        match resp.code {
            0 => resp
                .data
                .map(|data| data.url)
                .ok_or_else(|| Error::Error("otp response is incomplete".to_string())),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "otp request failed".to_string());
                Err(Error::Error(msg))
            }
        }
    }

    async fn get_otp_uri_by_otp<O: LoginObserver>(
        &mut self,
        tps_login: &HashMap<String, RespTpsLoginMethod>,
        method: &String,
        observer: &mut O,
    ) -> Result<String, Error> {
        return match self.get_otp_uri(tps_login, method, observer).await {
            Ok(url) => {
                if url == "" {
                    // A Feilian password login must return its authenticated
                    // completion URL. Falling back to /api/v2/p/otp here
                    // only creates a TOTP seed without establishing a
                    // session, which later appears as a misleading
                    // "Cookies are missing" response from /vpn/conn.
                    if method == PLATFORM_CORPLINK {
                        return Err(Error::Error(
                            "feilian password login returned no completion URL".to_string(),
                        ));
                    }
                    self.request_otp_code().await
                } else {
                    Ok(url)
                }
            }
            Err(e) => Err(e),
        };
    }
    async fn get_otp_uri<O: LoginObserver>(
        &mut self,
        tps_login: &HashMap<String, RespTpsLoginMethod>,
        method: &String,
        observer: &mut O,
    ) -> Result<String, Error> {
        if tps_login.contains_key(method) && self.is_platform_or_default(method) {
            log::info!("try to login with third party platform {method}");
            let resp = tps_login.get(method).unwrap();
            return self
                .get_otp_uri_from_tps(method, &resp.login_url, &resp.token, observer)
                .await;
        }
        match method.as_str() {
            PLATFORM_CORPLINK => {
                if self.is_platform_or_default(PLATFORM_CORPLINK) {
                    log::info!("try to login with platform {PLATFORM_CORPLINK}");
                    return self.corplink_login().await;
                }
            }
            PLATFORM_LDAP => {
                if self.is_platform_or_default(PLATFORM_LDAP) {
                    log::info!("try to login with platform {PLATFORM_LDAP}");
                    return self.ldap_login().await;
                }
            }
            _ => {}
        }
        Ok(String::new())
    }

    // choose right login method and login
    #[cfg(feature = "full-client")]
    pub async fn login(&mut self) -> Result<(), Error> {
        let mut observer = TerminalLoginObserver;
        self.login_with_observer(&mut observer).await
    }

    pub async fn login_with_observer<O: LoginObserver>(
        &mut self,
        observer: &mut O,
    ) -> Result<(), Error> {
        let resp = self.get_login_method().await?;
        let tps_login_resp = self.get_tps_login_method().await?;
        let mut tps_login = HashMap::new();
        for resp in tps_login_resp {
            tps_login.insert(resp.alias.clone(), resp);
        }
        let mut last_error: Option<Error> = None;
        for method in resp.login_orders {
            // A configured platform is a hard selector.  In particular, a
            // Feilian password profile must skip an earlier lark/LDAP entry;
            // treating that filtered entry as an empty URI would incorrectly
            // fall through to /api/v2/p/otp and report a fake login success.
            if let Some(platform) = &self.conf.platform {
                if !platform.is_empty() && platform != &method {
                    continue;
                }
            }
            let otp_uri = self.get_otp_uri_by_otp(&tps_login, &method, observer).await;
            let otp_uri = match otp_uri {
                Ok(uri) => uri,
                Err(e) => {
                    log::warn!("failed to login with method {method}: {e}");
                    last_error = Some(e);
                    continue;
                }
            };
            if otp_uri.is_empty() {
                log::warn!("failed to login with method {method}");
                continue;
            }
            self.change_state(State::Login).await?;

            let url = Url::parse(&otp_uri)
                .map_err(|_| Error::Error("login completion URL is invalid".to_string()))?;
            for (k, v) in url.query_pairs() {
                if k == "secret" {
                    log::info!("got 2fa token: {}", &v);
                    self.conf.code = Some(v.to_string());
                    break;
                }
            }

            if let Some(code) = &self.conf.code {
                if !code.is_empty() {
                    self.conf.save().await.map_err(Error::from)?;
                    let cookie_written = self.save_cookie()?;
                    observer
                        .succeeded(cookie_written, true)
                        .map_err(Error::from)?;
                    return Ok(());
                }
            }
            return Err(Error::Error(format!(
                "login with method {method} returned no otp secret"
            )));
        }
        if let Some(error) = last_error {
            return Err(Error::Error(format!("login failed: {error}")));
        }
        Err(Error::Error(
            "no available login method for configured platform".to_string(),
        ))
    }

    async fn get_login_method(&mut self) -> Result<RespLoginMethod, Error> {
        let resp = self
            .request::<RespLoginMethod>(ApiName::LoginMethod, None)
            .await?;
        resp.data
            .ok_or_else(|| Error::Error("login settings response is incomplete".to_string()))
    }

    // get 3rd party login methods and links, only lark(feishu) is tested
    async fn get_tps_login_method(&mut self) -> Result<Vec<RespTpsLoginMethod>, Error> {
        let resp = self
            .request::<Vec<RespTpsLoginMethod>>(ApiName::TpsLoginMethod, None)
            .await?;
        Ok(resp.data.unwrap_or_default())
    }

    // get corplink login method, knowing result can be password or email
    async fn get_corplink_login_method(&mut self) -> Result<RespCorplinkLoginMethod, Error> {
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespCorplinkLoginMethod>(ApiName::CorplinkLoginMethod, Some(m))
            .await?;
        Ok(resp.data.unwrap())
    }

    async fn login_with_password(&mut self, platform: &str) -> Result<String, Error> {
        let mut password = self.conf.password.as_ref().unwrap().clone();
        let mut m = Map::new();
        match platform {
            PLATFORM_LDAP => {
                m.insert("platform".to_string(), json!(PLATFORM_LDAP));
            }
            PLATFORM_CORPLINK => {
                if password.len() != 64 {
                    let mut sha = sha2::Sha256::new();
                    sha.update(password.as_bytes());
                    password = format!("{:x}", sha.finalize());
                } // else: password already convert to sha256sum
            }
            _ => {
                panic!("invalid platform {platform}")
            }
        }
        m.insert("password".to_string(), json!(password));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespLogin>(ApiName::LoginPassword, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp.data.unwrap().url),
            _ => {
                let msg = resp.message.unwrap();
                Err(Error::Error(msg))
            }
        }
    }

    async fn request_email_code(&mut self) -> Result<(), Error> {
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("code_type".to_string(), json!("email"));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        self.request::<Map<String, Value>>(ApiName::RequestEmailCode, Some(m))
            .await?;
        Ok(())
    }

    async fn login_with_email(&mut self) -> Result<String, Error> {
        // tell server to send code to email
        log::info!("try to request code for email");
        self.request_email_code().await?;

        log::info!("input your code from email:");
        let input = utils::read_line().await?;
        let code = input.trim();
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("code_type".to_string(), json!("email"));
        m.insert("code".to_string(), json!(code));

        let resp = self
            .request::<RespLogin>(ApiName::LoginEmail, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp.data.unwrap().url),
            _ => Err(Error::Error(format!(
                "failed to login with email code {}: {}",
                code,
                resp.message.unwrap()
            ))),
        }
    }

    async fn handle_logout_err(&mut self, msg: String) -> Error {
        let _ = self.change_state(State::Init).await;
        Error::Error(format!("operation failed because of logout: {}", msg))
    }

    async fn list_vpn(&mut self) -> Result<Vec<RespVpnInfo>, Error> {
        let resp = self
            .request::<Vec<RespVpnInfo>>(ApiName::ListVPN, None)
            .await?;
        match resp.code {
            0 => Ok(resp.data.unwrap()),
            101 => Err(self.handle_logout_err(resp.message.unwrap()).await),
            _ => Err(Error::Error(format!(
                "failed to list vpn with error {}: {}",
                resp.code,
                resp.message.unwrap()
            ))),
        }
    }

    // 测试单个IP的延迟，返回延迟值（毫秒），-1表示测试失败
    async fn ping_single_ip(&mut self, ip: String, api_port: u16) -> i64 {
        // 设置重试次数为3次
        const MAX_RETRIES: i32 = 3;
        let mut retries = 0;

        // 配置cookie
        {
            let mut cookie = self.cookie.lock().unwrap();
            let server_url = self.conf.server.clone().unwrap();

            let mut url = Url::from_str(&server_url).unwrap();
            let mut cookies: Vec<Cookie> = Vec::new();
            for c in cookie.iter_any() {
                if c.domain.matches(&url.clone()) {
                    cookies.push(c.clone());
                }
            }
            url.set_host(Some(ip.as_str())).unwrap();
            url.set_port(Some(api_port)).unwrap();
            for c in cookies {
                let mut c = cookie::Cookie::new(c.name().to_string(), c.value().to_string());
                c.set_domain(ip.clone());
                let c = Cookie::try_from_raw_cookie(&c, &url.clone()).unwrap();
                cookie.insert(c, &url.clone()).unwrap();
            }
            self.api_url.vpn_param.url = url.to_string().trim_end_matches('/').to_string();
        }
        // 重试循环
        while retries < MAX_RETRIES {
            if retries > 0 {
                log::info!(
                    "retrying ping to {}:{}, attempt {}/{}",
                    ip,
                    api_port,
                    retries + 1,
                    MAX_RETRIES
                );
                // 每次重试前等待100ms
                sleep(Duration::from_millis(100)).await;
            }

            let req_start = Utc::now().timestamp_millis();
            let result = self.request::<String>(ApiName::PingVPN, None).await;
            let req_end = Utc::now().timestamp_millis();
            let latency = req_end - req_start;

            match result {
                Ok(resp) => match resp.code {
                    0 => return latency,
                    _ => {
                        log::warn!(
                            "failed to ping vpn with error {}: {}",
                            resp.code,
                            resp.message.unwrap()
                        );
                    }
                },
                Err(err) => {
                    // 特别处理连接超时错误
                    if err.to_string().contains("Operation timed out") {
                        log::warn!(
                            "failed to ping {}:{}: {} (attempt {}/{})
",
                            ip,
                            api_port,
                            err,
                            retries + 1,
                            MAX_RETRIES
                        );
                    } else {
                        log::warn!("failed to ping {}:{}: {}", ip, api_port, err);
                    }
                }
            }

            retries += 1;
        }

        // 所有重试都失败
        -1
    }

    // 测试VPN服务器的所有可用IP（主IP + 备用IP），返回最佳IP和延迟
    async fn ping_vpn_with_backup_ips(&mut self, vpn: &RespVpnInfo) -> (String, i64) {
        let mut best_ip = vpn.ip.clone();
        let mut best_latency = i64::MAX;

        // 收集所有要测试的IP
        let mut ips_to_test = vec![vpn.ip.clone()];

        // 处理备用IP，如果存在的话
        if let Some(backup_ips) = &vpn.backup_ips {
            ips_to_test.extend(backup_ips.clone());
        }

        // 测试每个IP的延迟
        for ip in ips_to_test {
            // 检查IP是否在bypass列表中，如果在就跳过
            if let Some(bypass_list) = &self.conf.vpn_server_ip_bypass {
                if bypass_list.contains(&ip) {
                    log::info!("skip IP {} in bypass list", ip);
                    continue;
                }
            }

            let latency = self.ping_single_ip(ip.clone(), vpn.api_port).await;

            if latency != -1 {
                log::info!("{} - {}: latency {}ms", vpn.name, ip, latency);
                if latency < best_latency {
                    best_latency = latency;
                    best_ip = ip.clone();
                }
            } else {
                log::info!("{} - {}: timeout", vpn.name, ip);
            }
        }

        if best_latency == i64::MAX {
            // 所有IP都测试失败
            (best_ip, -1)
        } else {
            (best_ip, best_latency)
        }
    }

    async fn get_first_vpn_by_latency(
        &mut self,
        vpn_info: Vec<RespVpnInfo>,
    ) -> Option<RespVpnInfo> {
        let mut fast_vpn = None;
        let mut min_latency = i64::MAX;

        for mut vpn in vpn_info {
            let (best_ip, latency) = self.ping_vpn_with_backup_ips(&vpn).await;

            // 如果找到更好的IP，更新VPN的主IP
            if latency != -1 && latency < min_latency {
                vpn.ip = best_ip;
                fast_vpn = Some(vpn);
                min_latency = latency;
            }
        }
        fast_vpn
    }

    async fn get_first_available_vpn(&mut self, vpn_info: Vec<RespVpnInfo>) -> Option<RespVpnInfo> {
        for mut vpn in vpn_info {
            let (best_ip, latency) = self.ping_vpn_with_backup_ips(&vpn).await;
            if latency != -1 {
                // 使用找到的最佳IP
                vpn.ip = best_ip;
                return Some(vpn);
            }
        }
        None
    }

    async fn select_vpn(&mut self) -> Result<RespVpnInfo, Error> {
        let vpn_info = self.list_vpn().await?;

        log::info!("found {} vpn(s)", vpn_info.len());
        for vpn in &vpn_info {
            log::info!(
                "VPN server info: id={}, name={}, ip={}, api_port={}, vpn_port={}, protocol_mode={}, timeout={}",
                vpn.id,
                vpn.name,
                vpn.ip,
                vpn.api_port,
                vpn.vpn_port,
                vpn.protocol_mode,
                vpn.timeout
            );
        }
        let filtered_vpn = vpn_info
            .into_iter()
            .filter(|vpn| {
                if let Some(server_name) = self.conf.vpn_server_name.clone() {
                    if vpn.name != server_name {
                        log::info!("skip {}, expect {}", vpn.name, server_name);
                        return false;
                    }
                }
                true
            })
            .filter(|vpn| {
                let mode = match vpn.protocol_mode {
                    1 => "tcp",
                    2 => "udp",
                    _ => "unknown protocol",
                };
                log::debug!(
                    "VPN server {} protocol mode: {}, value: {}",
                    vpn.name,
                    mode,
                    vpn.protocol_mode
                );
                match mode {
                    "udp" => {
                        log::info!("Server {} supports UDP mode", vpn.name);
                        true
                    }
                    "tcp" => {
                        log::info!("Server {} only supports TCP mode", vpn.name);
                        true
                    }
                    _ => {
                        log::info!(
                            "server name {} is not support {} wg for now",
                            vpn.name,
                            mode
                        );
                        false
                    }
                }
            })
            .collect();

        let vpn = match self.conf.vpn_select_strategy.clone() {
            Some(strategy) => match strategy.as_str() {
                STRATEGY_LATENCY => self.get_first_vpn_by_latency(filtered_vpn).await,
                STRATEGY_DEFAULT => self.get_first_available_vpn(filtered_vpn).await,
                _ => return Err(Error::Error("unsupported strategy".to_string())),
            },
            None => self.get_first_available_vpn(filtered_vpn).await,
        };

        vpn.ok_or_else(|| Error::Error("no vpn available".to_string()))
    }

    fn use_selected_vpn(&mut self, vpn: &RespVpnInfo) {
        // Preserve the original client endpoint construction for the selected node.
        self.api_url.vpn_param.url = format!("https://{}:{}", vpn.ip, vpn.api_port);
    }

    pub async fn refresh_cookie_once(&mut self) -> Result<RefreshOutcome, Error> {
        if !self.has_live_cookie {
            return Ok(RefreshOutcome::AuthRequired);
        }

        self.cookie_written = false;
        self.server_auth_rejected = false;
        self.defer_cookie_persistence = true;

        let result = async {
            let vpn = self.select_vpn().await?;
            self.use_selected_vpn(&vpn);
            let public_key = self
                .conf
                .public_key
                .clone()
                .ok_or_else(|| Error::Error("public key is missing".to_string()))?;

            // This deliberately ends at the original /vpn/conn implementation. The returned
            // tunnel parameters are discarded so refresh never creates a local tunnel.
            let _ = self.fetch_peer_info(&public_key).await?;
            let cookie_updated = self.save_cookie()?;
            Ok(if cookie_updated {
                RefreshOutcome::Updated
            } else {
                RefreshOutcome::Verified
            })
        }
        .await;

        self.defer_cookie_persistence = false;
        match result {
            Err(_error) if self.server_auth_rejected => Ok(RefreshOutcome::AuthRequired),
            other => other,
        }
    }

    // ping vpn and return latency in ms. Will return -1 on error
    // 保留原方法，供其他地方调用，直接调用ping_single_ip方法
    #[allow(dead_code)]
    async fn ping_vpn(&mut self, ip: String, api_port: u16) -> i64 {
        self.ping_single_ip(ip, api_port).await
    }

    async fn fetch_peer_info(&mut self, public_key: &String) -> Result<RespWgInfo, Error> {
        let mut otp = String::new();
        if let Some(code) = &self.conf.code {
            if !code.is_empty() {
                let code = utils::b32_decode(code)?;
                let offset = self.date_offset_sec / TIME_STEP as i32;
                let raw_otp = totp_offset(code.as_slice(), offset);
                otp = format!("{:06}", raw_otp.code);
                log::info!(
                    "2fa code generated: {}, {} seconds left",
                    &otp,
                    raw_otp.secs_left
                );
            }
        }
        if otp.is_empty() {
            log::info!("input your 2fa code:");
            otp = utils::read_line().await?;
        }
        let mut m = Map::new();
        m.insert("public_key".to_string(), json!(public_key));
        m.insert("otp".to_string(), json!(otp));
        let resp = self
            .request::<RespWgInfo>(ApiName::ConnectVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp.data.unwrap()),
            101 => Err(self.handle_logout_err(resp.message.unwrap()).await),
            _ => Err(Error::Error(format!(
                "failed to fetch peer info with error {}: {}",
                resp.code,
                resp.message.unwrap()
            ))),
        }
    }

    pub async fn connect_vpn(&mut self) -> Result<WgConf, Error> {
        // 首先检测是否在内网环境
        if let Some(_intranet_domain) = &self.conf.intranet_domain {
            if utils::is_in_intranet(&self.conf.intranet_domain) {
                log::info!("检测到内网环境，不需要建立VPN连接");

                // 获取默认路由IP
                match utils::get_default_route_ip() {
                    Ok(intranet_ip) => {
                        log::info!("获取到默认路由IP: {}", intranet_ip);

                        // 发送内网IP到飞书
                        // let check_config = crate::config::read_check_config(self.conf.check_config_path.as_deref());
                        // let feishu_message = format!("检测到内网环境，当前出口IP: {}", intranet_ip);
                        // if let Err(e) = utils::send_feishu_message(&check_config.feishu_webhook_url, &feishu_message).await {
                        //     log::warn!("发送飞书消息失败: {}", e);
                        // }

                        // 返回一个空的WgConf，仅设置内网相关字段
                        // 因为在内网环境下不需要实际的VPN配置
                        return Ok(WgConf {
                            address: format!("{}/24", intranet_ip),
                            address6: "".to_string(),
                            peer_address: format!("{}:0", intranet_ip),
                            mtu: 1420,
                            public_key: "".to_string(),
                            private_key: "".to_string(),
                            peer_key: "".to_string(),
                            route: Vec::new(),
                            dns: "8.8.8.8".to_string(),
                            protocol: 0,
                            use_intranet: true,
                            intranet_domain: self.conf.intranet_domain.clone(),
                        });
                    }
                    Err(e) => {
                        log::warn!("获取默认路由IP失败: {}, 继续执行VPN连接逻辑", e);
                    }
                }
            }
        }

        // 非内网环境，执行正常的VPN连接逻辑
        let vpn = self.select_vpn().await?;

        let vpn_addr = format!("{}:{}", vpn.ip, vpn.vpn_port);
        log::info!("try connect to {}, address {}", vpn.name, vpn_addr);

        // 更新API URL参数，确保使用正确的VPN服务器地址
        self.use_selected_vpn(&vpn);

        let key = self.conf.public_key.clone().unwrap();
        log::info!("try to get wg conf from remote");
        let wg_info = self.fetch_peer_info(&key).await?;
        let mtu = wg_info.setting.vpn_mtu;
        let dns = wg_info.setting.vpn_dns;
        let peer_key = wg_info.public_key;
        let public_key = self.conf.public_key.clone().unwrap();
        let private_key = self.conf.private_key.clone().unwrap();
        let address = format!("{}/{}", wg_info.ip, wg_info.ip_mask.parse::<u32>().unwrap());
        let address6 = (!wg_info.ipv6.is_empty())
            .then_some(format!("{}/128", wg_info.ipv6))
            .unwrap_or("".into());
        let route = [
            wg_info.setting.vpn_route_split,
            wg_info.setting.v6_route_split.unwrap_or_default(),
        ]
        .concat();

        // 确定协议模式
        let protocol = if let Some(forced_mode) = self.conf.protocol_mode {
            // 使用配置文件中强制指定的协议模式
            let mode_str = match forced_mode {
                0 => "UDP",
                1 => "TCP",
                _ => "Unknown",
            };
            log::info!(
                "Forcing protocol mode: {} ({}), ignoring server value: {}",
                mode_str,
                forced_mode,
                vpn.protocol_mode
            );
            forced_mode
        } else {
            // 使用服务器返回的协议模式
            match vpn.protocol_mode {
                // tcp
                1 => {
                    log::info!("Using TCP mode for server {}", vpn.name);
                    1
                }
                // udp
                2 => {
                    log::info!("Using UDP mode for server {}", vpn.name);
                    0
                }
                _ => {
                    log::warn!(
                        "Unknown protocol mode {} for server {}, defaulting to UDP",
                        vpn.protocol_mode,
                        vpn.name
                    );
                    0
                }
            }
        };

        // corplink config
        let wg_conf = WgConf {
            address,
            address6,
            peer_address: vpn_addr,
            mtu,
            public_key,
            private_key,
            peer_key,
            route,
            dns,
            protocol,
            use_intranet: false,
            intranet_domain: self.conf.intranet_domain.clone(),
        };

        log::info!(
            "Created WgConf with protocol mode: {} (0=UDP, 1=TCP)",
            protocol
        );
        Ok(wg_conf)
    }

    pub async fn keep_alive_vpn(&mut self, conf: &WgConf, _interval: u64) {
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 5;
        const KEEP_ALIVE_INTERVAL: u64 = 10; // 所有环境下统一使用10秒保活间隔

        loop {
            let keep_alive_success = if conf.use_intranet && conf.intranet_domain.is_some() {
                // 在内网环境，使用ping方式保活
                if let Some(domain) = &conf.intranet_domain {
                    log::debug!("使用ping方式保活，目标域名: {}", domain);
                    utils::ping_domain(domain)
                } else {
                    false
                }
            } else {
                // 在外网环境，使用原来的report_vpn_status方式
                self.report_vpn_status(conf).await.is_ok()
            };

            if keep_alive_success {
                // 成功时重置错误计数器
                consecutive_errors = 0;
                log::debug!("保活成功");
            } else {
                consecutive_errors += 1;
                log::warn!("保活失败 (连续失败次数 {}): 触发重试", consecutive_errors);

                // 如果连续错误超过5次，则返回，触发重连
                if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                    log::error!("连续失败次数超过 {}, 触发重连", MAX_CONSECUTIVE_ERRORS);
                    return;
                }
            }

            // 所有环境下统一使用10秒间隔保活
            tokio::time::sleep(Duration::from_secs(KEEP_ALIVE_INTERVAL)).await;
        }
    }

    pub async fn report_vpn_status(&mut self, conf: &WgConf) -> Result<(), Error> {
        let mut m = Map::new();
        m.insert("ip".to_string(), json!(conf.address));
        m.insert("public_key".to_string(), json!(conf.public_key));
        m.insert("mode".to_string(), json!("Split"));
        m.insert("type".to_string(), json!("100"));

        let resp = self
            .request::<Map<String, Value>>(ApiName::KeepAliveVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => Err(Error::Error(format!(
                "failed to report connection with error {}: {}",
                resp.code,
                resp.message.unwrap()
            ))),
        }
    }

    pub async fn disconnect_vpn(&mut self, wg_conf: &WgConf) -> Result<(), Error> {
        let mut m = Map::new();
        m.insert("ip".to_string(), json!(wg_conf.address));
        m.insert("public_key".to_string(), json!(wg_conf.public_key));
        m.insert("mode".to_string(), json!("Split"));
        m.insert("type".to_string(), json!("101"));
        let resp = self
            .request::<Map<String, Value>>(ApiName::DisconnectVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => Err(Error::Error(format!(
                "failed to fetch peer info with error {}: {}",
                resp.code,
                resp.message.unwrap()
            ))),
        }
    }
}
