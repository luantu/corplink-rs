use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use corplink_rs::client::{Client, RefreshOutcome};
use corplink_rs::config::Config;
use corplink_rs::login_observer::MachineLoginObserver;
use corplink_rs::machine::{
    parse_request, write_event, Action, MachineEvent, RequestError, MAX_MACHINE_REQUEST_BYTES,
    PROTOCOL_VERSION,
};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();

    match (args.next(), args.next(), args.next()) {
        (Some(argument), None, None) if argument == "--protocol-version" => {
            println!("{PROTOCOL_VERSION}");
            ExitCode::SUCCESS
        }
        (Some(argument), None, None) if argument == "--machine" => run_machine().await,
        (Some(argument), Some(config_path), None) if argument == "--refresh-cookie" => {
            run_refresh_config(PathBuf::from(config_path)).await
        }
        _ => {
            eprintln!("usage: corplink-rs-login --machine | --refresh-cookie config.json | --protocol-version");
            ExitCode::from(2)
        }
    }
}

async fn run_machine() -> ExitCode {
    log::set_max_level(log::LevelFilter::Off);
    let request = match read_machine_request() {
        Ok(request) => request,
        Err(error) => return machine_request_error(error),
    };

    match request.action {
        Action::Login => run_login(request).await,
        Action::RefreshCookie => run_refresh_request(request).await,
    }
}

fn read_machine_request() -> Result<corplink_rs::machine::MachineRequest, RequestError> {
    let mut input = Vec::with_capacity(4096);
    let mut stdin = io::stdin()
        .lock()
        .take((MAX_MACHINE_REQUEST_BYTES + 1) as u64);
    stdin
        .read_to_end(&mut input)
        .map_err(|_| RequestError::Invalid)?;
    parse_request(&input)
}

async fn run_login(request: corplink_rs::machine::MachineRequest) -> ExitCode {
    let machine_config = match request.into_client_config() {
        Ok(config) => config,
        Err(_) => {
            write_machine_error("INVALID_REQUEST", "Machine request is invalid.");
            eprintln!("machine request is invalid");
            return ExitCode::from(1);
        }
    };
    let mut client =
        match Client::new_with_cookie_file(machine_config.config, machine_config.cookie_file) {
            Ok(client) => client,
            Err(_) => {
                write_machine_error("LOGIN_FAILED", "Login could not be started.");
                eprintln!("machine login could not be started");
                return ExitCode::from(1);
            }
        };
    let stdout = io::stdout();
    let mut observer = MachineLoginObserver::new(stdout.lock());

    match client.login_with_observer(&mut observer).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            write_machine_error("LOGIN_FAILED", "Login did not complete.");
            eprintln!("machine login did not complete");
            ExitCode::from(1)
        }
    }
}

async fn run_refresh_request(request: corplink_rs::machine::MachineRequest) -> ExitCode {
    let machine_config = match request.into_client_config() {
        Ok(config) => config,
        Err(_) => {
            write_machine_error("INVALID_REQUEST", "Machine request is invalid.");
            eprintln!("machine request is invalid");
            return ExitCode::from(1);
        }
    };
    let client =
        match Client::new_with_cookie_file(machine_config.config, machine_config.cookie_file) {
            Ok(client) => client,
            Err(_) => {
                write_machine_error("REFRESH_FAILED", "Cookie refresh could not be started.");
                eprintln!("machine refresh could not be started");
                return ExitCode::from(1);
            }
        };
    run_refresh_client(client).await
}

async fn run_refresh_config(config_path: PathBuf) -> ExitCode {
    log::set_max_level(log::LevelFilter::Off);
    let path = match config_path.to_str() {
        Some(path) => path,
        None => {
            write_machine_error("INVALID_REQUEST", "Configuration path is invalid.");
            eprintln!("refresh configuration path is invalid");
            return ExitCode::from(1);
        }
    };
    let config = match Config::from_file(path).await {
        Ok(config) => config,
        Err(_) => {
            write_machine_error("REFRESH_FAILED", "Cookie refresh could not be started.");
            eprintln!("refresh configuration could not be loaded");
            return ExitCode::from(1);
        }
    };
    let client = match Client::new(config) {
        Ok(client) => client,
        Err(_) => {
            write_machine_error("REFRESH_FAILED", "Cookie refresh could not be started.");
            eprintln!("refresh client could not be started");
            return ExitCode::from(1);
        }
    };
    run_refresh_client(client).await
}

async fn run_refresh_client(mut client: Client) -> ExitCode {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if write_event(
        &mut stdout,
        &MachineEvent::new(corplink_rs::machine::Event::RefreshStarted),
    )
    .is_err()
    {
        eprintln!("machine refresh status could not be written");
        return ExitCode::from(1);
    }

    match client.refresh_cookie_once().await {
        Ok(RefreshOutcome::Updated) => write_refresh_success(&mut stdout, true),
        Ok(RefreshOutcome::Verified) => write_refresh_success(&mut stdout, false),
        Ok(RefreshOutcome::AuthRequired) => {
            let mut event = MachineEvent::new(corplink_rs::machine::Event::AuthRequired);
            event.message = Some("Cookie has expired or requires login.".to_string());
            match write_event(&mut stdout, &event) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("machine refresh status could not be written");
                    ExitCode::from(1)
                }
            }
        }
        Err(_) => {
            let event = MachineEvent::error("REFRESH_FAILED", "Cookie refresh did not complete.");
            let _ = write_event(&mut stdout, &event);
            eprintln!("machine refresh did not complete");
            ExitCode::from(1)
        }
    }
}

fn write_refresh_success<W: io::Write>(writer: &mut W, cookie_updated: bool) -> ExitCode {
    let mut event = MachineEvent::new(corplink_rs::machine::Event::RefreshSucceeded);
    event.cookie_updated = Some(cookie_updated);
    match write_event(writer, &event) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("machine refresh status could not be written");
            ExitCode::from(1)
        }
    }
}

fn machine_request_error(error: RequestError) -> ExitCode {
    write_machine_error(error.code(), error.message());
    eprintln!("machine request rejected");
    ExitCode::from(1)
}

fn write_machine_error(code: &'static str, message: &'static str) {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let _ = write_event(&mut stdout, &MachineEvent::error(code, message));
}
