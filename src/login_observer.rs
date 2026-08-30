use std::io::Write;

#[cfg(feature = "full-client")]
use std::io::{self};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::machine::{write_event, Event, MachineEvent};
#[cfg(feature = "full-client")]
use crate::qrcode::TerminalQrCode;

pub trait LoginObserver {
    fn login_url(&mut self, url: &str, expires_at: DateTime<Utc>) -> Result<()>;
    fn waiting(&mut self) -> Result<()>;
    fn succeeded(&mut self, cookie_written: bool, auth_written: bool) -> Result<()>;
}

#[cfg(feature = "full-client")]
#[derive(Default)]
pub struct TerminalLoginObserver;

#[cfg(feature = "full-client")]
impl LoginObserver for TerminalLoginObserver {
    fn login_url(&mut self, url: &str, _expires_at: DateTime<Utc>) -> Result<()> {
        log::info!("please scan the QR code or visit the following link to auth corplink:\n{url}");
        print!("\x1b[2J\x1b[H");
        io::stdout().flush()?;
        TerminalQrCode::from_bytes(url.as_bytes()).print();
        Ok(())
    }

    fn waiting(&mut self) -> Result<()> {
        log::info!("请扫描二维码完成验证，扫码后自动继续...");
        Ok(())
    }

    fn succeeded(&mut self, _cookie_written: bool, _auth_written: bool) -> Result<()> {
        log::info!("扫码验证成功");
        Ok(())
    }
}

pub struct MachineLoginObserver<W: Write> {
    writer: W,
}

impl<W: Write> MachineLoginObserver<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> LoginObserver for MachineLoginObserver<W> {
    fn login_url(&mut self, url: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let mut event = MachineEvent::new(Event::LoginUrl);
        event.url = Some(url.to_string());
        event.expires_at = Some(expires_at.to_rfc3339());
        write_event(&mut self.writer, &event)
    }

    fn waiting(&mut self) -> Result<()> {
        write_event(&mut self.writer, &MachineEvent::new(Event::Waiting))
    }

    fn succeeded(&mut self, cookie_written: bool, auth_written: bool) -> Result<()> {
        let mut event = MachineEvent::new(Event::Success);
        event.cookie_written = Some(cookie_written);
        event.auth_written = Some(auth_written);
        write_event(&mut self.writer, &event)
    }
}
