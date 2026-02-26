// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::sync::Mutex;
use std::fs::File;
use stacks_common::util::get_epoch_time_ms;

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum LogLevel {
    Debug = 3,
    Info = 2,
    Warn = 1,
    Error = 0,
}

impl LogLevel {
    pub fn as_u8(&self) -> u8 {
        match *self {
            Self::Debug => 3,
            Self::Info => 2,
            Self::Warn => 1,
            Self::Error => 0,
        }
    }
}

lazy_static! {
    pub static ref LOGFILE: Mutex<Option<File>> = Mutex::new(Some(
        File::options()
            .append(true)
            .write(true)
            .open("/dev/stderr")
            .expect("FATAL: failed to open /dev/stderr")
    ));
    pub static ref LOGLEVEL: Mutex<Option<LogLevel>> = Mutex::new(None);
}

pub fn redirect_logfile(new_path: &str) -> Result<(), io::Error> {
    let new_file = File::options()
        .create(true)
        .append(true)
        .write(true)
        .open(new_path)?;
    match LOGFILE.lock() {
        Ok(mut lf_opt) => lf_opt.replace(new_file),
        Err(_e) => {
            panic!("Logfile mutex poisoned");
        }
    };
    Ok(())
}

pub fn with_logfile<F, R>(func: F) -> Option<R>
where
    F: FnOnce(&mut File) -> R,
{
    match LOGFILE.lock() {
        Ok(mut lf_opt) => lf_opt.as_mut().map(|lf| func(lf)),
        Err(_e) => {
            panic!("Logfile mutex poisoned");
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Debug => write!(f, "DEBG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERRO"),
        }
    }
}

pub fn get_loglevel() -> LogLevel {
    match LOGLEVEL.lock() {
        Ok(mut ll_opt) => {
            if let Some(ll) = ll_opt.as_ref() {
                *ll
            } else {
                if env::var("M2_DEBUG") == Ok("1".into()) {
                    (*ll_opt).replace(LogLevel::Debug);
                    LogLevel::Debug
                } else {
                    (*ll_opt).replace(LogLevel::Info);
                    LogLevel::Info
                }
            }
        }
        Err(_e) => {
            panic!("FATAL: log mutex poisoned");
        }
    }
}

pub fn write_to_log(msg: &str) -> Result<(), io::Error> {
    with_logfile(|lf| lf.write_all(msg.as_bytes())).unwrap_or(Ok(()))
}

pub fn log_fmt(level: LogLevel, file: &str, line: u32, msg: &str) -> String {
    let now = get_epoch_time_ms();
    format!(
        "{} [{}.{:03}] [{}:{}] [{:?}]: {}\n",
        &level,
        now / 1000,
        now % 1000,
        file,
        line,
        std::thread::current().id(),
        msg
    )
}

#[macro_export]
macro_rules! m2_test_debug {
    ($($arg:tt)*) => ({
        if cfg!(test) && crate::util::log::get_loglevel().as_u8() >= crate::util::log::LogLevel::Debug.as_u8() {
            let _ = crate::util::log::write_to_log(&crate::util::log::log_fmt(crate::util::log::LogLevel::Debug, file!(), line!(), &format!($($arg)*)));
        }
    })
}

#[macro_export]
macro_rules! m2_debug {
    ($($arg:tt)*) => ({
        if crate::util::log::get_loglevel().as_u8() >= crate::util::log::LogLevel::Debug.as_u8() {
            let _ = crate::util::log::write_to_log(&crate::util::log::log_fmt(crate::util::log::LogLevel::Debug, file!(), line!(), &format!($($arg)*)));
        }
    })
}

#[macro_export]
macro_rules! m2_info {
    ($($arg:tt)*) => ({
        if crate::util::log::get_loglevel().as_u8() >= crate::util::log::LogLevel::Info.as_u8() {
            let _ = crate::util::log::write_to_log(&crate::util::log::log_fmt(crate::util::log::LogLevel::Info, file!(), line!(), &format!($($arg)*)));
        }
    })
}

#[macro_export]
macro_rules! m2_warn {
    ($($arg:tt)*) => ({
        if crate::util::log::get_loglevel().as_u8() >= crate::util::log::LogLevel::Warn.as_u8() {
            let _ = crate::util::log::write_to_log(&crate::util::log::log_fmt(crate::util::log::LogLevel::Warn, file!(), line!(), &format!($($arg)*)));
        }
    })
}

#[macro_export]
macro_rules! m2_error {
    ($($arg:tt)*) => ({
        if crate::util::log::get_loglevel().as_u8() >= crate::util::log::LogLevel::Error.as_u8() {
            let _ = crate::util::log::write_to_log(&crate::util::log::log_fmt(crate::util::log::LogLevel::Error, file!(), line!(), &format!($($arg)*)));
        }
    })
}

