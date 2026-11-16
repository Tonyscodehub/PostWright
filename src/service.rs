//! Running Postwright as a system service that starts at boot: a real Windows service
//! (Services / services.msc), or a systemd unit on Linux.

#[allow(unused_imports)]
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

#[cfg_attr(not(windows), allow(dead_code))]
pub const NAME: &str = "Postwright";

static AS_SERVICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True inside the Windows service process.
pub fn running_as_service() -> bool {
    AS_SERVICE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Stops `serve` (used by the Windows service control handler).
pub static STOP: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    NotInstalled,
    Stopped,
    Running,
    Other(String),
}

impl State {
    pub fn describe(&self) -> String {
        match self {
            State::NotInstalled => "not installed".into(),
            State::Stopped => "installed, stopped".into(),
            State::Running => "installed, running".into(),
            State::Other(s) => format!("installed, {s}"),
        }
    }
}

fn paths(config: &Path) -> Result<(PathBuf, PathBuf)> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let cfg = config.canonicalize().with_context(|| format!("{} doesn't exist", config.display()))?;
    #[cfg(windows)]
    {
        // canonicalize() gives \\?\C:\... which the service manager doesn't need.
        let strip = |p: PathBuf| PathBuf::from(p.display().to_string().trim_start_matches(r"\\?\").to_string());
        return Ok((strip(exe), strip(cfg)));
    }
    #[allow(unreachable_code)]
    Ok((exe, cfg))
}

// ------------------------------------------------------------------ Windows

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsString;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    fn denied(e: windows_service::Error) -> anyhow::Error {
        let t = format!("{e:?}");
        if t.contains("code: 5") || t.contains("Access is denied") || t.contains("os error 5") {
            anyhow::anyhow!("Windows refused: start Postwright with \"Run as administrator\" to manage the service")
        } else {
            anyhow::anyhow!("{e}")
        }
    }

    pub fn install(config: &Path) -> Result<String> {
        let (exe, cfg) = paths(config)?;
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE).map_err(denied)?;
        let info = ServiceInfo {
            name: OsString::from(NAME),
            display_name: OsString::from("Postwright mail server"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.clone(),
            launch_arguments: vec![OsString::from("service"), OsString::from("run"), OsString::from("-c"), cfg.clone().into_os_string()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let access = ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP;
        let svc = match mgr.open_service(NAME, access) {
            Ok(s) => {
                s.change_config(&info).map_err(denied)?;
                s
            }
            Err(_) => mgr.create_service(&info, access).map_err(denied)?,
        };
        let _ = svc.set_description("Mail, calendars and contacts (SMTP, IMAP, CalDAV, CardDAV).");
        let _ = svc.set_delayed_auto_start(false);
        // Restart after 5 s, 30 s, then every minute if it ever stops unexpectedly.
        let _ = svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
            ]),
        });
        let _ = svc.set_failure_actions_on_non_crash_failures(true);
        let fw = firewall();
        // The scheduled task used by earlier versions isn't needed any more.
        let _ = std::process::Command::new("schtasks").args(["/Delete", "/TN", "Postwright", "/F"]).output();
        Ok(format!("Windows service \"{NAME}\": starts automatically at boot and restarts if it stops. It runs {} with {}. {fw}", exe.display(), cfg.display()))
    }

    /// Windows Firewall rules for the mail ports (2222 for certificate pushes only from
    /// the admin networks' gateway range). Replaces any earlier Postwright rules.
    fn firewall() -> String {
        let netsh = |args: &[&str]| std::process::Command::new("netsh").args(args).output().map(|o| o.status.success()).unwrap_or(false);
        for name in ["Postwright mail", "Postwright cert push"] {
            let _ = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={name}")]);
        }
        let a = netsh(&["advfirewall", "firewall", "add", "rule", "name=Postwright mail", "dir=in", "action=allow", "protocol=TCP", "localport=25,465,587,143,993,443"]);
        let b = netsh(&["advfirewall", "firewall", "add", "rule", "name=Postwright cert push", "dir=in", "action=allow", "protocol=TCP", "localport=2222", "remoteip=localsubnet"]);
        if a && b {
            "Windows Firewall now allows ports 25, 465, 587, 143, 993 and 443, and 2222 from the local network.".into()
        } else {
            "Couldn't add the Windows Firewall rules; allow ports 25, 465, 587, 143, 993, 443 and 2222 (local network) yourself.".into()
        }
    }

    pub fn uninstall() -> Result<String> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(denied)?;
        let svc = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE).map_err(denied)?;
        if let Ok(s) = svc.query_status() {
            if s.current_state != ServiceState::Stopped {
                let _ = svc.stop();
                for _ in 0..30 {
                    std::thread::sleep(Duration::from_millis(500));
                    if svc.query_status().map(|s| s.current_state == ServiceState::Stopped).unwrap_or(true) {
                        break;
                    }
                }
            }
        }
        svc.delete().map_err(denied)?;
        for name in ["Postwright mail", "Postwright cert push"] {
            let _ = std::process::Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", &format!("name={name}")]).output();
        }
        Ok(format!("Windows service \"{NAME}\" removed"))
    }

    pub fn state() -> State {
        let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return State::NotInstalled };
        let Ok(svc) = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS) else { return State::NotInstalled };
        match svc.query_status().map(|s| s.current_state) {
            Ok(ServiceState::Running) => State::Running,
            Ok(ServiceState::Stopped) => State::Stopped,
            Ok(s) => State::Other(format!("{s:?}").to_ascii_lowercase()),
            Err(_) => State::Other("unknown".into()),
        }
    }

    pub fn start() -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(denied)?;
        let svc = mgr.open_service(NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS).map_err(denied)?;
        let r = svc.start::<&str>(&[]);
        // Judge by the outcome: the call can report an error even though the service
        // started (or was already running).
        for _ in 0..40 {
            match svc.query_status().map(|s| s.current_state) {
                Ok(ServiceState::Running) => return Ok(()),
                Ok(ServiceState::StartPending) => std::thread::sleep(Duration::from_millis(250)),
                _ => break,
            }
        }
        r.map_err(denied)?;
        anyhow::bail!("the service didn't start: see postwright.log next to the settings file")
    }

    pub fn stop() -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(denied)?;
        let svc = mgr.open_service(NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS).map_err(denied)?;
        if svc.query_status().map(|s| s.current_state == ServiceState::Stopped).unwrap_or(false) {
            return Ok(());
        }
        svc.stop().map_err(denied)?;
        for _ in 0..40 {
            if svc.query_status().map(|s| s.current_state == ServiceState::Stopped).unwrap_or(true) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    static CONFIG: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Called when the service manager starts us ("postwright service run").
    pub fn dispatch(config: PathBuf) -> Result<()> {
        let _ = CONFIG.set(config);
        service_dispatcher::start(NAME, ffi_service_main).context("this command is run by Windows' service manager; use \"postwright service start\" instead")?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        let handler = |c| match c {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                super::STOP.notify_one();
                // Windows waits for StopPending/Stopped; serve() returns within a moment.
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        super::AS_SERVICE.store(true, std::sync::atomic::Ordering::Relaxed);
        let Ok(h) = service_control_handler::register(NAME, handler) else { return };
        let status = |state, code: u32| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        };
        let _ = h.set_service_status(status(ServiceState::Running, 0));
        let cfg = CONFIG.get().cloned().unwrap_or_else(|| PathBuf::from("postwright.toml"));
        if let Some(dir) = cfg.parent() {
            crate::logbuf::log_to_file(&dir.join("postwright.log"));
        }
        let r = crate::serve(&cfg);
        if let Err(e) = &r {
            crate::logbuf::write_line(&format!("Postwright stopped: {e:#}"));
        }
        let _ = h.set_service_status(status(ServiceState::Stopped, if r.is_ok() { 0 } else { 1 }));
    }
}

// -------------------------------------------------------------------- Linux

#[cfg(unix)]
mod nix {
    use super::*;

    const UNIT: &str = "/etc/systemd/system/postwright.service";

    fn systemctl(args: &[&str]) -> Result<String> {
        let o = std::process::Command::new("systemctl").args(args).output().context("running systemctl")?;
        if !o.status.success() {
            bail!("systemctl {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn check() -> Result<()> {
        let root = std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0).unwrap_or(false);
        if !root {
            bail!("run Postwright as root (sudo) to manage the service");
        }
        if !Path::new("/run/systemd/system").exists() {
            bail!("this system doesn't use systemd; start Postwright from your init system instead");
        }
        Ok(())
    }

    pub fn install(config: &Path) -> Result<String> {
        check()?;
        let (exe, cfg) = paths(config)?;
        let unit = format!(
            "[Unit]\nDescription=Postwright mail server\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} -c {} serve\nRestart=always\nRestartSec=5\nLimitNOFILE=65536\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nProtectSystem=full\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n",
            exe.display(),
            cfg.display()
        );
        std::fs::write(UNIT, unit).with_context(|| format!("writing {UNIT}"))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "postwright"])?;
        Ok(format!("systemd service \"postwright\": starts automatically at boot and restarts if it stops. It runs {} with {}.", exe.display(), cfg.display()))
    }

    pub fn uninstall() -> Result<String> {
        check()?;
        let _ = systemctl(&["disable", "--now", "postwright"]);
        let _ = std::fs::remove_file(UNIT);
        systemctl(&["daemon-reload"])?;
        Ok("systemd service \"postwright\" removed".into())
    }

    pub fn state() -> State {
        if !Path::new(UNIT).exists() {
            return State::NotInstalled;
        }
        match std::process::Command::new("systemctl").args(["is-active", "postwright"]).output() {
            Ok(o) => match String::from_utf8_lossy(&o.stdout).trim() {
                "active" => State::Running,
                "inactive" | "failed" => State::Stopped,
                s => State::Other(s.to_string()),
            },
            Err(_) => State::Other("unknown".into()),
        }
    }

    pub fn start() -> Result<()> {
        check()?;
        systemctl(&["start", "postwright"]).map(|_| ())
    }

    pub fn stop() -> Result<()> {
        check()?;
        systemctl(&["stop", "postwright"]).map(|_| ())
    }
}

#[cfg(windows)]
pub use win::{dispatch, install, start, state, stop, uninstall};
#[cfg(unix)]
pub use nix::{install, start, state, stop, uninstall};

/// Hand over to the installed service: start it a few seconds after this process has
/// exited and released the ports, then exit.
pub fn hand_over() -> ! {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED: u32 = 0x0000_0008 | 0x0800_0000; // DETACHED_PROCESS | CREATE_NO_WINDOW
        let _ = std::process::Command::new("cmd").args(["/C", "ping -n 5 127.0.0.1 >nul & net start Postwright"]).creation_flags(DETACHED).spawn();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("sh").args(["-c", "sleep 3; systemctl start postwright"]).spawn();
    }
    println!("\n  Postwright now runs as a service and starts automatically at boot. This window can be closed.\n");
    std::process::exit(0);
}
