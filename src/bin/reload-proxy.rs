use nix::errno::Errno;
use nix::libc::c_int;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, kill, sigaction};
use nix::sys::wait::{WaitStatus, wait};
use nix::unistd::Pid;
use std::env;
use std::env::args_os;
use std::ffi::OsString;
use std::process::{Command, ExitCode, exit};
use std::sync::atomic::{AtomicBool, Ordering};

static GOT_SIGHUP: AtomicBool = AtomicBool::new(false);

extern "C" fn handlerfunc(signum: c_int) {
    if signum == Signal::SIGHUP as c_int {
        GOT_SIGHUP.store(true, Ordering::Relaxed);
    }
}

fn install_signal_handler() {
    unsafe {
        let handler = SigHandler::Handler(handlerfunc);
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
        sigaction(Signal::SIGHUP, &action).unwrap();
    }
}

fn fork_child(command: &mut Command) -> Option<Pid> {
    match command.spawn() {
        Ok(child) => {
            let pid = Pid::from_raw(child.id() as i32);
            eprintln!("spawned new daemon instance pid {pid}");
            Some(pid)
        }
        Err(err) => {
            eprintln!("spawn new daemon instance: {}", err);
            None
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = args_os().collect();

    if argv.len() < 2 {
        eprintln!("usage: reload-proxy DAEMON_PATH [args...]");
        return ExitCode::FAILURE;
    }

    let mut command = Command::new(&argv[1]);
    command.args(&argv[2..]);

    if env::var_os("LISTEN_FDS").is_some() {
        command.env("SRMILTER_LISTEN_FD", "3");
    }

    install_signal_handler();

    let mut children: Vec<Pid> = Vec::with_capacity(2);

    match fork_child(&mut command) {
        Some(pid) => children.push(pid),
        None => exit(1),
    }

    loop {
        let result = wait();
        match result {
            Ok(status) => match status {
                WaitStatus::Exited(pid, status) => {
                    eprintln!("child {pid} exited with status {status}");
                    children.retain(|&x| x != pid);
                    if children.is_empty() {
                        eprintln!("last child exited");
                        return if status == 0 {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        };
                    }
                }
                WaitStatus::Signaled(pid, signal, _core) => {
                    eprintln!("child {pid} terminated on signal {signal}");
                    children.retain(|&x| x != pid);
                    if children.is_empty() {
                        eprintln!("last child exited");
                        return ExitCode::FAILURE;
                    }
                }
                _ => (),
            },
            Err(Errno::EINTR) => (),
            Err(e) => {
                eprintln!("wait: {:?}", e);
                return ExitCode::FAILURE;
            }
        }
        if GOT_SIGHUP
            .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            if let Some(new_pid) = fork_child(&mut command) {
                for old_pid in &children {
                    eprintln!("send SIGINT to {old_pid}");
                    if let Err(e) = kill(*old_pid, Signal::SIGINT) {
                        eprintln!("kill -INT {old_pid}: {e}");
                    }
                }
                children.push(new_pid);
            }
        }
    }
}
