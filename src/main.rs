use log;
use nix::{
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use pretty_env_logger;
use std::{fmt::DebugTuple, process};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    log::info!("Hello, my pid is: {}", process::id());

    let system = System::new_all();
    let sshd_instances = system
        .processes_by_exact_name("sshd")
        .take(2)
        .collect::<Vec<_>>();

    if sshd_instances.len() != 1 {
        log::error!("haven't found a specific sshd process");
        return;
    }
    let process = sshd_instances[0];
    log::info!(
        "pid: {} --- name: {}",
        sshd_instances[0].pid(),
        sshd_instances[0].name()
    );

    let pid = Pid::from_raw(process.pid().as_u32() as i32);
    let result = ptrace::attach(pid);
    result.unwrap_or_else(|error| log::info!("Failed attaching to process, error: {}", error));
    log::info!("Successfuly attached pid {}", pid);

    let detach = ptrace::detach(pid, Signal::SIGCONT);
    detach.unwrap_or_else(|error| log::info!("Failed detaching from process, error: {}", error));
    log::info!("Successfuly detached pid {}", pid);
}
