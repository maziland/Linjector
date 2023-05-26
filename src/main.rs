use log::{self};
use nix::{
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use pretty_env_logger;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

mod utils;
fn main() {
    // Read config file
    let injector_config = utils::read_config("config");

    // Set logger
    pretty_env_logger::formatted_builder()
        .filter_level(injector_config.log_level_filter)
        .init();

    // Find process instances
    let system = System::new_all();
    let process_instances = system
        .processes_by_exact_name(&injector_config.process_name)
        .take(2)
        .collect::<Vec<_>>();

    // Verify there's only one
    if process_instances.len() != 1 {
        log::error!("haven't found a specific process");
        return;
    }
    let process = process_instances[0];
    log::info!(
        "pid: {} --- name: {}",
        process_instances[0].pid(),
        process_instances[0].name()
    );

    let pid = Pid::from_raw(process.pid().as_u32() as i32);
    let result = ptrace::attach(pid);
    result.unwrap_or_else(|error| log::info!("Failed attaching to process, error: {}", error));
    log::info!("Successfuly attached pid {}", pid);

    let detach = ptrace::detach(pid, Signal::SIGCONT);
    detach.unwrap_or_else(|error| log::info!("Failed detaching from process, error: {}", error));
    log::info!("Successfuly detached pid {}", pid);
}
