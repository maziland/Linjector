use std::collections::HashMap;

use config::{Config, File};
use log::LevelFilter;
use std::process::exit;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
pub struct InjectorConfig {
    pub process_name: String,
    pub log_level_filter: LevelFilter,
}

pub fn read_config(name: &str) -> InjectorConfig {
    let config = Config::builder()
        .add_source(File::with_name(name))
        .build()
        .unwrap_or_else(|e| panic!("Error: {}", e));

    let hashmap = config.try_deserialize::<HashMap<String, String>>().unwrap();
    let process_name = hashmap.get("process_name").unwrap().to_string();
    let log_level_filter = match hashmap.get("log_level_filter") {
        Some(filter) => {
            match filter.as_str() {
                "trace" => LevelFilter::Trace,
                "debug" => LevelFilter::Debug,
                "info" => LevelFilter::Info,
                "warn" => LevelFilter::Warn,
                "error" => LevelFilter::Error,
                _ => LevelFilter::Info, // Defaults to Info
            }
        }
        None => LevelFilter::Info,
    };

    InjectorConfig {
        process_name,
        log_level_filter,
    }
}

pub fn get_pid_from_process_name(process_name: &str) -> nix::unistd::Pid {
    let system = System::new_all();
    let process_instances = system
        .processes_by_exact_name(process_name)
        .take(2)
        .collect::<Vec<_>>();

    // Verify there's only one
    match process_instances.len() {
        0 => {
            log::error!("Process not found!");
            exit(-1)
        }
        2 => {
            log::error!("Found more than 1 process for the given name!");
            exit(-1)
        }
        _ => {} // Gets here if there's 1 - should continue executing
    }

    let process = process_instances[0];
    log::info!("Found '{}' with pid: {}", process.name(), process.pid());
    let pid_u32 = PidExt::as_u32(process.pid());
    nix::unistd::Pid::from_raw(pid_u32 as i32)
}
