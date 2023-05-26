use std::collections::HashMap;

use config::{Config, File};
use log::LevelFilter;

pub struct InjectorConfig {
    pub process_name: String,
    pub log_level_filter: LevelFilter,
}

pub fn read_config(name: &str) -> InjectorConfig {
    let config = Config::builder()
        .add_source(File::with_name(&name))
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
                _ => LevelFilter::Warn, // Defaults to Warn
            }
        }
        None => LevelFilter::Info,
    };

    InjectorConfig {
        process_name,
        log_level_filter,
    }
}
