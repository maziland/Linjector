use log::{self};

mod debugee;
mod utils;

use debugee::{Debugee, DebugeeResult};
use nix::libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use syscalls::Sysno;
fn main() -> DebugeeResult<()> {
    // Read config file
    let injector_config = utils::read_config("config");

    // Set logger
    pretty_env_logger::formatted_builder()
        .filter_level(injector_config.log_level_filter)
        .init();

    log::trace!(
        "built config with: process_name: '{}', log_level_filter: {}",
        injector_config.process_name,
        injector_config.log_level_filter
    );

    let mut debugee = Debugee::new(injector_config.process_name);
    debugee.attach();
    let mem_address = debugee.syscall(
        Sysno::mmap,
        0,
        10,
        (PROT_READ | PROT_WRITE) as u64,
        (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
        u64::MAX,
        0,
    )?;

    // let mem_address = debugee.syscall(Sysno::exit, 42, 0, 0, 0, 0, 0)?;
    debugee.detach();

    Ok(())
}
