use log::{self};
use syscalls::Sysno;

mod debugee;
mod utils;

use crate::debugee::Debugee;
use debugee::DebugeeResult;
use nix::libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
fn main() -> DebugeeResult<()> {
    // Read config file
    let injector_config = utils::read_config("config");

    // Set logger
    pretty_env_logger::formatted_builder()
        .filter_level(injector_config.log_level_filter)
        .init();

    log::trace!(
        "built config with: process_name: '{}'",
        injector_config.process_name
    );

    let mut debugee = Debugee::new(injector_config.process_name);
    debugee.attach();
    let _mem_address = debugee
        .syscall(
            Sysno::mmap,
            0,                                    // start
            11,                                   // len
            (PROT_READ | PROT_WRITE) as u64,      // prot
            (MAP_PRIVATE | MAP_ANONYMOUS) as u64, // flags
            0,                                    // fd
            0,                                    // offset
        )
        .unwrap()
        .rax;

    debugee.write(_mem_address, &[1, 2, 3, 4, 5])?;
    let mem = debugee.read(_mem_address, 11)?;
    for a in mem {
        log::trace!("{a}");
    }
    Ok(())
}
