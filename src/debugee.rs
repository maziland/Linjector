use std::{ffi::c_void, process::exit};

use log::{self};
use nix::{
    libc::user_regs_struct,
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DebugeeErr {
    #[error("Process not found `{0}`")]
    ProcessNotFound(String),
    #[error("Nix Error `{0}`")]
    NixError(#[from] nix::errno::Errno),
    #[error("Unexpected Wait Status `{0:#?}`")]
    UnexpectedWaitStatus(WaitStatus),
    #[error("StdIo Error `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Mmap Error `{0:#?}`")]
    MmapBadAddress(u64),
    #[error("Munmap Error `{0:#?}`")]
    MunmapFailed(u64),
}

pub type DebugeeResult<T> = Result<T, DebugeeErr>;
pub struct Debugee {
    pub pid: nix::unistd::Pid,
    pub process_name: String,
    is_attached: bool,
}

impl Debugee {
    pub fn new(process_name: String) -> Self {
        let dbg: Debugee = Debugee {
            pid: get_pid_from_process_name(process_name.as_str()),
            process_name,
            is_attached: false,
        };
        dbg
    }

    pub fn attach(&mut self) {
        ptrace::attach(self.pid).unwrap_or_else(|error| {
            log::error!("Failed attaching to process, error: {}", error);
            exit(-1);
        });
        self.is_attached = true;
        log::info!("Successfuly attached pid {}", self.pid);
    }

    pub fn detach(&mut self) {
        if (self.is_attached) {
            // Detach with ptrace
            match ptrace::detach(self.pid, Signal::SIGCONT) {
                Ok(()) => {
                    log::info!("Successfuly detached pid {}", self.pid);
                    self.is_attached = false;
                }
                Err(error) => {
                    log::error!("Failed detaching from process, error: {}", error);
                    exit(-1);
                }
            }
        } else {
            log::warn!("Debugee is detached already");
        }
    }

    fn single_step(&self) -> DebugeeResult<()> {
        ptrace::step(self.pid, None)?;
        self.wait_trap()
    }

    fn wait_trap(&self) -> DebugeeResult<()> {
        match self.wait()? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => Ok(()),
            status => Err(DebugeeErr::UnexpectedWaitStatus(status)),
        }
    }

    fn wait(&self) -> DebugeeResult<WaitStatus> {
        waitpid(self.pid, None).map_err(DebugeeErr::NixError)
    }

    // Wrapping ptrace write
    fn write(&self, addr: *mut c_void, data: *mut c_void) -> DebugeeResult<()> {
        log::trace!("writing to address: {:#?}", addr);
        unsafe { ptrace::write(self.pid, addr, data).map_err(DebugeeErr::NixError) }
    }

    // Wrapping ptrace read
    fn read(&self, addr: *mut c_void) -> DebugeeResult<i64> {
        log::trace!("reading from address: {:#?}", addr);
        ptrace::read(self.pid, addr).map_err(DebugeeErr::NixError)
    }

    pub fn syscall(
        &self,
        syscall: syscalls::Sysno,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        rcx: u64,
        r8: u64,
        r9: u64,
    ) -> DebugeeResult<user_regs_struct> {
        if !self.is_attached {
            log::error!("There is no debugee attached");
            exit(-1);
        }

        let backup_registers = ptrace::getregs(self.pid)?;

        // In order to syscall, we need to set RIP to a SYSCALL gadget
        let original_rip = backup_registers.rip as *mut c_void;
        let original_rip_opcodes = self.read(original_rip)? as *mut c_void;

        // Write our syscall opcode to RIP
        let syscall_opcode = u16::from_le_bytes([0x0F, 0x05]) as *mut c_void;
        self.write(original_rip, syscall_opcode)?;

        // Provide registers for the syscall
        let mut new_registers = backup_registers;
        new_registers.rax = syscall as u64;
        new_registers.rdi = rdi;
        new_registers.rsi = rsi;
        new_registers.rdx = rdx;
        new_registers.rcx = rcx;
        new_registers.r8 = r8;
        new_registers.r9 = r9;

        ptrace::setregs(self.pid, new_registers).unwrap_or_else(|error| {
            log::error!("Failed setting new registers, error: {}", error);
        });

        log::info!("Successfuly changed syscall opcode and registers");
        self.single_step()?;

        let result = ptrace::getregs(self.pid)?;

        // Restore original instructions, and original registers to continue normal program control flow
        self.write(original_rip, original_rip_opcodes)?;
        ptrace::setregs(self.pid, backup_registers)?;
        log::info!("Restored opcodes and registers");

        log::info!("Syscall return value: {:#?}", result.rax as *mut c_void);
        Ok(result)
    }
}

// Debugee destructor
impl Drop for Debugee {
    fn drop(&mut self) {
        if self.is_attached {
            log::trace!("Dropping debugee");
            self.detach();
        }
    }
}

fn get_pid_from_process_name(process_name: &str) -> nix::unistd::Pid {
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
