use crate::utils::get_pid_from_process_name;
use log::{self};
use nix::libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use nix::{
    libc::user_regs_struct,
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
};
use pete::{Ptracer, Tracee};
use std::{ffi::c_void, mem, process::exit};
use syscalls::Sysno;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DebugeeErr {
    #[error("Nix Error `{0}`")]
    NixError(#[from] nix::errno::Errno),
    #[error("Unexpected Wait Status `{0:#?}`")]
    UnexpectedWaitStatus(WaitStatus),
    #[error("StdIo Error `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Mmap Error `{0:#?}`")]
    MmapBadAddress(u64),
    #[error("Munmap Error `{0:#x?}`")]
    MunmapFailed(u64),
    #[error("Pete Error: `{0:#?}`")]
    PeteError(#[from] pete::Error),
    #[error("No debugee attached!")]
    NoDebugeeAttached(),
}

pub type DebugeeResult<T> = Result<T, DebugeeErr>;
pub struct Debugee {
    pub pid: nix::unistd::Pid,
    pub process_name: String,
    pub tracee: Option<Tracee>,
    is_attached: bool,
    memory_allocations: Vec<MemoryAllocation>,
}

pub struct MemoryAllocation {
    address: u64,
    len: u64,
}

impl Debugee {
    pub fn new(process_name: String) -> Self {
        let pid = get_pid_from_process_name(process_name.as_str());
        let debugee: Debugee = Debugee {
            pid,
            process_name,
            tracee: None,
            is_attached: false,
            memory_allocations: Vec::new(),
        };
        debugee
    }

    fn get_tracee(&self) -> Tracee {
        if let Some(tracee) = self.tracee {
            tracee.to_owned()
        } else {
            log::error!("Problem obtaining tracee");
            exit(-1);
        }
    }

    pub fn attach(&mut self) {
        let mut ptracer = Ptracer::new();
        log::trace!("Attaching process...");
        // TODO: fix error return value
        let _a = ptracer.attach(self.pid);
        if _a.is_err() {
            log::trace!("ERR");
        }

        match ptracer.wait() {
            Ok(tracee) => {
                log::info!("Successfully attached pid {}", self.pid);
                self.is_attached = true;
                self.tracee = tracee;
                tracee
            }
            _ => {
                log::error!("Failed attaching to process");
                exit(-1)
            }
        };
    }

    pub fn detach(&mut self) {
        if self.is_attached {
            // Detach with ptrace
            match ptrace::detach(self.pid, Signal::SIGCONT) {
                Ok(()) => {
                    log::info!("Successfully detached pid {}", self.pid);
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
    pub fn write(&mut self, addr: u64, data: &[u8]) -> DebugeeResult<usize> {
        self.get_tracee()
            .write_memory(addr, data)
            .map_err(DebugeeErr::PeteError)
    }

    // Wrapping ptrace read
    pub fn read(&self, addr: u64, len: usize) -> DebugeeResult<Vec<u8>> {
        self.get_tracee()
            .read_memory(addr, len)
            .map_err(DebugeeErr::PeteError)
    }

    pub fn allocate_memory(&mut self, len: u64) -> DebugeeResult<u64> {
        let mmap_ret_address = &self
            .syscall(
                Sysno::mmap,
                0,                                    // start
                len,                                  // len
                (PROT_READ | PROT_WRITE) as u64,      // prot
                (MAP_PRIVATE | MAP_ANONYMOUS) as u64, // flags
                0,                                    // fd
                0,                                    // offset
            )?
            .rax;

        if *mmap_ret_address == 0 {
            log::error!(
                "Memory allocation failed! mmap return address: {:#018x}",
                mmap_ret_address
            );
            Err(DebugeeErr::MmapBadAddress(*mmap_ret_address))
        } else {
            log::trace!("Successfully allocated {} bytes!", len);
            let mem_alloc = MemoryAllocation {
                address: *mmap_ret_address,
                len: len,
            };
            self.memory_allocations.push(mem_alloc);
            Ok(*mmap_ret_address)
        }
    }

    pub fn deallocate_memory(&mut self, addr: u64, len: u64) -> DebugeeResult<()> {
        let munmap_ret_address = &self.syscall(Sysno::munmap, addr, len, 0, 0, 0, 0)?.rax;

        if *munmap_ret_address != 0 {
            log::error!(
                "Memory deallocation failed! munmap return address: {}",
                munmap_ret_address
            );
            Err(DebugeeErr::MunmapFailed(*munmap_ret_address))
        } else {
            log::trace!("Successfully deallocated {} bytes!", len);
            // Remove this address from the allocations vector
            if let Some(index) = self
                .memory_allocations
                .iter()
                .position(|allocation| allocation.address == addr)
            {
                self.memory_allocations.swap_remove(index);
            }
            Ok(())
        }
    }

    pub fn deallocate_all_addresses(&mut self) -> DebugeeResult<()> {
        let allocations_to_deallocate: Vec<_> = self.memory_allocations.drain(..).collect();
        for memory_allocation in allocations_to_deallocate.iter() {
            self.deallocate_memory(memory_allocation.address, memory_allocation.len)?;
        }
        Ok(())
    }

    pub fn syscall(
        &mut self,
        syscall: syscalls::Sysno,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> DebugeeResult<user_regs_struct> {
        if !self.is_attached {
            log::error!("There is no debugee attached");
            return Err(DebugeeErr::NoDebugeeAttached());
        }
        let syscall_name = syscall.name();
        let syscall_number = syscall.id();
        let backup_registers = self.get_tracee().registers()?;

        // In order to syscall, we need to set RIP to a SYSCALL gadget
        let original_rip = backup_registers.rip;
        let original_rip_opcodes = self.read(original_rip, mem::size_of::<u64>())?;

        // Write our syscall opcode to RIP
        // let syscall_opcode = u16::from_le_bytes([0x0F, 0x05]);
        let syscall_opcode: &[u8] = &[0x0F, 0x05];
        self.write(original_rip, &syscall_opcode)?;

        // Provide registers for the syscall
        let mut new_registers = backup_registers;
        new_registers.rax = syscall as u64;
        new_registers.rdi = rdi;
        new_registers.rsi = rsi;
        new_registers.rdx = rdx;
        new_registers.r10 = r10;
        new_registers.r8 = r8;
        new_registers.r9 = r9;

        ptrace::setregs(self.pid, new_registers)?;

        log::trace!("Changed opcodes and registers");
        log::trace!(
            "Executing `{syscall_name} ({syscall_number})` with: {rdi}, {rsi}, {rdx}, {r10}, {r8}, {r9}"
        );
        self.single_step()?;
        let result = ptrace::getregs(self.pid)?;

        // Restore original instructions, and original registers to continue normal program control flow
        self.write(original_rip, &original_rip_opcodes)?;

        self.get_tracee().set_registers(backup_registers)?;
        log::trace!("Restored opcodes and registers");

        log::trace!("Syscall return value: {:#?}", result.rax as *mut c_void);
        Ok(result)
    }
}

// Debugee destructor
impl Drop for Debugee {
    fn drop(&mut self) {
        if self.is_attached {
            log::trace!("Dropping debugee");
            let _ = self.deallocate_all_addresses();
            self.detach();
        }
    }
}
