use std::cmp::{min};
use std::str::{FromStr};
use std::ptr;
use std::fmt::{self, Formatter};
use std::num::ParseIntError;
use std::io::{Read, Write};
use std::os::fd::{RawFd};

use libc::{pid_t, WIFEXITED, WIFSIGNALED, SIGKILL, STDOUT_FILENO, ADDR_NO_RANDOMIZE, SIGTRAP, process_vm_readv};
use libc::{c_int, waitpid, kill, SIGSTOP, SIGCONT, WEXITSTATUS, WTERMSIG, WIFSTOPPED, WSTOPSIG, iovec, c_void, c_ulong};

use crate::error::{Error};
use crate::interop;
use crate::interop::{ptrace, ForkResult};
use crate::pipe::Pipe;
use crate::process::PIDParseError::OutOfRange;
use crate::register::{debug_register_index, RegisterId, Registers};
use crate::types::{StoppointMode, TryFromBytes, VirtualAddress};
use crate::stoppoint_collection::{StopPoint, StopPointCollection};
use crate::breakpoint_site::{BreakpointScope, BreakpointSite, BreakpointType};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProcessState {
    Stopped(Option<VirtualAddress>),
    Running,
    Exited,
    Terminated
}

impl ProcessState {
    pub fn stopped() -> Self {
        Self::Stopped(None)
    }

    pub fn stopped_at(pc: VirtualAddress) -> Self {
        Self::Stopped(Some(pc))
    }

    pub fn is_stopped(&self) -> bool {
        if let Self::Stopped(_) = self {
            true
        } else {
            false
        }
    }

    pub fn set_pc(&mut self, pc: VirtualAddress) {
        if self.is_stopped() {
            *self = Self::Stopped(Some(pc))
        }
    }
}

//#[derive(Debug)]
pub struct Process {
    pid: pid_t,
    state: ProcessState,
    terminate_on_end: bool,
    is_attached: bool,
    registers: Registers,
    breakpoint_sites: StopPointCollection<BreakpointSite>
}

#[derive(Copy, Clone, Debug)]
pub struct StopReason {
    pub reason: ProcessState,
    pub info: c_int
}

#[derive(Copy, Clone, Debug)]
pub struct PID(pid_t);

#[derive(Debug)]
pub enum PIDParseError {
    InvalidInt(ParseIntError),
    OutOfRange
}

impl FromStr for PID {
    type Err = PIDParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pid = s.parse::<pid_t>().map_err(PIDParseError::InvalidInt)?;
        if pid > 0 {
            Ok(PID(pid))
        } else {
            Err(OutOfRange)
        }
    }
}

impl StopReason {
    fn from_status(wait_status: c_int) -> Self {
        if WIFEXITED(wait_status) {
            Self {
                reason: ProcessState::Exited,
                info: WEXITSTATUS(wait_status)
            }
        } else if WIFSIGNALED(wait_status) {
            Self {
                reason: ProcessState::Terminated,
                info: WTERMSIG(wait_status)
            }
        } else if WIFSTOPPED(wait_status) {
            Self {
                reason: ProcessState::stopped(),
                info: WSTOPSIG(wait_status)
            }
        } else {
            panic!("Unknown status for process");
        }
    }
}

fn signal_description(signal: c_int) -> String {
    interop::str_signal(signal)
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.reason {
            ProcessState::Running => {
                write!(f, "running")
            },
            ProcessState::Exited => {
                write!(f, "exited with status {}", self.info)
            },
            ProcessState::Terminated => {
                write!(f, "terminated with signal {}", signal_description(self.info))
            },
            ProcessState::Stopped(addr_opt) => {
                match addr_opt {
                    None => write!(f, "stopped with signal {}", signal_description(self.info)),
                    Some(addr) => write!(f, "stopped with signal {} at {}", signal_description(self.info), addr)
                }
            }
        }
    }
}

fn exit_with_perror(channel: &mut Pipe, error: Error) -> ! {
    // write error message to pipe
    let msg = error.to_string();

    let _r = channel.write(msg.as_bytes());
    std::process::exit(-1);
}

#[derive(Copy, Clone, Debug)]
pub enum StdoutReplacement {
    None,
    Fd(RawFd)
}

impl Process {
    pub fn launch(path: &str, debug: bool, stdout_replacement: StdoutReplacement) -> Result<Self, Error> {
        // create pipe to communicate with child process
        let mut pipe = Pipe::create(true)?;

        match interop::fork()? {
            ForkResult::InChild => {
                // turn off ASLR for this process
                interop::personality(ADDR_NO_RANDOMIZE)?;
                //close read side of pipe
                pipe.close_read();

                // replace stdout with given file hande if specified
                if let StdoutReplacement::Fd(fd) = stdout_replacement {
                    if let Err(e) = interop::dup2(fd, STDOUT_FILENO) {
                        let e = e.with_context("stdout replacement failed");
                        exit_with_perror(&mut pipe, e);
                    }
                }

                // configure debugging if required
                if debug {
                    if let Err(e) = ptrace::traceme() {
                        exit_with_perror(&mut pipe, e);
                    }
                }

                // execute debuggee
                if let Err(e) = interop::execlp0(path) {
                    exit_with_perror(&mut pipe, e)
                }

                // if execlp succeeds then this line should not be reached
                unreachable!()
            },
            ForkResult::InParent(pid) => {
                pipe.close_write();

                // wait for child process to write to pipe
                // pipe is closed on exec so this will be empty if exec succeeds
                // otherwise an error message should be written by the child
                let mut msg = String::new();
                let bytes_written = pipe.read_to_string(&mut msg)?;

                if bytes_written > 0 {
                    // wait for child to exit
                    unsafe { waitpid(pid, ptr::null_mut(), 0); }
                    return Err(Error::from_message(msg));
                }

                // create handle for child proces and wait if debugging
                let mut proc = Self { pid, state: ProcessState::stopped(), terminate_on_end: true, is_attached: debug, registers: Registers::new(pid), breakpoint_sites: StopPointCollection::new() };

                if debug {
                    proc.wait_on_signal()?;
                }

                Ok(proc)
            }
        }
    }

    pub fn attach(pid: PID) -> Result<Self, Error> {
        ptrace::attach(pid.0)?;

        // read all register and get program counter
        let mut registers = Registers::new(pid.0);
        registers.read_all()?;
        let state = ProcessState::stopped_at(registers.get_pc());

        let mut proc = Self { pid: pid.0, state, terminate_on_end: false, is_attached: true, registers, breakpoint_sites: StopPointCollection::new() };
        proc.wait_on_signal()?;

        Ok(proc)
    }

    pub fn resume(&mut self) -> Result<(), Error> {
        // if we're at a breakpoint we need to disable the breakpoint, step over it to the next
        // instruction and then re-enable
        let pc = self.get_pc();
        if self.breakpoint_sites.enabled_stoppoint_at_address(pc) {
            let pid = self.pid;
            let bp = self.breakpoint_sites_mut().get_by_address_mut(pc)?;

            // disable breakpoint and step over
            bp.disable()?;
            ptrace::single_step(pid)?;
            let _wait_status = interop::wait_pid(pid, 0)?;

            // re-enable breakpoint
            bp.enable()?;
        }

        ptrace::cont(self.pid)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason, Error> {
        let wait_status = interop::wait_pid(self.pid, 0)?;
        let mut stop_reason = StopReason::from_status(wait_status);

        if self.is_attached && stop_reason.reason.is_stopped() {
            // read all registers and get program counter for stop state
            self.read_all_registers()?;
            let pc = self.get_pc();
            stop_reason.reason.set_pc(pc);

            // update program counter to point to breakpoint if it's the next instruction
            let instr_begin = pc - 1;
            if stop_reason.info == SIGTRAP && self.breakpoint_sites().enabled_stoppoint_at_address(instr_begin) {
                self.set_pc(instr_begin)?;
            }
        }

        self.state = stop_reason.reason;
        Ok(stop_reason)
    }

    pub fn step_instruction(&mut self) -> Result<StopReason, Error> {
        let pc = self.get_pc();
        let at_breakpoint = self.breakpoint_sites().enabled_stoppoint_at_address(pc);

        if at_breakpoint {
            // disable breakpoint at address
            let bp = self.breakpoint_sites_mut().get_by_address_mut(pc)?;
            bp.disable()?;
        }

        ptrace::single_step(self.pid)?;
        let reason = self.wait_on_signal()?;

        // re-enable breakpoint if required
        if at_breakpoint {
            let bp = self.breakpoint_sites_mut().get_by_address_mut(pc)?;
            bp.enable()?;
        }

        Ok(reason)
    }

    fn read_all_registers(&mut self) -> Result<(), Error> {
        self.registers.read_all()
    }

    pub fn write_user_area(&mut self, offset: usize, word: usize) -> Result<(), Error> {
        self.registers.write_user_area(offset, word)
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn registers(&self) -> &Registers { &self.registers }

    pub fn registers_mut(&mut self) -> &mut Registers { &mut self.registers }

    pub fn get_pc(&self) -> VirtualAddress {
        self.registers.get_pc()
    }

    pub fn set_pc(&mut self, addr: VirtualAddress) -> Result<(), Error> {
        self.registers.write_by_id(RegisterId::rip, addr)
    }

    pub fn create_breakpoint_site(&mut self, address: VirtualAddress, breakpoint_type: BreakpointType, scope: BreakpointScope) -> Result<&mut BreakpointSite, Error> {
        if self.breakpoint_sites.contains_address(address) {
            Err(Error::from_message(format!("Breakpoint site already created at address {}", address)))
        } else {
            let bp = BreakpointSite::new(self.pid, address, breakpoint_type, scope);
            Ok(self.breakpoint_sites.push(bp))
        }
    }

    pub fn breakpoint_sites(&self) -> &StopPointCollection<BreakpointSite> { &self.breakpoint_sites }
    pub fn breakpoint_sites_mut(&mut self) -> &mut StopPointCollection<BreakpointSite> { &mut self.breakpoint_sites }

    pub fn set_hardware_breakpoint(&mut self, id: <BreakpointSite as StopPoint>::IdType, address: VirtualAddress) -> Result<u8, Error> {
        self.set_hardware_stoppoint(address, StoppointMode::Execute, 1)
    }
    fn set_hardware_stoppoint(&mut self, address: VirtualAddress, mode: StoppointMode, size: usize) -> Result<u8, Error> {
        let control: u64 = self.registers().read_by_id_as(RegisterId::dr7);

        let reg_index = Self::find_free_stoppoint_register(control)?;
        let debug_register = debug_register_index(reg_index);

        let updated_control = {
            let mode_flag = Self::encode_hardware_stoppoint_mode(mode);
            let size_flag = Self::encode_hardware_stoppoint_size(size);

            let enable_bit: u64 = 1 << (reg_index * 2);
            let mode_bits: u64 = mode_flag << (reg_index * 4 + 16);
            let size_bits: u64 = size_flag << (reg_index * 4 + 18);
            let clear_mask: u64 = (0b11 << (reg_index * 2)) | (0b1111 << (reg_index * 4 + 16));
            let reset_control = control & !clear_mask;

            reset_control | enable_bit | mode_bits | size_bits
        };

        {
            let registers = self.registers_mut();

            // write address into debug register
            registers.write_by_id(debug_register, address)?;

            // update control register
            registers.write_by_id(RegisterId::dr7, updated_control)?;
        }

        Ok(reg_index)
    }

    fn clear_hardware_stoppoint(&mut self, register_index: u8) -> Result<(), Error> {
        let register_id = debug_register_index(register_index);
        self.registers_mut().write_by_id(register_id, 0u64)?;

        let control: u64 = self.registers.read_by_id_as(register_id);

        let updated_control = {
            let clear_mask: u64 = (0b11 << (register_index * 2)) | (0b1111 << (register_index * 4 + 16));
            control & !clear_mask
        };

        self.registers_mut().write_by_id(register_id, updated_control)
    }

    fn encode_hardware_stoppoint_mode(mode: StoppointMode) -> u64 {
        match mode {
            StoppointMode::Write => 0b01,
            StoppointMode::ReadWrite => 0b11,
            StoppointMode::Execute => 0b00
        }
    }

    fn encode_hardware_stoppoint_size(size: usize) -> u64 {
        match size {
            1 => 0b00,
            2 => 0b01,
            4 => 0b11,
            8 => 0b10,
            _ => panic!("Invalid stoppoint size {}", size)
        }
    }

    fn find_free_stoppoint_register(control_reg: u64) -> Result<u8, Error> {
        for i in 0..4 {
            let enabled_mask = 0b11 << (i * 2);
            if control_reg & enabled_mask == 0 {
                return Ok(i)
            }
        }

        Err(Error::from_message(String::from("No remaining hardware debug registers")))
    }

    pub fn read_memory(&self, address: VirtualAddress, num_bytes: usize) -> Result<Vec<u8>, Error> {
        let mut ret = vec![0u8; num_bytes];
        let local_desc = iovec { iov_base: ret.as_mut_ptr() as *mut c_void, iov_len: ret.len() };

        let mut remaining = num_bytes;
        let mut current_address = address;
        let mut remote_descs = Vec::new();

        while remaining > 0 {
            let up_to_next_page = 0x1000 - (address.addr() & 0xFFF);
            let chunk_size = min(remaining, up_to_next_page);

            remote_descs.push(iovec { iov_base: address.addr() as *mut c_void, iov_len: chunk_size });

            remaining -= chunk_size;
            current_address += chunk_size as isize;
        }

        let result = unsafe { process_vm_readv(
            self.pid,
            &local_desc,
            1,
            remote_descs.as_ptr(),
            remote_descs.len() as c_ulong,
            0
        )};

        if result < 0 {
            Err(Error::from_errno("Could not read process memory"))
        } else {
            Ok(ret)
        }
    }

    pub fn read_memory_without_traps(&self, address: VirtualAddress, num_bytes: usize) -> Result<Vec<u8>, Error> {
        let mut memory = self.read_memory(address, num_bytes)?;
        let address_range = address..(address + num_bytes as isize + 1);
        let sites = self.breakpoint_sites.get_in_region(&address_range);

        for site in sites.filter(|sp| sp.is_enabled() && sp.is_software()) {
            let offset = site.address() - address;
            memory[offset as usize] = site.saved_data()
        }

        Ok(memory)
    }

    pub fn read_memory_as<T: TryFromBytes>(&self, address: VirtualAddress) -> Result<T, Error> {
        let bytes = self.read_memory(address, size_of::<T>())?;
        match T::try_from_bytes(bytes.as_slice()) {
            Ok(v) => Ok(v),
            Err(e) => { panic!("Unexpected size for type: {}", e) }
        }
    }

    pub fn write_memory(&mut self, address: VirtualAddress, data: &[u8]) -> Result<(), Error> {
        let mut current_address = address;

        // write data to process memory a word at a time
        for chunk in data.chunks(8) {
            let word = match chunk.try_into() {
                Ok(arr) => { u64::from_le_bytes(arr) },
                Err(_) => {
                    // fewer than 8 bytes remaining
                    // read next 8 bytes from memory
                    // set first remaining bytes of the resulting word to the remainder of data
                    let read = self.read_memory(current_address, 8)?;
                    let mut word_bytes: [u8; 8] = read.try_into().expect("Unexpected number of bytes read");

                    word_bytes[0..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(word_bytes)
                }
            };

            ptrace::poke_data(self.pid, current_address, word as usize)?;
            current_address += chunk.len() as isize;
        }

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid != 0 {
            if self.state == ProcessState::Running {
                // request process to stop if running
                unsafe {
                    // NOTE: error from kill ignored
                    kill(self.pid, SIGSTOP);

                    let mut status = -1;
                    waitpid(self.pid, &mut status, 0);
                }
            }

            // detach from process if required
            if self.is_attached {
                unsafe {
                    // NOTE: errors ignored
                    let _r = ptrace::detach(self.pid);
                    kill(self.pid, SIGCONT);
                }
            }


            // kill process if we spawned it initially
            if self.terminate_on_end {
                unsafe {
                    kill(self.pid, SIGKILL);

                    let mut status = -1;
                    waitpid(self.pid, &mut status, 0);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{self, BufReader, BufRead};
    use std::fs::File;
    use std::mem;
    use std::path::{Path, PathBuf};
    use std::process::{Command};
    use libc::{ESRCH, Elf64_Addr, Elf64_Ehdr};
    use regex::Regex;
    use super::*;
    use crate::error::{errno};
    use crate::register::*;
    use crate::types::{Byte64, Byte128};

    fn process_exists(pid: pid_t) -> bool {
        let ret = unsafe { kill(pid, 0) };
        ret != -1 && errno() != ESRCH
    }

    fn get_process_status(pid: pid_t) -> io::Result<char> {
        let mut path = PathBuf::new();
        path.push("/proc");
        path.push(pid.to_string());
        path.push("stat");

        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        let proc_name_end = line.rfind(')').expect("Failed to find process name");

        // status should follow a space after the closing parenthesis around the process name
        // NOTE: rfind returns a byte index
        let status_indicator_index = proc_name_end + 2;
        Ok(line.as_bytes()[status_indicator_index] as char)
    }

    fn get_section_load_bias(path: &Path, file_address: Elf64_Addr) -> u64 {
        let output = Command::new("readelf")
            .args(["-W", "-S"])
            .arg(path)
            .output()
            .expect("Failed to execute readelf");

        let re = Regex::new(r"PROGBITS\s+(\w+)\s+(\w+)\s+(\w+)").expect("Invalid regex");

        // iterate over stdout
        for line_result in BufReader::new(output.stdout.as_slice()).lines() {
            if let Ok(line) = line_result {
                if let Some(captures) = re.captures(line.as_str()) {
                    let (_, [address, offset, size]) = captures.extract();
                    let address = u64::from_str_radix(address, 16).expect("Invalid address");
                    let offset = u64::from_str_radix(offset, 16).expect("Invalid offset");
                    let size = u64::from_str_radix(size, 16).expect("Invalid offset");

                    if address <= file_address && file_address < (address + size) {
                        return address - offset;
                    }
                }
            }
        }

        panic!("Could not find section load bias");
    }

    fn get_entry_point_offset(path: &Path) -> u64 {
        let mut header = unsafe { mem::zeroed::<Elf64_Ehdr>() };
        let p: *mut u8 = unsafe { mem::transmute(&mut header as *mut Elf64_Ehdr) };
        let bytes = unsafe { std::slice::from_raw_parts_mut(p, size_of::<Elf64_Ehdr>() ) };

        {
            let mut f = File::open(path).expect("Failed to open executable");
            f.read_exact(bytes).expect("Failed to read entire ELF header");
        }

        let entry_file_address = header.e_entry;
        entry_file_address - get_section_load_bias(path, entry_file_address)
    }

    fn get_load_address(pid: pid_t, offset: u64) -> VirtualAddress {
        let re = Regex::new(r"(\w+)-\w+ ..(.). (\w+)").expect("Invalid map line regex");
        let maps_file: PathBuf = ["/proc", pid.to_string().as_str(), "maps"].iter().collect();
        let f = File::open(maps_file).expect("Failed to open maps file");
        let mut reader = BufReader::new(f);

        for line_result in reader.lines() {
            if let Ok(line) = line_result {
                if let Some(captures) = re.captures(line.as_str()) {
                    let (_, [low_range, perm, file_offset]) = captures.extract();

                    if perm == "x" {
                        let low_range = u64::from_str_radix(low_range, 16).expect("Invalid low range");
                        let file_offset = u64::from_str_radix(file_offset, 16).expect("Invalid file offset");
                        let addr = offset - file_offset + low_range;
                        return VirtualAddress::new(addr as usize)
                    }
                }
            }
        }
        panic!("Could not find load address");
    }

    #[test]
    fn process_launch_succeeds() {
        let r = Process::launch("yes", true, StdoutReplacement::None).expect("Failed to start process");
        assert!(process_exists(r.pid()), "Process does not exist");
    }

    #[test]
    fn process_launch_no_such_program() {
        let r = Process::launch("you_do_not_have_to_be_good", true, StdoutReplacement::None);
        assert!(r.is_err(), "Expected error launching non-existant process");
    }

    #[test]
    fn process_attach_success() {
        let target = Process::launch("target/debug/run_endlessly", false, StdoutReplacement::None).expect("Failed to launch process");
        let _proc = Process::attach(PID(target.pid())).expect("Failed to attach to process");
        let status = get_process_status(target.pid()).expect("Failed to read process status");
        assert_eq!('t', status, "Unexpected process status");
    }

    #[test]
    fn process_resume_launched_success() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");
        proc.resume().expect("Failed to resume");

        let status = get_process_status(proc.pid()).expect("Failed to get process status");
        assert!(status == 'R' || status == 'S', "Unexpected process status after resume");
    }

    #[test]
    fn process_resume_attached_success() {
        let target = Process::launch("target/debug/run_endlessly", false, StdoutReplacement::None).expect("Failed to launch process");

        let mut proc = Process::attach(PID(target.pid())).expect("Failed to attach to process");
        proc.resume().expect("Failed to resume");

        let status = get_process_status(proc.pid()).expect("Failed to get process status");
        assert!(status == 'R' || status == 'S');
    }

    #[test]
    fn process_resume_already_terminated() {
        let mut proc = Process::launch("target/debug/end_immediately", true, StdoutReplacement::None).expect("Failed to launch process");
        proc.resume().expect("Failed to resume");
        let _reason = proc.wait_on_signal().expect("Failed to wait");
        let result = proc.resume();
        assert!(result.is_err(), "Expected error waiting on terminated process");
    }

    fn read_next_string(channel: &mut Pipe) -> String {
        let mut buf = [0u8; 100];
        let bytes_read = channel.read(buf.as_mut_slice()).expect("Failed to read");
        String::from_utf8(buf[0..bytes_read].to_vec()).expect("Invalid utf8")
    }

    // TODO: move to new tests directory?
    #[test]
    fn write_registers() {
        let close_on_exec = false;
        let mut channel = Pipe::create(close_on_exec).expect("Failed to create pipe");

        let mut proc = Process::launch("target/debug/reg_write", true, StdoutReplacement::Fd(channel.write_fd())).expect("Failed to launch process");
        channel.close_write();

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        proc.registers_mut().write_by_id(RegisterId::rsi, 0xcafecafeu32).expect("Failed to write register");

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        {
            let output = read_next_string(&mut channel);
            assert_eq!("0xcafecafe", output);
        };

        // write to mm0 register
        proc.registers_mut().write_by_id(RegisterId::mm0, 0xba5eba11u32).expect("Failed to write register");

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        {
            let output = read_next_string(&mut channel);
            assert_eq!("0xba5eba11", output);
        }

        // write to sse register
        proc.registers_mut().write_by_id(RegisterId::xmm0, 42.24f64).expect("Failed to write register");

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        {
            let output = read_next_string(&mut channel);
            assert_eq!("42.24", output);
        }

        // x87
        {
            let regs = proc.registers_mut();
            regs.write_by_id(RegisterId::fsw, 0b0011100000000000u16).expect("Failed to write fws register");
            regs.write_by_id(RegisterId::st0, 1234.56f128).expect("Failed to write st0");
            regs.write_by_id(RegisterId::ftw, 0b0011111111111111u16).expect("Failed to write ftw register");
        }

        proc.resume().expect("Failed to wait");
        proc.wait_on_signal().expect("Failed to wait");

        {
            let output = read_next_string(&mut channel);

            // TODO: fix!
            // assert_eq!("1234.56", output);
        }
    }

    #[test]
    fn read_registers() {
        let mut proc = Process::launch("target/debug/reg_read", true, StdoutReplacement::None).expect("Failed to launch process");

        proc.resume().expect("Failed to resume");
        let reason = proc.wait_on_signal().expect("Failed to wait");
        assert!(reason.reason.is_stopped());

        {
            // read r13
            let v: u64 = proc.registers_mut().read_by_id_as(RegisterId::r13);
            assert_eq!(0xcafecafeu64, v, "Unexpected value for R13");
        }

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        {
            // read r13b
            let v: u8 = proc.registers_mut().read_by_id_as(RegisterId::r13b);
            assert_eq!(42, v, "Unexpected value for R13b");
        }

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");
        {
            let v: Byte64 = proc.registers_mut().read_by_id_as(RegisterId::mm0);
            let expected = Byte64::from_le_bytes([0x11, 0xba, 0x5e, 0xba, 0, 0, 0, 0]);
            assert_eq!(expected, v, "Unexpected value for MM0");
        }

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        {
            let v: Byte128 = proc.registers_mut().read_by_id_as(RegisterId::xmm0);

            let expected_f = 64.125f64;
            let expected_bytes: Byte128 = expected_f.into();

            assert_eq!(v, expected_bytes, "Unexpected value loaded from XMM0 register");
        }

        proc.resume().expect("Failed to resume");
        proc.wait_on_signal().expect("Failed to wait");

        {
            let v: Byte128 = proc.registers_mut().read_by_id_as(RegisterId::st0);

            // TODO: figure out how to get the expected bytes for an 80-bit float
            //assert_eq!(expected_bytes, v, "Unexpected value for st0");
        }
    }

    #[test]
    fn can_create_breakpoint_site_test() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");
        let site_address = VirtualAddress::new(42);
        let site = proc.create_breakpoint_site(site_address, BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint");

        assert_eq!(site_address, site.address(), "Unexpected breakpoint address");
    }

    #[test]
    fn breakpoint_site_ids_increase() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");

        let (s1_id, s1_addr) = {
            let s1 = proc.create_breakpoint_site(VirtualAddress::new(42), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint s1");
            (s1.id(), s1.address())
        };
        assert_eq!(VirtualAddress::new(42), s1_addr);

        let s2_id = {
            let s2 = proc.create_breakpoint_site(VirtualAddress::new(43), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint s2");
            s2.id()
        };
        assert_eq!(s2_id, s1_id + 1);

        let s3_id = {
            let s3 = proc.create_breakpoint_site(VirtualAddress::new(44), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint s3");
            s3.id()
        };
        assert_eq!(s3_id, s1_id + 2);

        let s4_id = {
            let s4 = proc.create_breakpoint_site(VirtualAddress::new(45), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint s4");
            s4.id()
        };
        assert_eq!(s4_id, s1_id + 3);
    }

    #[test]
    fn can_find_breakpoint_site_test() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");

        proc.create_breakpoint_site(VirtualAddress::new(42), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint 1");
        proc.create_breakpoint_site(VirtualAddress::new(43), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint 2");
        proc.create_breakpoint_site(VirtualAddress::new(44), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint 3");
        proc.create_breakpoint_site(VirtualAddress::new(45), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint 4");

        let s1 = proc.breakpoint_sites.get_by_address(VirtualAddress::new(44)).expect("Failed to get breakpoint site 1");
        assert!(proc.breakpoint_sites().contains_address(VirtualAddress::new(44)), "Expected breakpoint to exist");
        assert_eq!(VirtualAddress::new(44), s1.address());

        // NOTE: c++ const tests ignored

        let s2 = proc.breakpoint_sites().get_by_id(s1.id() + 1).expect("Failed to get breakpoint site 2");
        assert!(proc.breakpoint_sites().contains_id(s1.id() + 1), "Expected breakpoint with id to exist");
        assert_eq!(s2.id(), s1.id() + 1, "Unexpected id for breakpoint 2");
        assert_eq!(VirtualAddress::new(45), s2.address(), "Unexpected address for breakpoint 2");

        // NOTE: more const tests ignored
    }

    #[test]
    fn cannot_find_breakpoint_site_test() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to create breakpoint site");

        assert!(proc.breakpoint_sites().get_by_address(VirtualAddress::new(44)).is_err(), "Unexpected breakpoint at address");
        assert!(proc.breakpoint_sites().get_by_id(44).is_err(), "Unexpected breakpoint with id");
    }

    #[test]
    fn breakpoint_site_list_and_emptiness_test() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");

        assert!(proc.breakpoint_sites().is_empty(), "Expected empty breakpoint list on launch");
        assert_eq!(0, proc.breakpoint_sites().len(), "Expected zero length breakpoint list on launch");

        proc.create_breakpoint_site(VirtualAddress::new(42), BreakpointType::Software, BreakpointScope::Internal).expect("Failed to create first breakpoint site");
        assert_eq!(false, proc.breakpoint_sites().is_empty(), "Expected non-empty breakpoint list after create");
        assert_eq!(1, proc.breakpoint_sites().len(), "Expected singleton breakpoint list after create");

        proc.create_breakpoint_site(VirtualAddress::new(43), BreakpointType::Software, BreakpointScope::Internal).expect("Failed to create second breakpoint site");
        assert_eq!(false, proc.breakpoint_sites.is_empty(), "Expected non-empty breakpoint list after second breakpoint created");
        assert_eq!(2, proc.breakpoint_sites().len(), "Expected breakpoint list of length 2 after second breakpoint created");
    }

    #[test]
    fn can_iterate_breakpoint_sites_test() {
        let mut proc = Process::launch("target/debug/run_endlessly", true, StdoutReplacement::None).expect("Failed to launch process");

        {
            proc.create_breakpoint_site(VirtualAddress::new(42), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint site 1");
            proc.create_breakpoint_site(VirtualAddress::new(43), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint site 2");
            proc.create_breakpoint_site(VirtualAddress::new(44), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint site 3");
            proc.create_breakpoint_site(VirtualAddress::new(45), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint site 4");
        }

        {
            let mut addr = 42;
            for site in proc.breakpoint_sites().iter() {
                assert_eq!(VirtualAddress::new(addr), site.address(), "Unexpected breakpoint address");
                addr += 1;
            }
        }
    }

    #[test]
    fn breakpoint_on_address_test() {
        let close_on_exec = false;
        let mut channel = Pipe::create(close_on_exec).expect("Failed to create pipe");
        let exec_path = "target/debug/hello_rsdb";

        let mut proc = Process::launch(exec_path, true, StdoutReplacement::Fd(channel.write_fd())).expect("Failed to launch process");
        channel.close_write();

        let offset = get_entry_point_offset(Path::new(exec_path));
        let load_address = get_load_address(proc.pid(), offset);

        let bp = proc.create_breakpoint_site(load_address, BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint");
        bp.enable().expect("Failed to enable breakpoint");
        proc.resume().expect("Failed to resume");
        let reason = proc.wait_on_signal().expect("Failed to wait");

        assert!(reason.reason.is_stopped(), "Unexpected stop reason");
        assert_eq!(reason.info, SIGTRAP, "Unexpected stop info");
        assert_eq!(proc.get_pc(), load_address, "Unexpected program counter");

        proc.resume().expect("Failed to resume");
        let reason = proc.wait_on_signal().expect("Failed to wait after resume");

        assert_eq!(reason.reason, ProcessState::Exited, "Unexpected wait reason after resume");
        assert_eq!(reason.info, 0, "Unexpected wait info after resume");

        let data = {
            let mut s = String::new();
            channel.read_to_string(&mut s).expect("Failed to read from pipe");
            s
        };
        assert_eq!("Hello, rsdb!\n", data, "Unexpected output");
    }

    #[test]
    fn can_remove_breakpoint_sites() {
        let mut proc = Process::launch("target/debug/hello_rsdb", true, StdoutReplacement::None).expect("Failed to launch process");

        let bp1 = proc.create_breakpoint_site(VirtualAddress::new(42), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint site 1");
        let bp1_id = bp1.id();
        proc.create_breakpoint_site(VirtualAddress::new(43), BreakpointType::Software, BreakpointScope::External).expect("Failed to create breakpoint site 2");
        assert_eq!(2, proc.breakpoint_sites().len(), "Unexpected number of breakpoints after create");

        proc.breakpoint_sites_mut().remove_by_id(bp1_id);
        proc.breakpoint_sites_mut().remove_by_address(VirtualAddress::new(43));
        assert!(proc.breakpoint_sites().is_empty(), "Expected breakpoints to be removed");
    }

    #[test]
    fn reading_and_writing_memory_test() -> Result<(), Error> {
        let close_on_exec = false;
        let mut channel = Pipe::create(close_on_exec)?;

        let mut proc = Process::launch("target/debug/memory", true, StdoutReplacement::Fd(channel.write_fd()))?;
        channel.close_write();

        proc.resume()?;
        proc.wait_on_signal()?;

        // debugee should have written pointer to stdout
        let mut ptr_bytes = [0u8; 8];
        channel.read_exact(&mut ptr_bytes)?;
        let ptr = usize::try_from_bytes(ptr_bytes.as_slice()).expect("Failed to read pointer");

        let bytes = proc.read_memory(VirtualAddress::new(ptr), 8)?;
        let word = u64::try_from_bytes(bytes.as_slice()).expect("Failed to read word");

        assert_eq!(0xcafecafe, word, "Unexpected value for word");

        proc.resume()?;
        proc.wait_on_signal()?;

        let message = "Hello, rsdb!";

        let str_ptr = {
            // debuggee should have written address of string to write to stdout`
            let mut ptr_bytes = [0u8; 8];
            channel.read_exact(&mut ptr_bytes)?;
            usize::try_from_bytes(ptr_bytes.as_slice()).expect("Failed to read pointer")
        };

        proc.write_memory(VirtualAddress::new(str_ptr), message.as_bytes())?;

        proc.resume()?;
        proc.wait_on_signal()?;

        // debuggee should have written the previous message to stdout
        let mut written = String::with_capacity(message.len());
        channel.read_to_string(&mut written)?;

        assert_eq!(message, written, "Unexpected message after memory write");

        Ok(())
    }
}