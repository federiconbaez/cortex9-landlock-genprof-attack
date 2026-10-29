//! A tiny `strace`-equivalent built on `ptrace(2)`.
//!
//! We avoid depending on the `strace` binary (it is not always installable and
//! parsing its text output is brittle). Instead we drive the tracee with
//! `PTRACE_SYSCALL`, read the argument registers at each syscall-entry stop, and
//! pull path strings out of the tracee's address space via `process_vm_readv(2)`
//! (more reliable than `/proc/<pid>/mem` under some LSM configs). Only the
//! handful of syscalls that matter for a Landlock+seccomp profile are decoded;
//! every syscall *number* is recorded for the seccomp allowlist.
//!
//! Fork/vfork/clone are followed via `PTRACE_O_TRACE{FORK,VFORK,CLONE}`, so
//! multithreaded and multiprocess workloads (e.g. `python3 -m http.server`)
//! are captured. Each new child is auto-traced; we record its syscalls into
//! the same Trace.

use crate::{FsAccess, Mode, Trace};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::CString;

const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const WRITE_BITS: u64 = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC;

const SYS_OPEN: u64 = 2;
const SYS_OPENAT: u64 = 257;
const SYS_OPENAT2: u64 = 437;
const SYS_EXECVE: u64 = 59;
const SYS_EXECVEAT: u64 = 322;
const SYS_CONNECT: u64 = 42;
const SYS_BIND: u64 = 49;

/// Optional driver run (on another thread) after the tracee starts, e.g. to
/// hit a server and then stop it. It receives the tracee's pid.
pub type Driver = Box<dyn FnOnce(Pid) + Send>;

/// Trace `cmd` under ptrace and return the observations. Follows fork/clone so
/// multithreaded and multiprocess workloads are captured.
pub fn trace_command(cmd: &[String]) -> std::io::Result<Trace> {
    trace_command_driven(cmd, None)
}

/// Like [`trace_command`] but runs `driver` on a side thread once tracing is
/// under way (used for server workloads that must be poked and then killed).
pub fn trace_command_driven(cmd: &[String], driver: Option<Driver>) -> std::io::Result<Trace> {
    if cmd.is_empty() {
        return Err(std::io::Error::other("empty command"));
    }
    match unsafe { fork() }.map_err(std::io::Error::other)? {
        ForkResult::Child => {
            ptrace::traceme().ok();
            // Stop so the parent can set options before we exec.
            unsafe {
                libc::raise(libc::SIGSTOP);
            }
            let c = CString::new(cmd[0].as_str()).unwrap();
            let args: Vec<CString> = cmd
                .iter()
                .map(|a| CString::new(a.as_str()).unwrap())
                .collect();
            let _ = execvp(&c, &args);
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            let driver_handle = driver.map(|d| std::thread::spawn(move || d(child)));
            let t = parent_loop(child, cmd);
            if let Some(h) = driver_handle {
                let _ = h.join();
            }
            t
        }
    }
}

fn parent_loop(child: Pid, cmd: &[String]) -> std::io::Result<Trace> {
    use nix::sys::ptrace::Options;

    waitpid(child, None).map_err(std::io::Error::other)?;
    let opts = Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_EXITKILL;
    ptrace::setoptions(child, opts).map_err(std::io::Error::other)?;

    let mut fs: Vec<FsAccess> = Vec::new();
    let mut syscalls: BTreeSet<i64> = BTreeSet::new();
    let mut bind_ports: BTreeSet<u16> = BTreeSet::new();
    let mut connect_ports: BTreeSet<u16> = BTreeSet::new();
    let mut exit_code = None;

    let mut at_entry: HashMap<Pid, bool> = HashMap::new();
    let mut alive: HashSet<Pid> = HashSet::new();
    at_entry.insert(child, true);
    alive.insert(child);

    let _ = ptrace::syscall(child, None);

    loop {
        let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
            Ok(s) => s,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(_) => break,
        };
        match status {
            WaitStatus::Exited(pid, code) => {
                if pid == child {
                    exit_code = Some(code);
                }
                alive.remove(&pid);
                if alive.is_empty() {
                    break;
                }
            }
            WaitStatus::Signaled(pid, _, _) => {
                alive.remove(&pid);
                if alive.is_empty() {
                    break;
                }
            }
            WaitStatus::PtraceEvent(pid, _, _) => {
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::PtraceSyscall(pid) => {
                let entry = at_entry.entry(pid).or_insert(true);
                if *entry {
                    if let Ok(regs) = ptrace::getregs(pid) {
                        syscalls.insert(regs.orig_rax as i64);
                        decode(pid, &regs, &mut fs, &mut bind_ports, &mut connect_ports);
                    }
                }
                *entry = !*entry;
                let _ = ptrace::syscall(pid, None);
            }
            WaitStatus::Stopped(pid, sig) => {
                alive.insert(pid);
                at_entry.entry(pid).or_insert(true);
                let forward = if sig == Signal::SIGSTOP || sig == Signal::SIGTRAP {
                    None
                } else {
                    Some(sig)
                };
                let _ = ptrace::syscall(pid, forward);
            }
            _ => {}
        }
    }

    if let Some(p) = resolve_exe(&cmd[0]) {
        fs.insert(
            0,
            FsAccess {
                path: p,
                mode: Mode::Exec,
            },
        );
    }
    let execs: Vec<String> = fs
        .iter()
        .filter(|a| a.mode == Mode::Exec)
        .map(|a| a.path.clone())
        .collect();
    for e in execs {
        if let Some(i) = exec_interpreter(&e) {
            fs.push(FsAccess {
                path: i,
                mode: Mode::Exec,
            });
        }
    }
    dedup(&mut fs);
    Ok(Trace {
        cmd: cmd.to_vec(),
        fs,
        syscalls,
        bind_ports,
        connect_ports,
        exit_code,
    })
}

fn decode(
    pid: Pid,
    regs: &libc::user_regs_struct,
    fs: &mut Vec<FsAccess>,
    bind_ports: &mut BTreeSet<u16>,
    connect_ports: &mut BTreeSet<u16>,
) {
    match regs.orig_rax {
        SYS_OPEN => {
            if let Some(p) = read_cstr(pid, regs.rdi) {
                let mode = if regs.rsi & WRITE_BITS != 0 {
                    Mode::Write
                } else {
                    Mode::Read
                };
                push(fs, p, mode);
            }
        }
        SYS_OPENAT => {
            if let Some(p) = read_cstr(pid, regs.rsi) {
                let mode = if regs.rdx & WRITE_BITS != 0 {
                    Mode::Write
                } else {
                    Mode::Read
                };
                push(fs, p, mode);
            }
        }
        SYS_OPENAT2 => {
            if let Some(p) = read_cstr(pid, regs.rsi) {
                let flags = read_u64(pid, regs.rdx).unwrap_or(0);
                let mode = if flags & WRITE_BITS != 0 {
                    Mode::Write
                } else {
                    Mode::Read
                };
                push(fs, p, mode);
            }
        }
        SYS_EXECVE => {
            if let Some(p) = read_cstr(pid, regs.rdi) {
                push(fs, p, Mode::Exec);
            }
        }
        SYS_EXECVEAT => {
            if let Some(p) = read_cstr(pid, regs.rsi) {
                push(fs, p, Mode::Exec);
            }
        }
        SYS_BIND => {
            if let Some(port) = read_port(pid, regs.rsi, regs.rdx) {
                bind_ports.insert(port);
            }
        }
        SYS_CONNECT => {
            if let Some(port) = read_port(pid, regs.rsi, regs.rdx) {
                connect_ports.insert(port);
            }
        }
        _ => {}
    }
}

fn push(fs: &mut Vec<FsAccess>, path: String, mode: Mode) {
    if path.is_empty() {
        return;
    }
    fs.push(FsAccess { path, mode });
}

/// Read up to `len` bytes from `pid` at `addr` via process_vm_readv.
fn vm_read(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut _,
        iov_len: len,
    };
    let n = unsafe { libc::process_vm_readv(pid.as_raw(), &local, 1, &remote, 1, 0) };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

fn read_cstr(pid: Pid, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    // Read in chunks; stop at NUL.
    let mut out = Vec::new();
    let mut off = addr;
    while out.len() < 4096 {
        let chunk = vm_read(pid, off, 256)?;
        if chunk.is_empty() {
            break;
        }
        for &b in &chunk {
            if b == 0 {
                return String::from_utf8(out).ok();
            }
            out.push(b);
        }
        off += chunk.len() as u64;
    }
    String::from_utf8(out).ok()
}

fn read_u64(pid: Pid, addr: u64) -> Option<u64> {
    let buf = vm_read(pid, addr, 8)?;
    if buf.len() < 8 {
        return None;
    }
    Some(u64::from_ne_bytes(buf[..8].try_into().ok()?))
}

fn read_port(pid: Pid, addr: u64, len: u64) -> Option<u16> {
    if addr == 0 || len < 4 {
        return None;
    }
    let buf = vm_read(pid, addr, 4)?;
    if buf.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    if family != libc::AF_INET as u16 && family != libc::AF_INET6 as u16 {
        return None;
    }
    Some(u16::from_be_bytes([buf[2], buf[3]]))
}

/// Return the interpreter the kernel loads when exec'ing `path`: the ELF
/// `PT_INTERP` string or the `#!` line's program.
pub fn exec_interpreter(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    if data.starts_with(b"#!") {
        let line = data[2..].split(|b| *b == b'\n').next()?;
        let prog = std::str::from_utf8(line).ok()?.split_whitespace().next()?;
        return Some(prog.to_string());
    }
    elf_interp(&data)
}

/// Parse PT_INTERP out of a 64-bit little-endian ELF image.
pub fn elf_interp(d: &[u8]) -> Option<String> {
    if d.len() < 64 || &d[..4] != b"\x7fELF" || d[4] != 2 || d[5] != 1 {
        return None;
    }
    let u16_at = |o: usize| -> Option<usize> {
        Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?) as usize)
    };
    let u64_at =
        |o: usize| -> Option<u64> { Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?)) };
    let phoff = u64_at(0x20)? as usize;
    let phentsize: usize = u16_at(0x36)?;
    let phnum: usize = u16_at(0x38)?;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(d.get(ph..ph + 4)?.try_into().ok()?);
        if p_type == 3 {
            let off = u64_at(ph + 8)? as usize;
            let sz = u64_at(ph + 32)? as usize;
            let raw = d.get(off..off + sz)?;
            let s = raw.split(|b| *b == 0).next()?;
            return std::str::from_utf8(s).ok().map(|s| s.to_string());
        }
    }
    None
}

/// Resolve `argv[0]` the way execvp does (PATH lookup when it has no '/').
pub fn resolve_exe(arg0: &str) -> Option<String> {
    if arg0.contains('/') {
        return std::fs::canonicalize(arg0)
            .ok()
            .map(|p| p.to_string_lossy().into());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let cand = std::path::Path::new(dir).join(arg0);
        if cand.is_file() {
            return Some(cand.to_string_lossy().into());
        }
    }
    None
}

fn dedup(fs: &mut Vec<FsAccess>) {
    let mut seen = BTreeSet::new();
    fs.retain(|a| seen.insert((a.path.clone(), a.mode as u8)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interp_of_running_binary() {
        let exe = std::env::current_exe().unwrap();
        let i = exec_interpreter(exe.to_str().unwrap());
        assert!(i.as_deref().unwrap_or("").contains("ld-linux"), "{i:?}");
    }

    #[test]
    fn interp_of_shebang() {
        let p = std::env::temp_dir().join(format!("lgpa-shebang-{}", std::process::id()));
        std::fs::write(&p, "#!/usr/bin/python3 -u\nprint(1)\n").unwrap();
        assert_eq!(
            exec_interpreter(p.to_str().unwrap()).as_deref(),
            Some("/usr/bin/python3")
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn non_elf_has_no_interp() {
        assert_eq!(elf_interp(b"not an elf"), None);
    }

    #[test]
    fn follows_fork_and_captures_child_syscalls() {
        let dir = std::env::temp_dir().join(format!("lgpa-fork-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("from-child.txt");
        std::fs::write(&marker, b"x").unwrap();
        let cmd = vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("cat {} > /dev/null", marker.display()),
        ];
        let t = trace_command(&cmd).unwrap();
        assert!(
            t.fs.iter().any(|a| a.path.contains("from-child")),
            "child open not recorded: {:?}",
            t.fs
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
