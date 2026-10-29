//! A tiny `strace`-equivalent built on `ptrace(2)`.
//!
//! We avoid depending on the `strace` binary (it is not always installable and
//! parsing its text output is brittle). Instead we drive the tracee with
//! `PTRACE_SYSCALL`, read the argument registers at each syscall-entry stop, and
//! pull path strings out of `/proc/<pid>/mem`. Only the handful of syscalls that
//! matter for a Landlock+seccomp profile are decoded; every syscall *number* is
//! recorded for the seccomp allowlist.

use crate::{FsAccess, Mode, Trace};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::unix::fs::FileExt;

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

/// Trace `cmd` under ptrace and return the observations.
pub fn trace_command(cmd: &[String]) -> std::io::Result<Trace> {
    if cmd.is_empty() {
        return Err(std::io::Error::other("empty command"));
    }
    match unsafe { fork() }.map_err(std::io::Error::other)? {
        ForkResult::Child => {
            ptrace::traceme().ok();
            let c = CString::new(cmd[0].as_str()).unwrap();
            let args: Vec<CString> = cmd
                .iter()
                .map(|a| CString::new(a.as_str()).unwrap())
                .collect();
            let _ = execvp(&c, &args);
            // execvp only returns on error.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            let mut t = parent_loop(child, cmd)?;
            // The initial execve happens before the first syscall-stop we see
            // (PTRACE_TRACEME semantics), so record the resolved target here.
            if let Some(p) = resolve_exe(&cmd[0]) {
                t.fs.insert(
                    0,
                    FsAccess {
                        path: p,
                        mode: Mode::Exec,
                    },
                );
            }
            // The kernel opens the ELF interpreter (PT_INTERP) or the `#!`
            // interpreter inside execve without a syscall we can see; Landlock
            // still checks Execute on it, so derive it from each exec target.
            let execs: Vec<String> =
                t.fs.iter()
                    .filter(|a| a.mode == Mode::Exec)
                    .map(|a| a.path.clone())
                    .collect();
            for e in execs {
                if let Some(i) = exec_interpreter(&e) {
                    t.fs.push(FsAccess {
                        path: i,
                        mode: Mode::Exec,
                    });
                }
            }
            dedup(&mut t.fs);
            Ok(t)
        }
    }
}

fn parent_loop(child: Pid, cmd: &[String]) -> std::io::Result<Trace> {
    waitpid(child, None).map_err(std::io::Error::other)?;
    ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD)
        .map_err(std::io::Error::other)?;

    let mem = std::fs::File::open(format!("/proc/{child}/mem")).ok();
    let mut fs: Vec<FsAccess> = Vec::new();
    let mut syscalls: BTreeSet<i64> = BTreeSet::new();
    let mut bind_ports: BTreeSet<u16> = BTreeSet::new();
    let mut connect_ports: BTreeSet<u16> = BTreeSet::new();
    let mut at_entry = true;
    let mut exit_code = None;

    loop {
        if ptrace::syscall(child, None).is_err() {
            break;
        }
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                exit_code = Some(code);
                break;
            }
            Ok(WaitStatus::Signaled(_, _, _)) => break,
            Ok(WaitStatus::PtraceSyscall(_)) => {
                if at_entry {
                    if let Ok(regs) = ptrace::getregs(child) {
                        syscalls.insert(regs.orig_rax as i64);
                        decode(
                            &regs,
                            mem.as_ref(),
                            &mut fs,
                            &mut bind_ports,
                            &mut connect_ports,
                        );
                    }
                }
                at_entry = !at_entry;
            }
            Ok(_) => {}
            Err(_) => break,
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

#[allow(clippy::too_many_arguments)]
fn decode(
    regs: &libc::user_regs_struct,
    mem: Option<&std::fs::File>,
    fs: &mut Vec<FsAccess>,
    bind_ports: &mut BTreeSet<u16>,
    connect_ports: &mut BTreeSet<u16>,
) {
    let Some(mem) = mem else { return };
    match regs.orig_rax {
        SYS_OPEN => {
            if let Some(p) = read_cstr(mem, regs.rdi) {
                let mode = if regs.rsi & WRITE_BITS != 0 {
                    Mode::Write
                } else {
                    Mode::Read
                };
                push(fs, p, mode);
            }
        }
        SYS_OPENAT => {
            if let Some(p) = read_cstr(mem, regs.rsi) {
                let mode = if regs.rdx & WRITE_BITS != 0 {
                    Mode::Write
                } else {
                    Mode::Read
                };
                push(fs, p, mode);
            }
        }
        SYS_OPENAT2 => {
            // struct open_how { __u64 flags; __u64 mode; __u64 resolve; }
            if let Some(p) = read_cstr(mem, regs.rsi) {
                let flags = read_u64(mem, regs.rdx).unwrap_or(0);
                let mode = if flags & WRITE_BITS != 0 {
                    Mode::Write
                } else {
                    Mode::Read
                };
                push(fs, p, mode);
            }
        }
        SYS_EXECVE => {
            if let Some(p) = read_cstr(mem, regs.rdi) {
                push(fs, p, Mode::Exec);
            }
        }
        SYS_EXECVEAT => {
            if let Some(p) = read_cstr(mem, regs.rsi) {
                push(fs, p, Mode::Exec);
            }
        }
        SYS_BIND => {
            if let Some(port) = read_port(mem, regs.rsi, regs.rdx) {
                bind_ports.insert(port);
            }
        }
        SYS_CONNECT => {
            if let Some(port) = read_port(mem, regs.rsi, regs.rdx) {
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

fn read_cstr(mem: &std::fs::File, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    let mut off = addr;
    loop {
        let n = mem.read_at(&mut buf, off).ok()?;
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            if b == 0 {
                return String::from_utf8(out).ok();
            }
            out.push(b);
            if out.len() > 4096 {
                return String::from_utf8(out).ok();
            }
        }
        off += n as u64;
    }
    String::from_utf8(out).ok()
}

fn read_u64(mem: &std::fs::File, addr: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    mem.read_at(&mut buf, addr).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// Parse the port out of a `sockaddr_in`/`sockaddr_in6` (both carry the port in
/// bytes 2..4, network byte order). Returns None for AF_UNIX etc.
fn read_port(mem: &std::fs::File, addr: u64, len: u64) -> Option<u16> {
    if addr == 0 || len < 4 {
        return None;
    }
    let mut buf = [0u8; 4];
    mem.read_at(&mut buf, addr).ok()?;
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
        // Test binaries are dynamically linked on glibc runners.
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
}
