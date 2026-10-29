//! The adversarial escape catalog.
//!
//! Each attack runs in a forked child that applies the profile and then tries to
//! break out. We classify the result as `Blocked` (the kernel returned
//! `EACCES`/`EPERM`, or seccomp killed the thread), `Escaped` (the forbidden
//! operation succeeded), or `Inconclusive` (it failed for an unrelated reason,
//! e.g. the target did not exist). The headline metric counts, over the attacks
//! that a correct sandbox *should* block, how many were blocked.
//!
//! Honesty note: Landlock does not revoke file descriptors opened before the
//! ruleset is applied, so `fd-passing` genuinely escapes. We keep it in the
//! catalog (counted as not blocked). The `lgpa run` launcher closes inherited
//! fds before sandboxing; that mitigation is covered by an integration test,
//! not counted as an attack (it has no unsandboxed positive control).

use crate::enforce::{self, Layers};
use crate::Profile;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use std::ffi::CString;

/// Runtime context: concrete in-sandbox and out-of-sandbox paths/ports.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// A readable secret file OUTSIDE the sandbox (inside the attack workspace).
    pub outside_file: String,
    /// A path we try to create OUTSIDE the sandbox.
    pub outside_new: String,
    /// A directory OUTSIDE the sandbox.
    pub outside_dir: String,
    /// A read-only file INSIDE the sandbox.
    pub ro_file: String,
    /// A writable directory INSIDE the sandbox.
    pub rw_dir: String,
    /// A TCP port NOT allowed by the profile, with a listener behind it.
    pub denied_port: u16,
    /// A free TCP port NOT allowed by the profile (for bind).
    pub denied_bind_port: u16,
    /// Abstract unix socket name the harness pre-created outside the domain.
    pub abstract_name: String,
}

/// Outcome of a single attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Blocked,
    Escaped,
    Inconclusive,
    /// The sandbox itself could not be applied: a hard failure, never a block.
    HarnessError,
}

const EXIT_ESCAPED: i32 = 10;
const EXIT_BLOCKED: i32 = 11;
const EXIT_INCONCLUSIVE: i32 = 12;
const EXIT_ENFORCE_FAIL: i32 = 20;

/// One catalogued escape.
pub struct Attack {
    pub id: &'static str,
    pub category: &'static str,
    pub desc: &'static str,
    /// True if a correct sandbox should block this (it is a real escape attempt).
    /// False marks a *negative control* that must stay allowed.
    pub expect_block: bool,
    /// Runs BEFORE the sandbox. Returns a value handed to `post` (e.g. an fd).
    pub pre: fn(&Ctx) -> i64,
    /// Runs AFTER the sandbox; returns the raw outcome.
    pub post: fn(&Ctx, i64) -> Outcome,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Classify a syscall return: <0 means error (errno set).
fn classify(ret: i64) -> Outcome {
    if ret >= 0 {
        return Outcome::Escaped;
    }
    match errno() {
        libc::EACCES | libc::EPERM | SECCOMP_ERRNO => Outcome::Blocked,
        _ => Outcome::Inconclusive,
    }
}

/// errno returned by the seccomp allowlist for non-allowlisted syscalls.
pub const SECCOMP_ERRNO: i32 = libc::ENOSYS;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap())
}

fn no_pre(_: &Ctx) -> i64 {
    -1
}

// ---- attack implementations -------------------------------------------------

fn open_ro(path: &str) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            cs(path).as_ptr(),
            libc::O_RDONLY,
        )
    }
}
fn open_create(path: &str) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            cs(path).as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    }
}

fn a_read_outside(c: &Ctx, _: i64) -> Outcome {
    classify(open_ro(&c.outside_file))
}
fn a_write_outside(c: &Ctx, _: i64) -> Outcome {
    classify(open_create(&c.outside_new))
}
fn a_write_ro_region(c: &Ctx, _: i64) -> Outcome {
    // Only read was granted on ro_file -> opening it for write must fail.
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            cs(&c.ro_file).as_ptr(),
            libc::O_WRONLY | libc::O_TRUNC,
        )
    };
    classify(r)
}
fn a_create_in_ro(c: &Ctx, _: i64) -> Outcome {
    let p = format!("{}.evil", c.ro_file);
    classify(open_create(&p))
}
fn a_unlink_ro(c: &Ctx, _: i64) -> Outcome {
    let r = unsafe {
        libc::syscall(
            libc::SYS_unlinkat,
            libc::AT_FDCWD,
            cs(&c.ro_file).as_ptr(),
            0,
        )
    };
    classify(r)
}
fn a_truncate_ro(c: &Ctx, _: i64) -> Outcome {
    let r = unsafe { libc::syscall(libc::SYS_truncate, cs(&c.ro_file).as_ptr(), 0i64) };
    classify(r)
}
fn a_dotdot_traversal(c: &Ctx, _: i64) -> Outcome {
    // rw_dir = <ws>/app/out, outside_file = <ws>/secret/canary.txt
    let p = format!("{}/../../secret/canary.txt", c.rw_dir);
    classify(open_ro(&p))
}
fn a_proc_self_root(c: &Ctx, _: i64) -> Outcome {
    classify(open_ro(&format!("/proc/self/root{}", c.outside_file)))
}
fn a_proc_self_mem(_: &Ctx, _: i64) -> Outcome {
    classify(open_ro("/proc/self/mem"))
}
fn a_proc_fd_reopen(c: &Ctx, pre: i64) -> Outcome {
    if pre < 0 {
        return Outcome::Inconclusive;
    }
    // Reopen the writable-dir fd via /proc/self/fd and climb out with '..'.
    let _ = c;
    let p = format!("/proc/self/fd/{pre}/../../secret/canary.txt");
    classify(open_ro(&p))
}
fn pre_open_rwdir(c: &Ctx) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            cs(&c.rw_dir).as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
    }
}

// symlink: plant a symlink (pre, allowed) inside rw_dir pointing outside, then
// follow it after the sandbox is up. Landlock must resolve the target.
fn pre_plant_symlink(c: &Ctx) -> i64 {
    let link = format!("{}/lgpa-symlink", c.rw_dir);
    unsafe {
        libc::unlink(cs(&link).as_ptr());
        libc::symlink(cs(&c.outside_file).as_ptr(), cs(&link).as_ptr()) as i64
    }
}
fn a_follow_symlink(c: &Ctx, _: i64) -> Outcome {
    let link = format!("{}/lgpa-symlink", c.rw_dir);
    classify(open_ro(&link))
}
fn a_create_symlink(c: &Ctx, _: i64) -> Outcome {
    // Creating a symlink needs MakeSym, which the profile does not grant.
    let link = format!("{}/lgpa-symlink2", c.rw_dir);
    let r = unsafe {
        libc::syscall(
            libc::SYS_symlinkat,
            cs(&c.outside_file).as_ptr(),
            libc::AT_FDCWD,
            cs(&link).as_ptr(),
        )
    };
    classify(r)
}
/// Like [`classify`] but also credits `EXDEV`, which Landlock returns when a
/// link/rename would move a file across rule hierarchies (REFER denied).
fn classify_refer(ret: i64) -> Outcome {
    if ret < 0 && errno() == libc::EXDEV {
        Outcome::Blocked
    } else {
        classify(ret)
    }
}
fn a_hardlink_escape(c: &Ctx, _: i64) -> Outcome {
    let link = format!("{}/lgpa-hardlink", c.rw_dir);
    let r = unsafe {
        libc::syscall(
            libc::SYS_linkat,
            libc::AT_FDCWD,
            cs(&c.outside_file).as_ptr(),
            libc::AT_FDCWD,
            cs(&link).as_ptr(),
            0,
        )
    };
    classify_refer(r)
}
// environmental: a colluder outside the sandbox plants a hardlink to the secret
// inside the writable dir *before* the sandbox starts. Landlock rules are
// path/inode-hierarchy based, so the planted name is reachable.
fn pre_plant_hardlink(c: &Ctx) -> i64 {
    let link = format!("{}/lgpa-planted-hl", c.rw_dir);
    unsafe {
        libc::unlink(cs(&link).as_ptr());
        libc::link(cs(&c.outside_file).as_ptr(), cs(&link).as_ptr()) as i64
    }
}
fn a_planted_hardlink(c: &Ctx, pre: i64) -> Outcome {
    if pre < 0 {
        return Outcome::Inconclusive;
    }
    let link = format!("{}/lgpa-planted-hl", c.rw_dir);
    classify(open_ro(&link))
}
fn a_rename_out(c: &Ctx, _: i64) -> Outcome {
    let dst = format!("{}/lgpa-moved", c.outside_dir);
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat,
            libc::AT_FDCWD,
            cs(&c.ro_file).as_ptr(),
            libc::AT_FDCWD,
            cs(&dst).as_ptr(),
        )
    };
    classify_refer(r)
}
fn a_mkdir_outside(c: &Ctx, _: i64) -> Outcome {
    let p = format!("{}/lgpa-newdir", c.outside_dir);
    let r = unsafe { libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, cs(&p).as_ptr(), 0o700) };
    classify(r)
}
fn a_mknod_outside(c: &Ctx, _: i64) -> Outcome {
    let p = format!("{}/lgpa-fifo", c.outside_dir);
    let r = unsafe {
        libc::syscall(
            libc::SYS_mknodat,
            libc::AT_FDCWD,
            cs(&p).as_ptr(),
            libc::S_IFIFO | 0o600,
            0u64,
        )
    };
    classify(r)
}

fn a_exec_outside(_: &Ctx, _: i64) -> Outcome {
    // Exec a binary the workload never ran. If it runs, `sh` exits with
    // EXIT_ESCAPED, which the parent reads as an escape.
    let sh = cs("/bin/sh");
    let a0 = cs("sh");
    let a1 = cs("-c");
    let a2 = cs("exit 10");
    let argv = [a0.as_ptr(), a1.as_ptr(), a2.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let r = unsafe { libc::syscall(libc::SYS_execve, sh.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    classify(r)
}

// network ---------------------------------------------------------------------
fn tcp_socket() -> i64 {
    unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) }
}
fn sockaddr_in(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    }
}
fn a_connect_denied(c: &Ctx, _: i64) -> Outcome {
    let fd = tcp_socket();
    if fd < 0 {
        return Outcome::Inconclusive;
    }
    let sa = sockaddr_in(c.denied_port);
    let r = unsafe {
        libc::syscall(
            libc::SYS_connect,
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    unsafe { libc::syscall(libc::SYS_close, fd) };
    classify(r)
}
fn a_bind_denied(c: &Ctx, _: i64) -> Outcome {
    let fd = tcp_socket();
    if fd < 0 {
        return Outcome::Inconclusive;
    }
    let sa = sockaddr_in(c.denied_bind_port);
    let r = unsafe {
        libc::syscall(
            libc::SYS_bind,
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    unsafe { libc::syscall(libc::SYS_close, fd) };
    classify(r)
}

// scopes ----------------------------------------------------------------------
fn a_signal_outside(_: &Ctx, _: i64) -> Outcome {
    // Our parent (the harness) is outside the Landlock domain. With
    // Scope::Signal, signaling it must fail with EPERM.
    let ppid = unsafe { libc::getppid() };
    let r = unsafe { libc::syscall(libc::SYS_kill, ppid, 0) };
    classify(r)
}
fn a_abstract_uds(c: &Ctx, _: i64) -> Outcome {
    // The harness pre-created a listening abstract UDS outside the domain.
    // Scope::AbstractUnixSocket must block connecting to it.
    let fd = unsafe { libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Outcome::Inconclusive;
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    let name = c.abstract_name.as_bytes();
    // abstract namespace: leading NUL.
    for (i, b) in name.iter().enumerate() {
        addr.sun_path[1 + i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as u32;
    let r = unsafe {
        libc::syscall(
            libc::SYS_connect,
            fd,
            &addr as *const _ as *const libc::sockaddr,
            len,
        )
    };
    unsafe { libc::syscall(libc::SYS_close, fd) };
    if r >= 0 {
        return Outcome::Escaped;
    }
    match errno() {
        libc::EACCES | libc::EPERM | SECCOMP_ERRNO => Outcome::Blocked,
        // ECONNREFUSED would mean the scope let the connect through to a dead
        // server; treat as escaped (scope did not isolate).
        libc::ECONNREFUSED => Outcome::Escaped,
        _ => Outcome::Inconclusive,
    }
}

// seccomp allowlist -----------------------------------------------------------
fn seccomp_probe(nr: i64, a0: i64) -> Outcome {
    // "Escaped" here means the syscall *reached the kernel* (attack surface
    // exposed), whatever the kernel then answered. Only the allowlist's own
    // errno counts as blocked, so a kernel-side EPERM (e.g. mount without
    // CAP_SYS_ADMIN) is not credited to the sandbox.
    let r = unsafe { libc::syscall(nr, a0, 0, 0, 0, 0, 0) };
    if r < 0 && errno() == SECCOMP_ERRNO {
        Outcome::Blocked
    } else {
        Outcome::Escaped
    }
}
fn a_sec_ptrace(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_ptrace, libc::PTRACE_TRACEME as i64)
}
fn a_sec_unshare(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_unshare, libc::CLONE_NEWUSER as i64)
}
fn a_sec_mount(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_mount, 0)
}
fn a_sec_bpf(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_bpf, 0)
}
fn a_sec_keyctl(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_keyctl, 0)
}
fn a_sec_userfaultfd(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_userfaultfd, 0)
}
fn a_sec_setns(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_setns, -1)
}
fn a_sec_pidfd_getfd(_: &Ctx, _: i64) -> Outcome {
    seccomp_probe(libc::SYS_pidfd_getfd, -1)
}

// fd passing ------------------------------------------------------------------
fn pre_open_outside(c: &Ctx) -> i64 {
    open_ro(&c.outside_file)
}
fn a_fd_passing(_: &Ctx, pre: i64) -> Outcome {
    if pre < 0 {
        return Outcome::Inconclusive;
    }
    let mut buf = [0u8; 16];
    let r = unsafe { libc::syscall(libc::SYS_read, pre, buf.as_mut_ptr(), buf.len()) };
    // Landlock does NOT revoke already-open fds: this read succeeds.
    if r >= 0 {
        Outcome::Escaped
    } else {
        classify(r)
    }
}

// negative controls -----------------------------------------------------------
fn a_ctrl_read_allowed(c: &Ctx, _: i64) -> Outcome {
    let fd = open_ro(&c.ro_file);
    if fd >= 0 {
        unsafe { libc::syscall(libc::SYS_close, fd) };
        Outcome::Escaped // "allowed" — expected for a control
    } else {
        Outcome::Blocked
    }
}
fn a_ctrl_write_allowed(c: &Ctx, _: i64) -> Outcome {
    let p = format!("{}/lgpa-allowed.txt", c.rw_dir);
    let fd = open_create(&p);
    if fd >= 0 {
        unsafe { libc::syscall(libc::SYS_close, fd) };
        Outcome::Escaped
    } else {
        Outcome::Blocked
    }
}

/// The full catalog.
pub fn catalog() -> Vec<Attack> {
    vec![
        Attack {
            id: "read-outside",
            category: "fs-confinement",
            desc: "read a world-readable file outside the sandbox",
            expect_block: true,
            pre: no_pre,
            post: a_read_outside,
        },
        Attack {
            id: "write-outside",
            category: "fs-confinement",
            desc: "create a file outside the sandbox",
            expect_block: true,
            pre: no_pre,
            post: a_write_outside,
        },
        Attack {
            id: "write-ro-region",
            category: "fs-underprivilege",
            desc: "open a read-only file for writing",
            expect_block: true,
            pre: no_pre,
            post: a_write_ro_region,
        },
        Attack {
            id: "create-in-ro",
            category: "fs-underprivilege",
            desc: "create a file in a read-only directory",
            expect_block: true,
            pre: no_pre,
            post: a_create_in_ro,
        },
        Attack {
            id: "unlink-ro",
            category: "fs-underprivilege",
            desc: "unlink a file in a read-only directory",
            expect_block: true,
            pre: no_pre,
            post: a_unlink_ro,
        },
        Attack {
            id: "truncate-ro",
            category: "fs-underprivilege",
            desc: "truncate a read-only file",
            expect_block: true,
            pre: no_pre,
            post: a_truncate_ro,
        },
        Attack {
            id: "dotdot-traversal",
            category: "fs-traversal",
            desc: "escape via ../ path traversal from the writable dir",
            expect_block: true,
            pre: no_pre,
            post: a_dotdot_traversal,
        },
        Attack {
            id: "proc-self-root",
            category: "proc-tricks",
            desc: "escape via /proc/self/root magic symlink",
            expect_block: true,
            pre: no_pre,
            post: a_proc_self_root,
        },
        Attack {
            id: "proc-self-mem",
            category: "proc-tricks",
            desc: "open /proc/self/mem (outside sandbox)",
            expect_block: true,
            pre: no_pre,
            post: a_proc_self_mem,
        },
        Attack {
            id: "proc-fd-reopen",
            category: "proc-tricks",
            desc: "reopen a dir fd via /proc/self/fd and climb out with ..",
            expect_block: true,
            pre: pre_open_rwdir,
            post: a_proc_fd_reopen,
        },
        Attack {
            id: "follow-symlink",
            category: "symlink",
            desc: "follow a planted symlink that points outside",
            expect_block: true,
            pre: pre_plant_symlink,
            post: a_follow_symlink,
        },
        Attack {
            id: "create-symlink",
            category: "symlink",
            desc: "create a symlink pointing outside (needs MakeSym)",
            expect_block: true,
            pre: no_pre,
            post: a_create_symlink,
        },
        Attack {
            id: "hardlink-escape",
            category: "hardlink",
            desc: "hardlink an outside file into the writable dir",
            expect_block: true,
            pre: no_pre,
            post: a_hardlink_escape,
        },
        Attack {
            id: "planted-hardlink",
            category: "environmental",
            desc: "read a hardlink to the secret planted in the writable dir before sandboxing",
            expect_block: true,
            pre: pre_plant_hardlink,
            post: a_planted_hardlink,
        },
        Attack {
            id: "rename-out",
            category: "rename",
            desc: "rename an in-sandbox file to outside",
            expect_block: true,
            pre: no_pre,
            post: a_rename_out,
        },
        Attack {
            id: "mkdir-outside",
            category: "fs-create",
            desc: "mkdir outside the sandbox",
            expect_block: true,
            pre: no_pre,
            post: a_mkdir_outside,
        },
        Attack {
            id: "mknod-outside",
            category: "fs-create",
            desc: "mknod a FIFO outside the sandbox",
            expect_block: true,
            pre: no_pre,
            post: a_mknod_outside,
        },
        Attack {
            id: "exec-outside",
            category: "exec",
            desc: "execve a binary the workload never executed (/bin/sh)",
            expect_block: true,
            pre: no_pre,
            post: a_exec_outside,
        },
        Attack {
            id: "connect-denied-port",
            category: "network",
            desc: "TCP connect to a port not in the profile",
            expect_block: true,
            pre: no_pre,
            post: a_connect_denied,
        },
        Attack {
            id: "bind-denied-port",
            category: "network",
            desc: "TCP bind to a port not in the profile",
            expect_block: true,
            pre: no_pre,
            post: a_bind_denied,
        },
        Attack {
            id: "signal-outside",
            category: "scope",
            desc: "signal a process outside the Landlock domain",
            expect_block: true,
            pre: no_pre,
            post: a_signal_outside,
        },
        Attack {
            id: "abstract-uds",
            category: "scope",
            desc: "connect to an abstract unix socket outside the domain",
            expect_block: true,
            pre: no_pre,
            post: a_abstract_uds,
        },
        Attack {
            id: "seccomp-ptrace",
            category: "seccomp",
            desc: "call ptrace (not in allowlist)",
            expect_block: true,
            pre: no_pre,
            post: a_sec_ptrace,
        },
        Attack {
            id: "seccomp-unshare",
            category: "seccomp",
            desc: "call unshare(CLONE_NEWUSER)",
            expect_block: true,
            pre: no_pre,
            post: a_sec_unshare,
        },
        Attack {
            id: "seccomp-mount",
            category: "seccomp",
            desc: "call mount",
            expect_block: true,
            pre: no_pre,
            post: a_sec_mount,
        },
        Attack {
            id: "seccomp-bpf",
            category: "seccomp",
            desc: "call bpf",
            expect_block: true,
            pre: no_pre,
            post: a_sec_bpf,
        },
        Attack {
            id: "seccomp-keyctl",
            category: "seccomp",
            desc: "call keyctl",
            expect_block: true,
            pre: no_pre,
            post: a_sec_keyctl,
        },
        Attack {
            id: "seccomp-userfaultfd",
            category: "seccomp",
            desc: "call userfaultfd",
            expect_block: true,
            pre: no_pre,
            post: a_sec_userfaultfd,
        },
        Attack {
            id: "seccomp-setns",
            category: "seccomp",
            desc: "call setns",
            expect_block: true,
            pre: no_pre,
            post: a_sec_setns,
        },
        Attack {
            id: "seccomp-pidfd-getfd",
            category: "seccomp",
            desc: "call pidfd_getfd (CVE-2026-46333 class)",
            expect_block: true,
            pre: no_pre,
            post: a_sec_pidfd_getfd,
        },
        Attack {
            id: "fd-passing",
            category: "fd-passing",
            desc: "use an fd opened before the sandbox (Landlock limitation)",
            expect_block: true,
            pre: pre_open_outside,
            post: a_fd_passing,
        },
        Attack {
            id: "ctrl-read-allowed",
            category: "control",
            desc: "NEGATIVE CONTROL: read an allowed in-sandbox file",
            expect_block: false,
            pre: no_pre,
            post: a_ctrl_read_allowed,
        },
        Attack {
            id: "ctrl-write-allowed",
            category: "control",
            desc: "NEGATIVE CONTROL: write in the allowed writable dir",
            expect_block: false,
            pre: no_pre,
            post: a_ctrl_write_allowed,
        },
    ]
}

/// Run one attack under `layers` of `profile` in a forked child.
pub fn run_one(profile: &Profile, layers: Layers, ctx: &Ctx, attack: &Attack) -> Outcome {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let pre_val = (attack.pre)(ctx);
            if enforce::apply(profile, layers, &[]).is_err() {
                unsafe { libc::_exit(EXIT_ENFORCE_FAIL) };
            }
            let out = (attack.post)(ctx, pre_val);
            let code = match out {
                Outcome::Escaped => EXIT_ESCAPED,
                Outcome::Blocked => EXIT_BLOCKED,
                Outcome::Inconclusive | Outcome::HarnessError => EXIT_INCONCLUSIVE,
            };
            unsafe { libc::_exit(code) };
        }
        Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, EXIT_ESCAPED)) => Outcome::Escaped,
            Ok(WaitStatus::Exited(_, EXIT_BLOCKED)) => Outcome::Blocked,
            Ok(WaitStatus::Exited(_, EXIT_ENFORCE_FAIL)) => Outcome::HarnessError,
            Ok(WaitStatus::Exited(_, _)) => Outcome::Inconclusive,
            // Seccomp set to KillThread/KillProcess would surface here as SIGSYS.
            Ok(WaitStatus::Signaled(_, nix::sys::signal::Signal::SIGSYS, _)) => Outcome::Blocked,
            _ => Outcome::Inconclusive,
        },
        Err(_) => Outcome::Inconclusive,
    }
}
