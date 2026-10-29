//! Apply a [`Profile`]: Landlock ABI 6 (fs + TCP + scopes) and a seccomp
//! allowlist (default action `ENOSYS`).
//!
//! Enforcement fails loudly: if the kernel does not fully enforce the Landlock
//! ruleset we return an error instead of silently running unconfined.

use crate::Profile;
use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use std::collections::BTreeMap;

/// Which layers to apply. `Both` is the real profile; the others exist so the
/// attack report can attribute each block to a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layers {
    None,
    LandlockOnly,
    SeccompOnly,
    Both,
}

impl Layers {
    pub fn landlock(self) -> bool {
        matches!(self, Layers::LandlockOnly | Layers::Both)
    }
    pub fn seccomp(self) -> bool {
        matches!(self, Layers::SeccompOnly | Layers::Both)
    }
    pub fn name(self) -> &'static str {
        match self {
            Layers::None => "none",
            Layers::LandlockOnly => "landlock",
            Layers::SeccompOnly => "seccomp",
            Layers::Both => "both",
        }
    }
}

const ABI_USED: ABI = ABI::V6;

fn rights_ro() -> landlock::BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::ReadDir
}
fn rights_rx() -> landlock::BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute
}
fn rights_rw() -> landlock::BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::RemoveFile
        | AccessFs::Truncate
}

/// Apply Landlock for `profile`. Errors if the ruleset is not fully enforced.
pub fn apply_landlock(profile: &Profile) -> Result<(), String> {
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI_USED))
        .map_err(|e| e.to_string())?
        .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
        .map_err(|e| e.to_string())?;
    let mut scope = landlock::BitFlags::<Scope>::empty();
    if profile.scope_abstract_unix {
        scope |= Scope::AbstractUnixSocket;
    }
    if profile.scope_signal {
        scope |= Scope::Signal;
    }
    if !scope.is_empty() {
        ruleset = ruleset.scope(scope).map_err(|e| e.to_string())?;
    }
    let mut created = ruleset.create().map_err(|e| e.to_string())?;

    let groups: [(&Vec<String>, landlock::BitFlags<AccessFs>); 3] = [
        (&profile.ro, rights_ro()),
        (&profile.rx, rights_rx()),
        (&profile.rw, rights_rw()),
    ];
    for (paths, rights) in groups {
        for p in paths {
            // A learned path may have been removed since training (e.g. a temp
            // file). Skipping it can only *narrow* the sandbox, never widen it.
            let Ok(fd) = PathFd::new(p) else { continue };
            // Directory-only rights on a regular file are rejected by the
            // kernel; restrict to the file-compatible subset in that case.
            let is_dir = std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false);
            let r = if is_dir {
                rights
            } else {
                rights & AccessFs::from_file(ABI_USED)
            };
            created = created
                .add_rule(PathBeneath::new(fd, r))
                .map_err(|e| format!("add_rule {p}: {e}"))?;
        }
    }
    for port in &profile.bind_ports {
        created = created
            .add_rule(NetPort::new(*port, AccessNet::BindTcp))
            .map_err(|e| e.to_string())?;
    }
    for port in &profile.connect_ports {
        created = created
            .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
            .map_err(|e| e.to_string())?;
    }
    let status = created.restrict_self().map_err(|e| e.to_string())?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!(
            "Landlock not fully enforced ({:?}); refusing to run unconfined",
            status.ruleset
        ));
    }
    Ok(())
}

/// Compile the seccomp allowlist (unknown syscalls -> ENOSYS).
pub fn compile_seccomp(profile: &Profile, extra: &[i64]) -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for n in profile.syscalls.iter().chain(extra.iter()) {
        rules.insert(*n, vec![]);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(crate::attack::SECCOMP_ERRNO as u32),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| e.to_string())?;
    BpfProgram::try_from(filter).map_err(|e| e.to_string())
}

/// Install a compiled seccomp program on the current thread.
pub fn install_seccomp(prog: &BpfProgram) -> Result<(), String> {
    seccompiler::apply_filter(prog).map_err(|e| e.to_string())
}

/// Close every fd >= 3 so nothing opened before the sandbox leaks into it.
pub fn close_inherited_fds() {
    unsafe {
        libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
    }
}

/// Apply `layers` of `profile` to the current process. `seccomp_extra` lets the
/// launcher keep `execve` reachable for the final exec.
pub fn apply(profile: &Profile, layers: Layers, seccomp_extra: &[i64]) -> Result<(), String> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("PR_SET_NO_NEW_PRIVS failed".into());
        }
    }
    let prog = if layers.seccomp() {
        Some(compile_seccomp(profile, seccomp_extra)?)
    } else {
        None
    };
    if layers.landlock() {
        apply_landlock(profile)?;
    }
    if let Some(p) = prog {
        install_seccomp(&p)?;
    }
    Ok(())
}

/// Probe the running kernel's Landlock ABI. Returns an error string when
/// Landlock is unavailable so callers can fail visibly.
pub fn landlock_abi() -> Result<i32, String> {
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    if v < 0 {
        Err(format!(
            "Landlock unavailable: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(v as i32)
    }
}
