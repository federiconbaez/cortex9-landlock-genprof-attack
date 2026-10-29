//! landlock-genprof-attack: learn a Landlock(+seccomp allowlist) profile from a
//! workload trace, then prove the profile with an adversarial escape suite.
//!
//! The novel part is **not** the learner (prior art exists: lightbox,
//! landlock-genprof, sandlock). The novel part is the paired *attack suite*:
//! given a learned profile, run a catalog of known escapes and report which the
//! profile blocks. The headline metric is **escapes blocked / total**.

pub mod attack;
pub mod enforce;
pub mod syscalls;
pub mod trace;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// How a path was touched by the workload, used to classify Landlock rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Read-only open.
    Read,
    /// Opened for write / create.
    Write,
    /// Executed (execve target or mmap PROT_EXEC region's backing file).
    Exec,
}

/// A single observed filesystem access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsAccess {
    pub path: String,
    pub mode: Mode,
}

/// The raw observations captured by the tracer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Trace {
    /// Command line that was traced.
    pub cmd: Vec<String>,
    /// Filesystem accesses (deduplicated).
    pub fs: Vec<FsAccess>,
    /// Syscall numbers (x86_64) the workload issued.
    pub syscalls: BTreeSet<i64>,
    /// TCP ports the workload called bind(2) on.
    pub bind_ports: BTreeSet<u16>,
    /// TCP ports the workload called connect(2) on.
    pub connect_ports: BTreeSet<u16>,
    /// Exit status of the traced process (None if killed by signal).
    pub exit_code: Option<i32>,
}

/// A learned (or hand-written) sandbox profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    /// Paths granted read (ReadFile+ReadDir).
    pub ro: Vec<String>,
    /// Paths granted read+execute.
    pub rx: Vec<String>,
    /// Paths granted read+write+create+remove (files).
    pub rw: Vec<String>,
    /// Allowed TCP bind ports (empty = all bind blocked).
    pub bind_ports: Vec<u16>,
    /// Allowed TCP connect ports (empty = all connect blocked).
    pub connect_ports: Vec<u16>,
    /// Allowed syscall numbers (x86_64). Everything else -> ENOSYS.
    pub syscalls: Vec<i64>,
    /// Deny abstract-unix-socket connections to outside the domain (Landlock scope).
    pub scope_abstract_unix: bool,
    /// Deny signaling processes outside the domain (Landlock scope).
    pub scope_signal: bool,
}

impl Profile {
    /// Human-readable syscall names for the allowlist.
    pub fn syscall_names(&self) -> Vec<String> {
        self.syscalls
            .iter()
            .map(|n| syscalls::num_to_name(*n))
            .collect()
    }
}

/// Classify a filesystem path into a right-bucket, folding writes up to the
/// parent directory so that *creating* files inside it is permitted.
fn classify(
    acc: &FsAccess,
    ro: &mut BTreeSet<String>,
    rx: &mut BTreeSet<String>,
    rw: &mut BTreeSet<String>,
) {
    match acc.mode {
        Mode::Exec => {
            rx.insert(acc.path.clone());
        }
        Mode::Write => {
            // Grant write+create on the parent directory so the workload can
            // (re)create the file across restarts, and read on the file itself.
            let parent = std::path::Path::new(&acc.path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            rw.insert(parent);
        }
        Mode::Read => {
            ro.insert(acc.path.clone());
        }
    }
}

/// Learn a [`Profile`] from a [`Trace`].
///
/// Rights are the least set that still covers every observed action. Network
/// and syscall allowlists are exactly what was observed; scopes are denied by
/// default (the demo workloads never need abstract sockets or cross-domain
/// signals), which is documented in the README as an intentional tightening.
pub fn learn(trace: &Trace) -> Profile {
    let mut ro = BTreeSet::new();
    let mut rx = BTreeSet::new();
    let mut rw = BTreeSet::new();
    for acc in &trace.fs {
        classify(acc, &mut ro, &mut rx, &mut rw);
    }
    // A path promoted to rx or covered by an rw parent need not also sit in ro.
    ro.retain(|p| !rx.contains(p));
    ro.retain(|p| !rw.iter().any(|w| p == w || p.starts_with(&format!("{w}/"))));

    Profile {
        ro: ro.into_iter().collect(),
        rx: rx.into_iter().collect(),
        rw: rw.into_iter().collect(),
        bind_ports: trace.bind_ports.iter().copied().collect(),
        connect_ports: trace.connect_ports.iter().copied().collect(),
        syscalls: trace.syscalls.iter().copied().collect(),
        scope_abstract_unix: true,
        scope_signal: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learn_classifies_modes() {
        let trace = Trace {
            cmd: vec!["demo".into()],
            fs: vec![
                FsAccess {
                    path: "/usr/lib/libc.so.6".into(),
                    mode: Mode::Exec,
                },
                FsAccess {
                    path: "/app/data/in.txt".into(),
                    mode: Mode::Read,
                },
                FsAccess {
                    path: "/app/out/result.txt".into(),
                    mode: Mode::Write,
                },
            ],
            syscalls: [0i64, 1, 257, 231].into_iter().collect(),
            bind_ports: [8080u16].into_iter().collect(),
            connect_ports: Default::default(),
            exit_code: Some(0),
        };
        let p = learn(&trace);
        assert!(p.rx.contains(&"/usr/lib/libc.so.6".to_string()));
        assert!(p.ro.contains(&"/app/data/in.txt".to_string()));
        assert!(p.rw.contains(&"/app/out".to_string()));
        assert_eq!(p.bind_ports, vec![8080]);
        assert!(p.scope_abstract_unix && p.scope_signal);
        assert!(p.syscalls.contains(&257));
    }

    #[test]
    fn ro_does_not_duplicate_rw_children() {
        let trace = Trace {
            cmd: vec!["demo".into()],
            fs: vec![
                FsAccess {
                    path: "/app/out/result.txt".into(),
                    mode: Mode::Write,
                },
                FsAccess {
                    path: "/app/out/result.txt".into(),
                    mode: Mode::Read,
                },
            ],
            syscalls: Default::default(),
            bind_ports: Default::default(),
            connect_ports: Default::default(),
            exit_code: Some(0),
        };
        let p = learn(&trace);
        assert!(p.rw.contains(&"/app/out".to_string()));
        assert!(!p.ro.contains(&"/app/out/result.txt".to_string()));
    }
}
