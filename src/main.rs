//! `lgpa` — learn a Landlock+seccomp profile from a workload and prove it with
//! an adversarial escape suite.

use clap::{Parser, Subcommand};
use landlock_genprof_attack::enforce::{self, Layers};
use landlock_genprof_attack::{learn, trace, Profile};
use std::ffi::CString;
use std::path::PathBuf;

mod apps;
mod demo;
mod report;

#[derive(Parser)]
#[command(
    name = "lgpa",
    about = "Landlock+seccomp genprof with an adversarial escape suite"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Trace a command with ptrace and emit a JSON trace.
    Trace {
        /// Command to trace (everything after `--`).
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
        /// Write trace JSON here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Learn a profile from a trace JSON.
    Learn {
        #[arg(short, long)]
        trace: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Apply a profile and exec a command under it (fails loud if unenforced).
    Run {
        #[arg(short, long)]
        profile: PathBuf,
        #[arg(long, default_value = "both")]
        layers: String,
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Report the Landlock ABI the running kernel exposes.
    Abi,
    /// Built-in demo workload (reads data, writes output, binds a TCP port).
    DemoWorkload {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Measure every available app: learn, fidelity, attack suite per app.
    MeasureApps {
        #[arg(long, default_value = "/tmp/lgpa-apps")]
        ws: PathBuf,
        #[arg(long)]
        json: Option<PathBuf>,
        #[arg(long, default_value_t = 0.0)]
        min_blocked_pct: f64,
    },
    /// End-to-end: build a workspace, learn a profile, verify training fidelity,
    /// run the escape suite, and print the metric.
    Measure {
        /// Workspace dir (created if missing).
        #[arg(long, default_value = "/tmp/lgpa-ws")]
        ws: PathBuf,
        /// Emit JSON report here as well as the human summary.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Skip the manual-vs-learned comparison.
        #[arg(long)]
        no_compare: bool,
        /// Exit non-zero if the learned profile blocks fewer than this % of
        /// valid escapes (0 = report only).
        #[arg(long, default_value_t = 0.0)]
        min_blocked_pct: f64,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Trace { argv, out } => cmd_trace(&argv, out),
        Cmd::Learn { trace, out } => cmd_learn(&trace, out),
        Cmd::Run {
            profile,
            layers,
            argv,
        } => cmd_run(&profile, &layers, &argv),
        Cmd::Abi => cmd_abi(),
        Cmd::DemoWorkload { dir, port } => demo::run(&dir, port),
        Cmd::Measure {
            ws,
            json,
            no_compare,
            min_blocked_pct,
        } => report::measure(&ws, json, !no_compare, min_blocked_pct),
        Cmd::MeasureApps {
            ws,
            json,
            min_blocked_pct,
        } => report::measure_apps(&ws, json, min_blocked_pct),
    };
    std::process::exit(code);
}

fn cmd_trace(argv: &[String], out: Option<PathBuf>) -> i32 {
    match trace::trace_command(argv) {
        Ok(t) => {
            let j = serde_json::to_string_pretty(&t).unwrap();
            match out {
                Some(p) => std::fs::write(p, j).map(|_| 0).unwrap_or(1),
                None => {
                    println!("{j}");
                    0
                }
            }
        }
        Err(e) => {
            eprintln!("trace error: {e}");
            1
        }
    }
}

fn cmd_learn(trace: &PathBuf, out: Option<PathBuf>) -> i32 {
    let t: landlock_genprof_attack::Trace = match std::fs::read_to_string(trace)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(t) => t,
        None => {
            eprintln!("cannot read trace {}", trace.display());
            return 1;
        }
    };
    let p = learn(&t);
    let j = serde_json::to_string_pretty(&p).unwrap();
    match out {
        Some(path) => std::fs::write(path, j).map(|_| 0).unwrap_or(1),
        None => {
            println!("{j}");
            0
        }
    }
}

fn cmd_run(profile: &PathBuf, layers: &str, argv: &[String]) -> i32 {
    let p: Profile = match std::fs::read_to_string(profile)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(p) => p,
        None => {
            eprintln!("cannot read profile {}", profile.display());
            return 1;
        }
    };
    let layers = parse_layers(layers);
    // Build exec args BEFORE enforcing so no disallowed syscall runs after the
    // seccomp filter is installed.
    let c = CString::new(argv[0].as_str()).unwrap();
    let args: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // execve must survive the seccomp allowlist.
    let execve_nr = landlock_genprof_attack::syscalls::name_to_num("execve").unwrap();
    enforce::close_inherited_fds();
    if let Err(e) = enforce::apply(&p, layers, &[execve_nr]) {
        eprintln!("enforcement failed: {e}");
        return 20;
    }
    unsafe {
        libc::syscall(
            libc::SYS_execve,
            c.as_ptr(),
            argv_ptrs.as_ptr(),
            crate::environ(),
        );
    }
    eprintln!("execve failed: {}", std::io::Error::last_os_error());
    126
}

fn cmd_abi() -> i32 {
    match enforce::landlock_abi() {
        Ok(v) => {
            println!("Landlock ABI: {v}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn parse_layers(s: &str) -> Layers {
    match s {
        "none" => Layers::None,
        "landlock" => Layers::LandlockOnly,
        "seccomp" => Layers::SeccompOnly,
        _ => Layers::Both,
    }
}

/// `environ` for raw execve.
pub(crate) fn environ() -> *const *const libc::c_char {
    extern "C" {
        static environ: *const *const libc::c_char;
    }
    unsafe { environ }
}
