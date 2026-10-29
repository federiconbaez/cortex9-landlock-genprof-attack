//! End-to-end tests against the real kernel. They FAIL (never skip) when
//! Landlock ABI < 6 is unavailable.

use std::os::unix::process::CommandExt;
use std::process::Command;

fn lgpa() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lgpa"))
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("lgpa-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn kernel_has_landlock_abi6() {
    let out = lgpa().arg("abi").output().unwrap();
    assert!(
        out.status.success(),
        "Landlock unavailable: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    let v: i32 = s
        .trim()
        .trim_start_matches("Landlock ABI: ")
        .parse()
        .unwrap();
    assert!(v >= 6, "need Landlock ABI >= 6, got {v}");
}

#[test]
fn measure_end_to_end_meets_acceptance() {
    let ws = tmpdir("measure");
    let json = ws.join("report.json");
    let out = lgpa()
        .args(["measure", "--ws"])
        .arg(ws.join("ws"))
        .arg("--json")
        .arg(&json)
        .args(["--min-blocked-pct", "90"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "measure failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let l = &r["learned"];
    // 100% of training actions (two runs: fresh + restart) allowed.
    assert_eq!(l["fidelity_ok"], l["fidelity_total"]);
    assert_eq!(l["fidelity_total"], 14);
    assert!(l["controls_ok"].as_bool().unwrap());
    // Catalog >= 15 attacks, all with a working positive control.
    let valid = l["valid_attacks"].as_u64().unwrap();
    assert!(valid >= 15, "only {valid} valid attacks");
    assert!(l["blocked_pct"].as_f64().unwrap() >= 90.0, "{stdout}");
    // The known Landlock limitations are reported as escapes, not hidden.
    let esc: Vec<String> = l["escaped_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(esc.contains(&"fd-passing".to_string()), "{esc:?}");
    // The learned profile beats the hand-written one.
    let m = &r["manual"];
    assert!(l["blocked"].as_u64().unwrap() > m["blocked"].as_u64().unwrap());
    let _ = std::fs::remove_dir_all(ws);
}

#[test]
fn trace_records_exec_interp_and_syscalls() {
    let ws = tmpdir("trace");
    let tj = ws.join("t.json");
    let st = lgpa()
        .args(["trace", "-o"])
        .arg(&tj)
        .args(["--", "true"])
        .status()
        .unwrap();
    assert!(st.success());
    let t: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&tj).unwrap()).unwrap();
    assert_eq!(t["exit_code"], 0);
    assert!(t["syscalls"].as_array().unwrap().len() > 5);
    let execs: Vec<&str> = t["fs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["mode"] == "Exec")
        .map(|a| a["path"].as_str().unwrap())
        .collect();
    assert!(execs.iter().any(|p| p.ends_with("/true")), "{execs:?}");
    assert!(execs.iter().any(|p| p.contains("ld-linux")), "{execs:?}");
    let _ = std::fs::remove_dir_all(ws);
}

#[test]
fn run_closes_inherited_fds() {
    // Mitigation for the fd-passing limitation: `lgpa run` must not leak an
    // fd opened (without CLOEXEC) by whoever launched it.
    let ws = tmpdir("fds");
    let prof = ws.join("p.json");
    std::fs::write(&prof, r#"{"ro":[],"rx":[],"rw":[],"bind_ports":[],"connect_ports":[],"syscalls":[],"scope_abstract_unix":false,"scope_signal":false}"#).unwrap();
    let secret = std::fs::File::open("/proc/self/status").unwrap();
    use std::os::fd::AsRawFd;
    let raw = secret.as_raw_fd();
    let mut cmd = lgpa();
    cmd.args(["run", "--profile"]).arg(&prof).args([
        "--layers",
        "none",
        "--",
        "/bin/ls",
        "/proc/self/fd",
    ]);
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 9) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fds: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(String::from)
        .collect();
    assert!(
        !fds.contains(&"9".to_string()),
        "fd 9 leaked into the sandbox: {fds:?}"
    );
    let _ = std::fs::remove_dir_all(ws);
}

#[test]
fn run_fails_loud_on_bad_profile() {
    let out = lgpa()
        .args(["run", "--profile", "/nonexistent/p.json", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn learned_profile_refuses_unlearned_exec() {
    // Independent of the attack harness: the real launcher, real execve.
    let ws = tmpdir("deny");
    let out = lgpa()
        .args(["measure", "--ws"])
        .arg(ws.join("ws"))
        .arg("--no-compare")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let prof = std::fs::canonicalize(ws.join("ws"))
        .unwrap()
        .join("profile.learned.json");
    let r = lgpa()
        .args(["run", "--profile"])
        .arg(&prof)
        .args(["--", "/bin/sh", "-c", "true"])
        .output()
        .unwrap();
    assert_eq!(
        r.status.code(),
        Some(126),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert!(String::from_utf8_lossy(&r.stderr).contains("Permission denied"));
    // Same command with no layers runs fine (positive control).
    let r = lgpa()
        .args(["run", "--profile"])
        .arg(&prof)
        .args(["--layers", "none", "--", "/bin/sh", "-c", "true"])
        .output()
        .unwrap();
    assert!(r.status.success());
    let _ = std::fs::remove_dir_all(ws);
}
