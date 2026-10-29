//! `lgpa measure`: the reproducible end-to-end measurement.

use landlock_genprof_attack::attack::{self, Ctx, Outcome};
use landlock_genprof_attack::enforce::{self, Layers};
use landlock_genprof_attack::{learn, trace, Profile};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

const LAYERS: [Layers; 4] = [
    Layers::None,
    Layers::LandlockOnly,
    Layers::SeccompOnly,
    Layers::Both,
];

#[derive(Serialize)]
struct Row {
    id: String,
    category: String,
    expect_block: bool,
    none: String,
    landlock: String,
    seccomp: String,
    both: String,
    /// Positive control: the attack must succeed with no sandbox to count.
    valid: bool,
}

#[derive(Serialize)]
struct ProfileResult {
    name: String,
    fidelity_ok: u32,
    fidelity_total: u32,
    rows: Vec<Row>,
    valid_attacks: u32,
    blocked: u32,
    blocked_pct: f64,
    controls_ok: bool,
    escaped_ids: Vec<String>,
}

#[derive(Serialize)]
struct Report {
    landlock_abi: i32,
    kernel: String,
    catalog_size: usize,
    learned: ProfileResult,
    manual: Option<ProfileResult>,
    learned_profile_sizes: Sizes,
    reproduce: String,
}

#[derive(Serialize)]
struct Sizes {
    ro: usize,
    rx: usize,
    rw: usize,
    syscalls: usize,
    bind_ports: Vec<u16>,
    connect_ports: Vec<u16>,
}

fn s(o: Option<Outcome>) -> String {
    let Some(o) = o else { return "-".to_string() };
    match o {
        Outcome::Blocked => "blocked",
        Outcome::Escaped => "escaped",
        Outcome::Inconclusive => "inconclusive",
        Outcome::HarnessError => "harness-error",
    }
    .to_string()
}

fn setup_ws(ws: &Path) -> std::io::Result<()> {
    for d in ["app/data", "app/out", "secret", "outside"] {
        let p = ws.join(d);
        if p.exists() {
            std::fs::remove_dir_all(&p)?;
        }
        std::fs::create_dir_all(&p)?;
    }
    std::fs::write(ws.join("app/data/a.txt"), "alpha\n")?;
    std::fs::write(ws.join("app/data/b.txt"), "beta\n")?;
    std::fs::write(ws.join("app/data/c.txt"), "gamma\n")?;
    std::fs::write(ws.join("secret/canary.txt"), "LGPA-CANARY-DO-NOT-READ\n")?;
    Ok(())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(18080)
}

/// Run the demo workload under `profile_path`, return (ok,total).
fn fidelity(exe: &Path, profile_path: &Path, layers: &str, ws: &Path, port: u16) -> (u32, u32) {
    let out = Command::new(exe)
        .args(["run", "--profile"])
        .arg(profile_path)
        .args(["--layers", layers, "--"])
        .arg(exe)
        .args(["demo-workload", "--dir"])
        .arg(ws.join("app"))
        .args(["--port", &port.to_string()])
        .output();
    let Ok(out) = out else { return (0, 1) };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ACTIONS ") {
            let mut ok = 0;
            let mut total = 0;
            for kv in rest.split_whitespace() {
                if let Some(v) = kv.strip_prefix("ok=") {
                    ok = v.parse().unwrap_or(0);
                }
                if let Some(v) = kv.strip_prefix("total=") {
                    total = v.parse().unwrap_or(0);
                }
            }
            if !out.status.success() {
                eprintln!("{text}{}", String::from_utf8_lossy(&out.stderr));
            }
            return (ok, total);
        }
    }
    eprintln!(
        "fidelity run produced no ACTIONS line (status {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    (0, 1)
}

/// Bind a listening abstract unix socket outside any Landlock domain.
fn abstract_listener(name: &str) -> Option<std::os::unix::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).ok()?;
    std::os::unix::net::UnixListener::bind_addr(&addr).ok()
}

fn run_suite(
    name: &str,
    profile: &Profile,
    ws: &Path,
    ctx: &Ctx,
    fid: (u32, u32),
    only_layer: Option<Layers>,
) -> Result<ProfileResult, String> {
    let mut rows = Vec::new();
    let mut valid = 0u32;
    let mut blocked = 0u32;
    let mut controls_ok = true;
    let mut escaped = Vec::new();
    for a in attack::catalog() {
        let mut outs: [Option<Outcome>; 4] = [None; 4];
        for (i, l) in LAYERS.iter().enumerate() {
            if let Some(ol) = only_layer {
                if *l != Layers::None && *l != ol {
                    continue;
                }
            }
            setup_ws(ws).map_err(|e| e.to_string())?;
            // Re-bind the pathname UNIX socket after setup_ws wiped outside/.
            let _sock_guard = std::os::unix::net::UnixListener::bind(
                std::path::Path::new(&ctx.outside_dir).join("lgpa.sock"),
            )
            .ok();
            // Re-seed the in-sandbox ro file (unlink-ro / truncate-ro destroy it).
            if let Some(parent) = std::path::Path::new(&ctx.ro_file).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&ctx.ro_file, b"ro\n");
            let _ = std::fs::create_dir_all(&ctx.rw_dir);
            let o = attack::run_one(profile, *l, ctx, &a);
            outs[i] = Some(o);
            if o == Outcome::HarnessError {
                return Err(format!(
                    "harness error: could not apply layer {} for {}",
                    l.name(),
                    a.id
                ));
            }
        }
        let real = match only_layer {
            Some(Layers::LandlockOnly) => outs[1],
            Some(Layers::SeccompOnly) => outs[2],
            _ => outs[3],
        };
        let real = real.unwrap_or(Outcome::Inconclusive);
        let is_valid = outs[0] == Some(Outcome::Escaped);
        if a.expect_block {
            if is_valid {
                valid += 1;
                if real == Outcome::Blocked {
                    blocked += 1;
                } else {
                    escaped.push(a.id.to_string());
                }
            }
        } else if real != Outcome::Escaped {
            controls_ok = false;
        }
        rows.push(Row {
            id: a.id.into(),
            category: a.category.into(),
            expect_block: a.expect_block,
            none: s(outs[0]),
            landlock: s(outs[1]),
            seccomp: s(outs[2]),
            both: s(outs[3]),
            valid: is_valid,
        });
    }
    let pct = if valid == 0 {
        0.0
    } else {
        100.0 * blocked as f64 / valid as f64
    };
    Ok(ProfileResult {
        name: name.into(),
        fidelity_ok: fid.0,
        fidelity_total: fid.1,
        rows,
        valid_attacks: valid,
        blocked,
        blocked_pct: (pct * 10.0).round() / 10.0,
        controls_ok,
        escaped_ids: escaped,
    })
}

/// A typical hand-written profile: directory-granular Landlock (whole app dir
/// writable, system dirs read/exec), no seccomp, no scopes.
fn manual_profile(ws: &Path, exe: &Path, port: u16) -> Profile {
    let mut rx: Vec<String> = ["/usr", "/lib", "/lib64", "/bin", "/etc"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .map(|p| p.to_string())
        .collect();
    if let Some(d) = exe.parent() {
        rx.push(d.to_string_lossy().into());
    }
    Profile {
        ro: vec![],
        rx,
        rw: vec![
            ws.join("app").to_string_lossy().into(),
            ws.join("app/data").to_string_lossy().into(),
            ws.join("app/out").to_string_lossy().into(),
        ],
        bind_ports: vec![port],
        connect_ports: vec![port],
        syscalls: vec![],
        scope_abstract_unix: false,
        scope_signal: false,
    }
}

fn print_result(r: &ProfileResult) {
    println!("== profile: {} ==", r.name);
    println!(
        "training fidelity: {}/{} actions allowed",
        r.fidelity_ok, r.fidelity_total
    );
    println!(
        "{:<22} {:<18} {:>8} {:>13} {:>13} {:>13} {:>13}",
        "attack", "category", "valid", "none", "landlock", "seccomp", "both"
    );
    for row in &r.rows {
        println!(
            "{:<22} {:<18} {:>8} {:>13} {:>13} {:>13} {:>13}",
            row.id,
            row.category,
            if row.expect_block {
                if row.valid {
                    "yes"
                } else {
                    "NO"
                }
            } else {
                "control"
            },
            row.none,
            row.landlock,
            row.seccomp,
            row.both
        );
    }
    println!(
        "ESCAPES BLOCKED: {}/{} = {:.1}%  (controls ok: {})  not blocked: {:?}",
        r.blocked, r.valid_attacks, r.blocked_pct, r.controls_ok, r.escaped_ids
    );
}

pub fn measure(ws: &Path, json: Option<PathBuf>, compare: bool, min_blocked_pct: f64) -> i32 {
    // 0. Fail loud without Landlock ABI >= 6.
    let abi = match enforce::landlock_abi() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return 2;
        }
    };
    if abi < 6 {
        eprintln!("FAIL: Landlock ABI {abi} < 6 (scopes need ABI 6); refusing to report a number");
        return 2;
    }
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("FAIL: current_exe: {e}");
            return 2;
        }
    };
    if let Err(e) = setup_ws(ws) {
        eprintln!("FAIL: workspace: {e}");
        return 2;
    }
    let ws = std::fs::canonicalize(ws).unwrap_or(ws.to_path_buf());
    let port = free_port();

    // 1. Trace the training workload.
    let argv: Vec<String> = vec![
        exe.to_string_lossy().into(),
        "demo-workload".into(),
        "--dir".into(),
        ws.join("app").to_string_lossy().into(),
        "--port".into(),
        port.to_string(),
    ];
    let t = match trace::trace_command(&argv) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL: trace: {e}");
            return 2;
        }
    };
    if t.exit_code != Some(0) {
        eprintln!(
            "FAIL: training workload exited {:?} unsandboxed",
            t.exit_code
        );
        return 2;
    }
    // 2. Learn.
    let profile = learn(&t);
    let ppath = ws.join("profile.learned.json");
    let _ = std::fs::write(
        ws.join("trace.json"),
        serde_json::to_string_pretty(&t).unwrap(),
    );
    let _ = std::fs::write(&ppath, serde_json::to_string_pretty(&profile).unwrap());

    // 3. Training fidelity: two consecutive runs (the second is a restart over
    // existing state).
    let _ = setup_ws(&ws);
    let f1 = fidelity(&exe, &ppath, "both", &ws, port);
    let f2 = fidelity(&exe, &ppath, "both", &ws, port);
    let fid = (f1.0 + f2.0, f1.1 + f2.1);

    // 4. Attack suite.
    let abstract_name = format!("lgpa-{}", std::process::id());
    let listener = abstract_listener(&abstract_name);
    // Something must listen on the denied port, or connect fails with
    // ECONNREFUSED and the attack has no positive control.
    let denied_port = if port == 65535 { port - 1 } else { port + 1 };
    let _tcp_listener = match std::net::TcpListener::bind(("127.0.0.1", denied_port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FAIL: cannot listen on denied port {denied_port}: {e}");
            return 2;
        }
    };
    if listener.is_none() {
        eprintln!("FAIL: could not bind abstract unix listener");
        return 2;
    }
    let ctx = Ctx {
        outside_file: ws.join("secret/canary.txt").to_string_lossy().into(),
        outside_new: ws.join("outside/escaped.txt").to_string_lossy().into(),
        outside_dir: ws.join("outside").to_string_lossy().into(),
        ro_file: ws.join("app/data/a.txt").to_string_lossy().into(),
        rw_dir: ws.join("app/out").to_string_lossy().into(),
        denied_port,
        denied_bind_port: loop {
            let p = free_port();
            if p != port && p != denied_port {
                break p;
            }
        },
        abstract_name,
    };
    let learned = match run_suite("learned (landlock+seccomp)", &profile, &ws, &ctx, fid, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return 3;
        }
    };

    // 5. Optional comparison with a hand-written profile.
    let manual = if compare {
        let mp = manual_profile(&ws, &exe, port);
        let mpath = ws.join("profile.manual.json");
        let _ = std::fs::write(&mpath, serde_json::to_string_pretty(&mp).unwrap());
        let _ = setup_ws(&ws);
        let mf1 = fidelity(&exe, &mpath, "landlock", &ws, port);
        let mf2 = fidelity(&exe, &mpath, "landlock", &ws, port);
        match run_suite(
            "manual (landlock only, dir-granular)",
            &mp,
            &ws,
            &ctx,
            (mf1.0 + mf2.0, mf1.1 + mf2.1),
            Some(Layers::LandlockOnly),
        ) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("FAIL: {e}");
                return 3;
            }
        }
    } else {
        None
    };
    drop(listener);

    let report = Report {
        landlock_abi: abi,
        kernel,
        catalog_size: attack::catalog().len(),
        learned_profile_sizes: Sizes {
            ro: profile.ro.len(),
            rx: profile.rx.len(),
            rw: profile.rw.len(),
            syscalls: profile.syscalls.len(),
            bind_ports: profile.bind_ports.clone(),
            connect_ports: profile.connect_ports.clone(),
        },
        learned,
        manual,
        reproduce: "cargo build --release && ./target/release/lgpa measure --ws /tmp/lgpa-ws"
            .into(),
    };
    println!(
        "Landlock ABI {} on kernel {}; catalog {} entries",
        report.landlock_abi, report.kernel, report.catalog_size
    );
    println!(
        "learned profile: ro={} rx={} rw={} syscalls={} bind={:?} connect={:?}",
        report.learned_profile_sizes.ro,
        report.learned_profile_sizes.rx,
        report.learned_profile_sizes.rw,
        report.learned_profile_sizes.syscalls,
        report.learned_profile_sizes.bind_ports,
        report.learned_profile_sizes.connect_ports
    );
    print_result(&report.learned);
    if let Some(m) = &report.manual {
        print_result(m);
    }
    if let Some(j) = json {
        let _ = std::fs::write(j, serde_json::to_string_pretty(&report).unwrap());
    }
    let l = &report.learned;
    if l.fidelity_ok != l.fidelity_total || l.fidelity_total == 0 {
        eprintln!(
            "FAIL: training fidelity {}/{}",
            l.fidelity_ok, l.fidelity_total
        );
        return 4;
    }
    if !l.controls_ok {
        eprintln!("FAIL: negative controls blocked by learned profile");
        return 4;
    }
    if l.valid_attacks as usize + 2 != report.catalog_size {
        // Every catalogued attack (minus the 2 controls) must have a working
        // unsandboxed positive control; otherwise the % is over a smaller,
        // silently-shrunk denominator.
        eprintln!(
            "FAIL: only {}/{} attacks passed their positive control",
            l.valid_attacks,
            report.catalog_size - 2
        );
        return 4;
    }
    if l.blocked_pct < min_blocked_pct {
        eprintln!(
            "FAIL: blocked {:.1}% < required {min_blocked_pct}%",
            l.blocked_pct
        );
        return 5;
    }
    0
}

/// Measure every available app from [`crate::apps::APPS`].
pub fn measure_apps(ws: &Path, json: Option<PathBuf>, min_blocked_pct: f64) -> i32 {
    use crate::apps;
    use landlock_genprof_attack::learn;

    let abi = match enforce::landlock_abi() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return 2;
        }
    };
    if abi < 6 {
        eprintln!("FAIL: Landlock ABI {abi} < 6");
        return 2;
    }
    let _ = std::fs::create_dir_all(ws);
    let ws = std::fs::canonicalize(ws).unwrap_or(ws.to_path_buf());

    #[derive(Serialize)]
    struct AppRow {
        id: String,
        title: String,
        available: bool,
        skipped_reason: Option<String>,
        fidelity_ok: u32,
        fidelity_total: u32,
        valid_attacks: u32,
        blocked: u32,
        blocked_pct: f64,
        escaped_ids: Vec<String>,
        profile_syscalls: usize,
    }
    #[derive(Serialize)]
    struct AppsReport {
        landlock_abi: i32,
        kernel: String,
        catalog_size: usize,
        apps: Vec<AppRow>,
        reproduce: String,
    }

    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut rows = Vec::new();

    for app in apps::APPS {
        println!("\n######## app: {} ({}) ########", app.id, app.title);
        if !apps::available(app) {
            let reason = if app.required_on_box {
                "REQUIRED binary missing on this host"
            } else {
                "optional; not installed on this host (CI installs it)"
            };
            eprintln!("SKIP {}: {reason}", app.id);
            rows.push(AppRow {
                id: app.id.into(),
                title: app.title.into(),
                available: false,
                skipped_reason: Some(reason.into()),
                fidelity_ok: 0,
                fidelity_total: 0,
                valid_attacks: 0,
                blocked: 0,
                blocked_pct: 0.0,
                escaped_ids: vec![],
                profile_syscalls: 0,
            });
            if app.required_on_box {
                return 2;
            }
            continue;
        }
        let app_ws = ws.join(app.id);
        let _ = std::fs::create_dir_all(&app_ws);
        // Shared attack workspace (secret/outside/…) lives next to the app dir.
        let attack_ws = ws.join(format!("{}-attack", app.id));
        if let Err(e) = setup_ws(&attack_ws) {
            eprintln!("FAIL setup {}: {e}", app.id);
            return 2;
        }
        let attack_ws = std::fs::canonicalize(&attack_ws).unwrap_or(attack_ws);

        let trace = match apps::trace_app(app, &app_ws) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL trace {}: {e}", app.id);
                return 2;
            }
        };
        let profile = learn(&trace);
        let ppath = app_ws.join("profile.learned.json");
        let _ = std::fs::write(&ppath, serde_json::to_string_pretty(&profile).unwrap());
        let _ = std::fs::write(
            app_ws.join("trace.json"),
            serde_json::to_string_pretty(&trace).unwrap(),
        );

        // Fidelity: two runs (fresh + restart).
        let f1 = match apps::fidelity(app, &app_ws, &ppath, "both") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("FAIL fidelity1 {}: {e}", app.id);
                return 4;
            }
        };
        let f2 = match apps::fidelity(app, &app_ws, &ppath, "both") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("FAIL fidelity2 {}: {e}", app.id);
                return 4;
            }
        };
        let fid = (f1.0 + f2.0, f1.1 + f2.1);
        if fid.0 != fid.1 || fid.1 == 0 {
            eprintln!("FAIL {}: training fidelity {}/{}", app.id, fid.0, fid.1);
            return 4;
        }

        let abstract_name = format!("lgpa-{}-{}", app.id, std::process::id());
        let _listener = abstract_listener(&abstract_name);
        let denied_port = free_port();
        let _tcp = std::net::TcpListener::bind(("127.0.0.1", denied_port));
        let ctx = Ctx {
            outside_file: attack_ws.join("secret/canary.txt").to_string_lossy().into(),
            outside_new: attack_ws
                .join("outside/escaped.txt")
                .to_string_lossy()
                .into(),
            outside_dir: attack_ws.join("outside").to_string_lossy().into(),
            // For apps without an obvious ro file, reuse the canary's sibling
            // under a read-granted path: grant the attack_ws/app path? The
            // attack suite needs an in-sandbox ro file. We seed one into the
            // profile by adding the attack workspace data file to ro.
            ro_file: attack_ws
                .join("secret/../secret/canary.txt")
                .to_string_lossy()
                .into(), // replaced below
            rw_dir: attack_ws.join("outside").to_string_lossy().into(), // replaced
            denied_port,
            denied_bind_port: free_port(),
            abstract_name,
        };
        // Build an attack-friendly overlay: copy a private ro/rw pair into the
        // profile so the suite's controls work regardless of the app's paths.
        let mut profile_for_attack = profile.clone();
        let ro = attack_ws.join("in/ro.txt");
        let rw = attack_ws.join("in/rw");
        let _ = std::fs::create_dir_all(&rw);
        let _ = std::fs::create_dir_all(ro.parent().unwrap());
        let _ = std::fs::write(&ro, b"ro\n");
        profile_for_attack.ro.push(ro.to_string_lossy().into());
        profile_for_attack.rw.push(rw.to_string_lossy().into());
        // Also allow Execute on the app binary + interp so controls that fork
        // don't need it; the suite itself does not exec the app.
        let ctx = Ctx {
            ro_file: ro.to_string_lossy().into(),
            rw_dir: rw.to_string_lossy().into(),
            ..ctx
        };

        let result = match run_suite(
            &format!("learned/{}", app.id),
            &profile_for_attack,
            &attack_ws,
            &ctx,
            fid,
            None,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("FAIL suite {}: {e}", app.id);
                return 3;
            }
        };
        print_result(&result);
        rows.push(AppRow {
            id: app.id.into(),
            title: app.title.into(),
            available: true,
            skipped_reason: None,
            fidelity_ok: result.fidelity_ok,
            fidelity_total: result.fidelity_total,
            valid_attacks: result.valid_attacks,
            blocked: result.blocked,
            blocked_pct: result.blocked_pct,
            escaped_ids: result.escaped_ids.clone(),
            profile_syscalls: profile.syscalls.len(),
        });
    }

    println!("\n======== PER-APP SUMMARY ========");
    println!(
        "{:<12} {:>10} {:>12} {:>8}",
        "app", "fidelity", "blocked%", "syscalls"
    );
    let mut worst = 100.0_f64;
    for r in &rows {
        if !r.available {
            println!(
                "{:<12} {:>10} {:>12}  ({})",
                r.id,
                "-",
                "SKIP",
                r.skipped_reason.as_deref().unwrap_or("")
            );
            continue;
        }
        println!(
            "{:<12} {:>5}/{:<4} {:>11.1}% {:>8}",
            r.id, r.fidelity_ok, r.fidelity_total, r.blocked_pct, r.profile_syscalls
        );
        worst = worst.min(r.blocked_pct);
    }

    let report = AppsReport {
        landlock_abi: abi,
        kernel,
        catalog_size: attack::catalog().len(),
        apps: rows,
        reproduce: "cargo build --release && ./target/release/lgpa measure-apps --ws /tmp/lgpa-apps --json apps.json".into(),
    };
    if let Some(j) = json {
        let _ = std::fs::write(j, serde_json::to_string_pretty(&report).unwrap());
    }
    if worst < min_blocked_pct {
        eprintln!("FAIL: worst app blocked {worst:.1}% < required {min_blocked_pct}%");
        return 5;
    }
    0
}
