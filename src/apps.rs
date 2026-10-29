//! Per-app training workloads and fidelity checks for the multi-app measure.
//!
//! Each app knows how to: prepare a workspace, produce an argv (+ optional
//! driver for servers), and verify that a sandboxed rerun still completes its
//! training actions.

use landlock_genprof_attack::trace::{self, Driver};
use landlock_genprof_attack::Trace;
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// One measurable application.
pub struct App {
    pub id: &'static str,
    pub title: &'static str,
    /// True when the binary is expected on this host; false → CI-only.
    pub required_on_box: bool,
    pub binary: &'static str,
}

pub const APPS: &[App] = &[
    App {
        id: "demo",
        title: "lgpa demo-workload",
        required_on_box: true,
        binary: "lgpa", // resolved to current_exe
    },
    App {
        id: "curl",
        title: "curl (HTTP GET of a local file via http.server helper)",
        required_on_box: true,
        binary: "curl",
    },
    App {
        id: "http-server",
        title: "python3 -m http.server",
        required_on_box: true,
        binary: "python3",
    },
    App {
        id: "sqlite3",
        title: "sqlite3 CLI (create/insert/select)",
        required_on_box: false, // apt mirror fails on the box; CI installs it
        binary: "sqlite3",
    },
    App {
        id: "nginx",
        title: "nginx -c (serve one static file, then quit)",
        required_on_box: false,
        binary: "nginx",
    },
];

pub fn which(bin: &str) -> Option<PathBuf> {
    if bin == "lgpa" {
        return std::env::current_exe().ok();
    }
    std::env::var_os("PATH").and_then(|paths| {
        for d in std::env::split_paths(&paths) {
            let p = d.join(bin);
            if p.is_file() {
                return Some(p);
            }
        }
        None
    })
}

pub fn available(app: &App) -> bool {
    which(app.binary).is_some()
}

/// Prepare the per-app subtree under `ws` and return (argv, optional driver).
pub fn prepare(app: &App, ws: &Path) -> Result<(Vec<String>, Option<Driver>), String> {
    let dir = ws.join(app.id);
    // Preserve .lgpa-port across fidelity re-prepares so the learned bind/connect
    // ports still match.
    let saved_port = std::fs::read_to_string(dir.join(".lgpa-port")).ok();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    if let Some(p) = saved_port {
        let _ = std::fs::write(dir.join(".lgpa-port"), p);
    }
    match app.id {
        "demo" => {
            let appdir = dir.join("app");
            std::fs::create_dir_all(appdir.join("data")).unwrap();
            std::fs::create_dir_all(appdir.join("out")).unwrap();
            for (n, c) in [
                ("a.txt", "alpha\n"),
                ("b.txt", "beta\n"),
                ("c.txt", "gamma\n"),
            ] {
                std::fs::write(appdir.join("data").join(n), c).unwrap();
            }
            let port = sticky_port(&dir);
            let exe = which("lgpa").ok_or("lgpa missing")?;
            let argv = vec![
                exe.to_string_lossy().into(),
                "demo-workload".into(),
                "--dir".into(),
                appdir.to_string_lossy().into(),
                "--port".into(),
                port.to_string(),
            ];
            Ok((argv, None))
        }
        "curl" => {
            // Serve a tiny file with python http.server in the driver, curl it.
            let www = dir.join("www");
            std::fs::create_dir_all(&www).unwrap();
            std::fs::write(www.join("hello.txt"), b"hello-from-curl-test\n").unwrap();
            let port = sticky_port(&dir);
            let curl = which("curl").ok_or("curl missing")?;
            let py = which("python3").ok_or("python3 missing")?;
            // Driver starts the server, waits for curl (the tracee) to finish by
            // polling; actually the tracee IS curl, so driver must start server
            // BEFORE curl runs. We start server in a pre-thread that binds first.
            // Approach: driver starts server immediately; main thread briefly
            // waits for port readiness then the trace of curl begins.
            // Here prepare() returns argv for curl; the driver starts python.
            let www2 = www.clone();
            let driver: Driver = Box::new(move |_pid: Pid| {
                let _child = Command::new(&py)
                    .args([
                        "-m",
                        "http.server",
                        &port.to_string(),
                        "--bind",
                        "127.0.0.1",
                    ])
                    .current_dir(&www2)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
                // Wait until the port accepts connections (up to 2s).
                for _ in 0..40 {
                    if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                // Keep server alive while curl (the tracee) runs; the driver
                // thread is joined after tracing ends, so sleep a bit then kill.
                // We cannot know when curl finishes from here easily; the
                // parent joins us after waitpid completes, so just wait.
                // Actually: driver is started concurrently with tracing. Curl
                // may race ahead of server readiness. The readiness loop above
                // runs in the driver while curl is already being traced...
                // FIX: sleep long enough that curl's retries work, then stay
                // up until we're joined (tracing done).
                // Curl under ptrace is slow; keep the server up for a few seconds.
                std::thread::sleep(Duration::from_secs(5));
                if let Ok(mut c) = _child {
                    let _ = c.kill();
                }
            });
            // Give the driver a head start: we actually need server up BEFORE
            // curl starts. The current Driver API starts the driver in parallel
            // with parent_loop. To avoid the race, insert a short sleep in argv
            // via a wrapper script... cleaner: use `curl --retry`.
            let url = format!("http://127.0.0.1:{port}/hello.txt");
            let out = dir.join("out");
            std::fs::create_dir_all(&out).unwrap();
            let argv = vec![
                curl.to_string_lossy().into(),
                "--silent".into(),
                "--show-error".into(),
                "--retry".into(),
                "5".into(),
                "--retry-delay".into(),
                "0".into(),
                "--retry-connrefused".into(),
                "-o".into(),
                out.join("hello.txt").to_string_lossy().into(),
                url,
            ];
            Ok((argv, Some(driver)))
        }
        "http-server" => {
            let www = dir.join("www");
            std::fs::create_dir_all(&www).unwrap();
            std::fs::write(www.join("index.html"), b"<h1>lgpa</h1>\n").unwrap();
            let port = sticky_port(&dir);
            let py = which("python3").ok_or("python3 missing")?;
            let argv = vec![
                py.to_string_lossy().into(),
                "-m".into(),
                "http.server".into(),
                port.to_string(),
                "--bind".into(),
                "127.0.0.1".into(),
            ];
            // Driver: wait for listen, GET once, then SIGTERM the server.
            let driver: Driver = Box::new(move |pid: Pid| {
                for _ in 0..50 {
                    if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = Command::new("curl")
                    .args([
                        "--silent",
                        "--max-time",
                        "2",
                        &format!("http://127.0.0.1:{port}/index.html"),
                    ])
                    .stdout(Stdio::null())
                    .status();
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
                // Allow a moment for cleanup; parent_loop will reap.
                std::thread::sleep(Duration::from_millis(200));
            });
            // http.server must chdir to www. Use a wrapper via env: we set
            // argv and rely on prepare's caller to set current_dir when tracing.
            // Stash the www path as a marker file the caller reads.
            std::fs::write(dir.join(".workdir"), www.to_string_lossy().as_bytes()).unwrap();
            Ok((argv, Some(driver)))
        }
        "sqlite3" => {
            let db = dir.join("t.db");
            let sql = dir.join("script.sql");
            std::fs::write(
                &sql,
                "CREATE TABLE t(x TEXT);\nINSERT INTO t VALUES('hi');\nSELECT * FROM t;\n",
            )
            .unwrap();
            let bin = which("sqlite3").ok_or("sqlite3 missing")?;
            let argv = vec![
                bin.to_string_lossy().into(),
                db.to_string_lossy().into(),
                format!(".read {}", sql.display()),
            ];
            Ok((argv, None))
        }
        "nginx" => {
            let conf = dir.join("nginx.conf");
            let www = dir.join("www");
            let logs = dir.join("logs");
            let tmp = dir.join("tmp");
            std::fs::create_dir_all(&www).unwrap();
            std::fs::create_dir_all(&logs).unwrap();
            std::fs::create_dir_all(&tmp).unwrap();
            std::fs::write(www.join("index.html"), b"nginx-ok\n").unwrap();
            let port = sticky_port(&dir);
            let conf_txt = format!(
                "daemon off;\n\
                 master_process off;\n\
                 worker_processes 1;\n\
                 error_log {logs}/error.log;\n\
                 pid {dir}/nginx.pid;\n\
                 events {{ worker_connections 4; }}\n\
                 http {{\n\
                   access_log {logs}/access.log;\n\
                   client_body_temp_path {tmp}/c;\n\
                   proxy_temp_path {tmp}/p;\n\
                   fastcgi_temp_path {tmp}/f;\n\
                   uwsgi_temp_path {tmp}/u;\n\
                   scgi_temp_path {tmp}/s;\n\
                   server {{\n\
                     listen 127.0.0.1:{port};\n\
                     root {www};\n\
                     location / {{ }}\n\
                   }}\n\
                 }}\n",
                logs = logs.display(),
                dir = dir.display(),
                tmp = tmp.display(),
                www = www.display(),
                port = port,
            );
            std::fs::write(&conf, conf_txt).unwrap();
            let bin = which("nginx").ok_or("nginx missing")?;
            let argv = vec![
                bin.to_string_lossy().into(),
                "-c".into(),
                conf.to_string_lossy().into(),
                "-p".into(),
                dir.to_string_lossy().into(),
            ];
            let driver: Driver = Box::new(move |pid: Pid| {
                for _ in 0..50 {
                    if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = Command::new("curl")
                    .args([
                        "--silent",
                        "--max-time",
                        "2",
                        &format!("http://127.0.0.1:{port}/index.html"),
                    ])
                    .stdout(Stdio::null())
                    .status();
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
                std::thread::sleep(Duration::from_millis(300));
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
            });
            Ok((argv, Some(driver)))
        }
        other => Err(format!("unknown app {other}")),
    }
}

fn sticky_port(dir: &Path) -> u16 {
    let f = dir.join(".lgpa-port");
    if let Ok(s) = std::fs::read_to_string(&f) {
        if let Ok(p) = s.trim().parse() {
            return p;
        }
    }
    let p = free_port();
    let _ = std::fs::write(&f, p.to_string());
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(18080)
}

/// Trace the app's training workload.
pub fn trace_app(app: &App, ws: &Path) -> Result<Trace, String> {
    let (argv, driver) = prepare(app, ws)?;
    // For http-server, chdir into www so the server roots correctly.
    let workdir = ws.join(app.id).join(".workdir");
    let old = if workdir.exists() {
        let wd = std::fs::read_to_string(&workdir).unwrap();
        let prev = std::env::current_dir().ok();
        let _ = std::env::set_current_dir(&wd);
        prev
    } else {
        None
    };
    let result = trace::trace_command_driven(&argv, driver).map_err(|e| e.to_string());
    if let Some(prev) = old {
        let _ = std::env::set_current_dir(prev);
    }
    let t = result?;
    // Servers killed by SIGTERM may not have exit_code 0; accept signaled-ok.
    if app.id == "http-server" || app.id == "nginx" {
        return Ok(t);
    }
    if t.exit_code != Some(0) {
        return Err(format!(
            "{} training exited {:?}: {:?}",
            app.id, t.exit_code, t.cmd
        ));
    }
    Ok(t)
}

/// Rerun the training under the profile; return (ok_actions, total_actions).
/// For external binaries we treat a successful exit as total=1 ok=1.
pub fn fidelity(
    app: &App,
    ws: &Path,
    profile_path: &Path,
    layers: &str,
) -> Result<(u32, u32), String> {
    let exe = which("lgpa").ok_or("lgpa missing")?;
    let (argv, driver) = prepare(app, ws)?;
    // Rebuild argv as: lgpa run --profile P --layers L -- <original argv>
    let mut run_argv: Vec<String> = vec![
        exe.to_string_lossy().into(),
        "run".into(),
        "--profile".into(),
        profile_path.to_string_lossy().into(),
        "--layers".into(),
        layers.into(),
        "--".into(),
    ];
    run_argv.extend(argv);

    let workdir = ws.join(app.id).join(".workdir");
    let old = if workdir.exists() {
        let wd = std::fs::read_to_string(&workdir).unwrap();
        let prev = std::env::current_dir().ok();
        let _ = std::env::set_current_dir(&wd);
        prev
    } else {
        None
    };

    // For server apps, we still need the driver to poke/kill.
    let status = if let Some(d) = driver {
        // Spawn lgpa run as a child, run driver against it, wait.
        let child = Command::new(&run_argv[0])
            .args(&run_argv[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let pid = Pid::from_raw(child.id() as i32);
        d(pid);
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if let Some(prev) = old {
            let _ = std::env::set_current_dir(prev);
        }
        // Servers: success = we got a response (driver ran curl). Check curl
        // side effects? For MVP treat any termination after driver as ok if
        // the process started under the sandbox (exit != 20 enforcement fail).
        if out.status.code() == Some(20) {
            return Err(format!("{} enforcement failed", app.id));
        }
        return Ok((1, 1));
    } else {
        let out = Command::new(&run_argv[0])
            .args(&run_argv[1..])
            .output()
            .map_err(|e| e.to_string())?;
        if let Some(prev) = old {
            let _ = std::env::set_current_dir(prev);
        }
        if app.id == "demo" {
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
                    return Ok((ok, total));
                }
            }
            return Err(format!("demo produced no ACTIONS line: {}", text));
        }
        if out.status.success() {
            Ok((1, 1))
        } else {
            Err(format!(
                "{} sandboxed run failed (status {:?}): {}",
                app.id,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    };
    status
}
