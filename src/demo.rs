//! Built-in demo workload: a tiny "service" with a fixed, countable set of
//! actions. It is the training workload *and* the fidelity check: rerun under
//! the learned profile it must report `ok == total`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

pub fn run(dir: &Path, port: u16) -> i32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    let mut fails: Vec<String> = Vec::new();
    let mut check = |name: &str, r: std::io::Result<()>| {
        total += 1;
        match r {
            Ok(()) => ok += 1,
            Err(e) => fails.push(format!("{name}: {e}")),
        }
    };

    // 1-3: read inputs.
    let mut acc = String::new();
    for f in ["a.txt", "b.txt", "c.txt"] {
        let r = std::fs::read_to_string(dir.join("data").join(f)).map(|s| acc.push_str(&s));
        check(&format!("read data/{f}"), r);
    }
    // 4: atomic write (tmp + rename in the same dir).
    let out = dir.join("out");
    check(
        "atomic write out/result.txt",
        std::fs::write(out.join("result.tmp"), acc.as_bytes())
            .and_then(|_| std::fs::rename(out.join("result.tmp"), out.join("result.txt"))),
    );
    // 5: append a log line.
    check(
        "append out/log.txt",
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out.join("log.txt"))
            .and_then(|mut f| f.write_all(b"run\n")),
    );
    // 6: read back own output.
    check(
        "read out/result.txt",
        std::fs::read_to_string(out.join("result.txt")).map(|_| ()),
    );
    // 7: TCP loopback echo on the configured port (bind + connect).
    check("tcp loopback echo", tcp_echo(port));

    println!("ACTIONS ok={ok} total={total}");
    for f in &fails {
        println!("FAIL {f}");
    }
    if ok == total {
        0
    } else {
        1
    }
}

fn tcp_echo(port: u16) -> std::io::Result<()> {
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let port = l.local_addr()?.port();
    let mut c = TcpStream::connect(("127.0.0.1", port))?;
    let (mut s, _) = l.accept()?;
    c.write_all(b"ping")?;
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf)?;
    if &buf != b"ping" {
        return Err(std::io::Error::other("echo mismatch"));
    }
    Ok(())
}
