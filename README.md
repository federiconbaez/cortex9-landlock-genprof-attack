# landlock-genprof-attack

Aprende un perfil **Landlock (ABI 6) + allowlist seccomp** a partir de una
corrida de entrenamiento y después lo **ataca**: corre un catálogo de escapes
conocidos y reporta cuáles pasan. La métrica es **escapes bloqueados / total**.

*Learns a Landlock (ABI 6) + seccomp-allowlist profile from a training run,
then attacks it with a catalog of known escapes and reports which ones get
through. Metric: escapes blocked / total.*

## Qué hay de nuevo (y qué no) / What is new (and what is not)

Aprender perfiles a partir de la observación **no es nuevo**. Por ejemplo,
[landlock-genprof](https://github.com/idriss-eliguene/landlock-genprof) se
describe como un generador automático de perfiles de seguridad para Kubernetes
(Landlock, NetworkPolicy, seccomp y capabilities) "built on observation of a
running pod", y [lightbox](https://github.com/burntcarrot/lightbox) es un sandbox
liviano sobre Landlock + seatbelt. Solo leímos sus páginas públicas de
repositorio, no auditamos su código.

El aporte de este repo es el **oráculo adversario**. Dado un perfil, mide
cuántos escapes catalogados bloquea, con un control positivo por ataque: un
ataque solo cuenta si funciona *sin* sandbox. Además atribuye cada bloqueo a
su capa (Landlock o seccomp) y compara varias apps.

## Resultado medido / Measured result

Kernel 6.12.94 con Landlock ABI 6, sin privilegios. Catálogo: **41 escapes + 2
controles** (todos los escapes con control positivo válido).

### Por app / Per app

```bash
cargo build --release
./target/release/lgpa measure-apps --ws /tmp/lgpa-apps --json apps.json --min-blocked-pct 80
```

| App | Fidelidad | Escapes bloqueados | Dónde se midió |
|---|---|---|---|
| **demo** (lgpa demo-workload) | **14/14** | **36/41 = 87,8 %** | box + CI (ABI 6/8) |
| **curl** | **2/2** | **35/41 = 85,4 %** | box + CI |
| **python3 -m http.server** | **2/2** | **35/41 = 85,4 %** | box + CI |
| **sqlite3** | **2/2** | **36/41 = 87,8 %** | **solo CI** (apt de la box no lo instala) |
| **nginx** | **2/2** | **37/41 = 90,2 %** | **solo CI** (apt de la box no lo instala) |

Los no bloqueados comunes son límites reales, no skips silenciosos:

| Escape | Por qué pasa |
|---|---|
| `fd-passing` | Landlock no revoca fds abiertos antes del sandbox ([docs](https://docs.kernel.org/userspace-api/landlock.html)). `lgpa run` cierra heredados; test `run_closes_inherited_fds`. |
| `planted-hardlink` | Hardlink plantado desde afuera *antes* del sandbox. Crear uno desde adentro sí se bloquea (`hardlink-escape`, `EXDEV`/REFER). |
| `access-outside` | Landlock no restringe `access(2)`; si el entrenamiento lo observó, queda en la allowlist. |
| `udp-exfil` | Landlock solo cubre UDP desde ABI 10; con `sendto` en la allowlist escapa en ABI 6. |
| `unix-pathname` | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` exige ABI 9; en ABI 6 escapa si `connect` está permitido. |
| `tiocsti` (curl/http.server) | `ioctl` aparece en esas allowlists; el kernel moderno igual exige CAP_SYS_ADMIN, pero el syscall llega. |

Comparación demo: perfil **manual** (Landlock por directorio, sin seccomp) ≈ 45 %;
aprendido ≈ 88 %.

```bash
./target/release/lgpa measure --ws /tmp/lgpa-ws --json report.json --min-blocked-pct 85
```

## Catálogo (41 escapes + 2 controles) / Catalog

| Categoría | Ataques |
|---|---|
| fs-confinement | read-outside, write-outside |
| fs-underprivilege | write-ro-region, create-in-ro, unlink-ro, truncate-ro |
| fs-traversal | dotdot-traversal |
| proc-tricks | proc-self-root, proc-self-mem, proc-fd-reopen |
| symlink | follow-symlink, create-symlink |
| hardlink / rename | hardlink-escape, rename-out |
| fs-create | mkdir-outside, mknod-outside |
| exec | exec-outside |
| network | connect-denied-port, bind-denied-port, udp-exfil, unix-pathname |
| scope (ABI 6) | signal-outside, abstract-uds |
| seccomp | ptrace, unshare, mount, bpf, keyctl, userfaultfd, setns, pidfd_getfd |
| fd-passing | fd-passing, opath-reopen |
| landlock-gap | chmod-outside, chown-outside, stat-outside, access-outside, utimes-outside |
| io-uring | iouring-openat (`io_uring_setup` como proxy de `IORING_OP_OPENAT`) |
| tty | tiocsti |
| environmental | planted-hardlink |
| control (negativo) | ctrl-read-allowed, ctrl-write-allowed |

### Por qué no llegamos a exactamente 40 “puros” / Gap vs the original 40 target

La idea pedía ~40 escapes. Hay **41** implementados y medidos. Queda **fuera
de alcance hoy**, justificado uno por uno:

1. **Carrera TOCTOU real de symlink con hilo que hace el swap** — requiere un
   segundo hilo/proceso sincronizado que mute el dentry entre el check y el
   uso. El catálogo ya tiene `follow-symlink` (symlink plantado *antes*). Una
   carrera viva no está armada; armarla bien excede el día y su resultado
   depende del scheduler. **No medida.**
2. **`IORING_OP_OPENAT` completo** — `iouring-openat` prueba `io_uring_setup`
   (si setup está permitido, la superficie está abierta). Un submit SQE real
   con `IORING_OP_OPENAT` contra el secreto no está cableado. **Parcial.**
3. **UDP con enforcement Landlock** — necesita ABI ≥ 10; la box y el runner
   actual reportan ABI 6/8. En ABI 6 medimos el escape vía seccomp/allowlist
   (`udp-exfil`). **Medido como gap de ABI.**
4. **UNIX pathname con `RESOLVE_UNIX`** — ABI ≥ 9. Igual que UDP: medido como
   escape en ABI 6 (`unix-pathname`). **Medido como gap de ABI.**

## Cómo funciona / How it works

1. `lgpa trace -- cmd…`: tracer propio sobre `ptrace(2)` (sin `strace`). Sigue
   **fork/vfork/clone** (`PTRACE_O_TRACE*`). Lee paths con `process_vm_readv`
   (en esta box `/proc/<pid>/mem` devolvía `EIO`). Deduce `PT_INTERP` / `#!`.
2. `lgpa learn`: lectura por archivo, escritura sobre el padre, puertos
   exactos, allowlist = syscalls observadas (+ `exit`/`exit_group`/
   `rt_sigreturn` siempre). Scopes ABI 6 negados.
3. `lgpa run --profile p.json -- cmd`: cierra fds heredados; si Landlock no
   queda `FullyEnforced`, **falla** (no corre sin confinar).
4. `lgpa measure` / `lgpa measure-apps`: fidelidad (2 corridas) + matriz de
   ataques × {none, landlock, seccomp, both}. Sin ABI ≥ 6 sale con error y
   **no inventa un número**.

## Qué está probado y qué no / Proven vs not

**Probado** (box + CI, `cargo test` 12 tests, kernel real):

- aprendizaje con intérprete ELF/`#!` y seguimiento de fork;
- fidelidad 100 % en demo/curl/http.server;
- ≥85 % de bloqueo en el catálogo completo de 41 con controles positivos;
- cierre de fds heredados; `execve` no aprendido → `EACCES`.

**No probado / limitaciones:**

- **sqlite3 y nginx** no se pueden instalar en la box (apt mirror 500 /
  paquete ausente); el job `measure-apps` de CI los instaló y midió
  (run `40818322394`): sqlite3 87,8 %, nginx 90,2 %.
- El loader Cortex-9 (`09-elf-zk-loader`) **no** se midió: cablearlo como
  workload de entrenamiento + corpus de bins excede el resto del día.
- Solo x86_64.
- El perfil “manual” del demo es un ejemplo nuestro, no una muestra real.
- `iouring-openat` no llega al submit de `IORING_OP_OPENAT`.
- Sin carrera TOCTOU viva de symlink.

## Licencia / License

Apache-2.0. Ver `LICENSE`.
