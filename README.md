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
su capa (Landlock o seccomp).

*Profile learning is prior art. Our contribution is the adversarial oracle with
per-attack positive controls and per-layer attribution.*

## Resultado medido / Measured result

Kernel 6.12.94 con Landlock ABI 6, como usuario sin privilegios, 5/5 corridas
idénticas:

| Perfil | Fidelidad de entrenamiento | Escapes bloqueados |
|---|---|---|
| **aprendido** (Landlock + seccomp) | **14/14** acciones (2 corridas: limpia + restart) | **29/31 = 93,5 %** |
| manual (solo Landlock, por directorio) | 14/14 | 14/31 = 45,2 % |

Los 31 ataques pasaron su control positivo (escapan sin sandbox). Los 2
controles negativos, leer y escribir donde el perfil sí lo permite, siguen
permitidos.

**Lo que NO bloquea el perfil aprendido**, que son límites reales de Landlock:

- `fd-passing`: un fd abierto *antes* del sandbox sigue sirviendo. La
  documentación del kernel lo dice: *"Files or directories opened before the
  sandboxing are not subject to these restrictions"*
  ([docs.kernel.org](https://docs.kernel.org/userspace-api/landlock.html)).
  Mitigación: `lgpa run` cierra los fds heredados (`close_range`), y el test
  `run_closes_inherited_fds` lo verifica. No lo contamos como ataque
  bloqueado.
- `planted-hardlink`: si alguien de afuera planta *antes* un hardlink al
  secreto dentro del directorio escribible, ese nombre queda alcanzable. Crear
  el hardlink desde adentro sí se bloquea (`hardlink-escape`, con `EXDEV`,
  REFER).

```bash
cargo build --release
./target/release/lgpa measure --ws /tmp/lgpa-ws --json report.json --min-blocked-pct 90
```

## Catálogo (31 ataques + 2 controles) / Catalog

| Categoría | Ataques |
|---|---|
| fs-confinement | read-outside, write-outside |
| fs-underprivilege | write-ro-region, create-in-ro, unlink-ro, truncate-ro |
| fs-traversal | dotdot-traversal |
| proc-tricks | proc-self-root, proc-self-mem, proc-fd-reopen |
| symlink | follow-symlink (symlink plantado afuera→adentro), create-symlink |
| hardlink / rename | hardlink-escape, rename-out |
| fs-create | mkdir-outside, mknod-outside |
| exec | exec-outside |
| network (TCP, ABI 4) | connect-denied-port, bind-denied-port |
| scope (ABI 6) | signal-outside, abstract-uds |
| seccomp | ptrace, unshare, mount, bpf, keyctl, userfaultfd, setns, pidfd_getfd |
| fd-passing | fd-passing |
| environmental | planted-hardlink |
| control (negativo) | ctrl-read-allowed, ctrl-write-allowed |

El objetivo es llegar a 40 ataques; hoy hay 31. Quedan pendientes y **no
están medidos**:

- carrera TOCTOU real de symlinks con un hilo que haga el swap,
- `openat` vía io_uring,
- exfiltración UDP (Landlock recién la cubre desde ABI 10),
- sockets UNIX con path (ABI 9),
- `TIOCSTI` y ioctl sobre la TTY,
- `chmod`/`chown`/`stat`, que según la documentación Landlock no restringe,
- `O_PATH` + reabrir por `/proc/self/fd`.

## Cómo funciona / How it works

1. `lgpa trace -- cmd…`: tracer propio sobre `ptrace(2)`; no depende de
   `strace`. Registra cada número de syscall, los paths de
   `open`/`openat`/`openat2` (lectura o escritura según los flags), los
   destinos de `execve` y los puertos TCP de `bind`/`connect`. Además deduce
   el intérprete ELF (`PT_INTERP`) o el `#!`, porque el kernel lo abre dentro
   de `execve` sin una syscall visible pero Landlock igual exige `Execute`.
2. `lgpa learn`: lectura sobre el archivo exacto, escritura sobre el directorio
   padre (para recrear archivos en un restart) y exec sobre los binarios. La
   red queda en los puertos exactos que se observaron. La allowlist seccomp
   tiene exactamente las syscalls observadas, y el resto devuelve `ENOSYS`.
   Los scopes de ABI 6 se niegan siempre.
3. `lgpa run --profile p.json -- cmd`: cierra los fds heredados y aplica
   Landlock. Si el ruleset no queda `FullyEnforced`, **falla** en vez de
   correr sin confinar. Después aplica seccomp y hace `execve`.
4. `lgpa measure`: workspace descartable, traza del demo, aprendizaje,
   fidelidad (2 corridas) y la matriz de ataques × {none, landlock, seccomp,
   both}. Con un ABI menor a 6 sale con error y no reporta ningún número.

Los ataques seccomp cuentan como "escaped" si la syscall *llega al kernel*,
sin importar qué responda el kernel. Solo el `ENOSYS` de la allowlist cuenta
como bloqueo, para no acreditarle al sandbox un `EPERM` propio del kernel
(por ejemplo, `mount` sin `CAP_SYS_ADMIN`).

## Qué está probado y qué no / Proven vs not

**Probado** en la box y en CI (`cargo test`, 11 tests, contra el kernel real):

- aprendizaje,
- intérprete ELF y `#!`,
- fidelidad 14/14,
- ≥90 % de bloqueo con todos los controles positivos válidos,
- que el perfil aprendido le gana al manual,
- cierre de fds heredados,
- `execve` no aprendido → `EACCES`.

**No probado / limitaciones:**

- **Una sola app demo**: el workload incluido (lee 3 archivos, escribe
  atómico, append, eco TCP por loopback). La idea original pedía 5 apps
  (nginx, curl, `python -m http.server`, sqlite, el loader); eso **no está
  hecho**.
- El tracer sigue **un solo hilo/proceso**: no tiene `PTRACE_O_TRACEFORK` ni
  `TRACECLONE`. Las apps multihilo o que hacen fork (por ejemplo
  `http.server` con threads) van a dar perfiles incompletos.
- Solo x86_64.
- Los ataques corren *dentro* del proceso sandboxeado (fork + perfil), que
  modela un atacante con ejecución de código en la app. No hay exploits de
  kernel.
- El perfil "manual" lo escribimos nosotros como ejemplo típico, por
  directorio y sin seccomp. No es una muestra de perfiles reales.
- El puerto de entrenamiento se elige al azar en cada medición. Hay una
  carrera teórica si otro proceso lo toma.

## Licencia / License

Apache-2.0. Ver `LICENSE`.
