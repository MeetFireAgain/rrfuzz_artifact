# lightftp sample

This is the real-world non-firmware sample in the artifact.

Run:

```bash
bash run.sh /path/to/patched-qemu
```

Requirements:
- `gcc`
- `make`
- `libgnutls` development headers — Ubuntu/Debian: `sudo apt-get install libgnutls28-dev`
  (the package is `libgnutls28-dev`, not `libgnutls-dev`)
- `openssl` (standard on most systems; used to generate a self-signed TLS certificate)

Files:
- `commands.txt`: sample command list
- `run.sh`: sample launcher
- `auto_retr.trace`: reference trace (included for inspection; see below)
- `fftp_artifact.conf`: runtime config

## source modifications for RR tracing

LightFTP's `main.c` was modified to enable deterministic record-replay:

1. **Single-thread execution.** The original server spawned a new pthread per
   connection. For RR tracing, threading is disabled: `ftpmain(NULL)` is called
   directly in the main thread. This makes the entire session fully sequential
   and traceable by the RR engine.

2. **Single-connection mode.** `ftpmain` handles exactly one FTP client session
   and then returns. The server exits after that session completes. This bounds
   the trace to a single well-defined interaction.

3. **Interactive console removed.** The original `do { c = getc(stdin); } while
   (c != 'q')` loop was removed. The server no longer reads from stdin.

These changes are visible in `src/main.c`.

## why run.sh records a fresh trace

RR-Fuzz replay works at the syscall level: every syscall result (including
memory-mapped addresses for shared libraries) is stored in the trace and fed
back verbatim during replay. The trace therefore encodes the virtual address
layout of the recording environment.

When `fftp` is compiled on a different machine, the dynamic linker may load
`libgnutls.so` at a different base address. Replaying the pre-packaged trace
against such a binary causes divergence at the first mmap-dependent access,
which manifests as a SIGSEGV early in replay.

`run.sh` avoids this by recording locally: it compiles `fftp`, starts it in
`RR_MODE=record`, runs one FTP session (LIST + RETR), then immediately fuzzes
the resulting trace. The trace and binary are always from the same build.

The included `auto_retr.trace` is a reference recording from the development
environment, useful for inspecting the trace format and syscall structure, but
is not used directly by `run.sh`.

## why the port readiness check uses `ss`

Because the server handles exactly one connection and then exits, any TCP
connect used to test whether port 2121 is open would be accepted as the real
FTP session, causing the server to exit before the actual FTP client runs.

`run.sh` checks readiness with:

```bash
ss -tlnp | grep ':2121 '
```

This confirms the socket is in LISTEN state without establishing a connection.
