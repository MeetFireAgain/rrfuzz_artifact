# RR-Fuzz Quick Start Guide

## Quick Start

### Prerequisites

1. Compiled QEMU: `../qemu-x86_64` (with RR-Fuzz support)
2. Target program and Trace file can be generated automatically

### 1. Quick Verification (Single Process)

The simplest way is to run the pre-configured test script, which will automatically record a trace and start fuzzing:

```bash
# From the linux-user/rr_fuzzing/ directory
./run_ls_fuzz_test.sh
```

This script will:
1. Record an initial seed trace using `/bin/ls`
2. Start a single-process Fuzzer
3. Run 1000 iterations (approx. 20 seconds)
4. Output results to `fuzzing_output_ls/`

### 2. Multi-Process Stress Testing (Recommended)

In production environments, multi-process mode can significantly improve efficiency (linear scaling):

```bash
# From the linux-user/rr_fuzzing/ directory
./run_ls_fuzz_multiprocess.sh
```

This script will:
1. Automatically detect CPU core count
2. Start N Worker processes
3. Use shared memory to synchronize coverage and corpus
4. Run for 90 seconds then stop automatically

### 3. Batch Testing (Full Suite)

Validate all 15 targets (including standard tools and LAVA-M):

```bash
./run_multiple_targets.sh
```

---

## Core Command Parameter Reference

If you want to run the Fuzzer manually (rather than using the Helper Scripts above), refer to the following parameters:

### Single-Process Mode (`fuzz_main.py`)

```bash
python3 fuzzing/fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /bin/ls \
    --iterations 1000
```

- `--qemu`: QEMU executable path
- `--trace`: Recorded initial Trace file
- `--target`: Target program path
- `--smart`: Enable smart mutation mode (with PathFinder)

### Multi-Process Mode (`fuzz_multiprocess.py`)

```bash
python3 fuzzing/fuzz_multiprocess.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /bin/ls \
    --workers 4 \
    --timeout 3600
```

- `--workers`: Number of Worker processes (default: CPU core count)
- `--sync-dir`: Synchronization directory (default: `sync_dir`)
- `--timeout`: Runtime limit (seconds)

---

## Frequently Asked Questions

### Q: Why do Workers start so fast?
**A**: We introduced **IPC Caching** in v7.0. On first run, the Trace is parsed and cached as a `.pkl` file; subsequent starts load the cache directly, reducing startup time from 5s to <0.1s.

### Q: How do I view coverage details?
**A**: After each run completes, a `final_stats.json` is generated. For detailed test reports, refer to **`FINAL_SUMMARY_REPORT.md`** in the project root directory.

### Q: What target programs are supported?
**A**: Almost all Linux user-mode programs are supported, including IO-intensive programs (`cp`, `cat`) and interactive programs. We ensure determinism through complete hooks for `pread64`, `recvfrom`, and other syscalls.
