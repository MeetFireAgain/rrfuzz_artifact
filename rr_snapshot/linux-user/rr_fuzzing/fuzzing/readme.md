# RR-Fuzz (Record-Replay Fuzzer)

**Version**: 7.0 (Production Ready)  
**Date**: 2026-01-08

RR-Fuzz is a high-performance, deterministic Fuzzing framework based on QEMU user-mode emulation. It achieves 100% reproducible execution flow through Record-Replay technology, and explores deep program states through syscall-level mutation (Syscall Mutation).

---

## 🚀 Core Features (v7.0)

### 1. Extreme Performance and Scalability
- **High Performance**: 50+ execs/s on a single core, linear scaling on multi-core (4 cores > 200 execs/s).
- **IPC Caching**: Smart caching mechanism reduces Worker startup latency from 5s to <10ms.
- **Multi-Process Architecture**: 1+N architecture based on `FuzzMaster`, efficiently synchronizing Coverage and Corpus.

### 2. Deep State Exploration
- **Exploration Mode**: `PathFinder` automatically switches modes when the graph is saturated, performing deep mutations on already-covered paths to break out of local optima.
- **IO Determinism**: Complete hooks for `pread64`, `recvfrom`, `getrandom`, and other syscalls ensure deterministic replay of IO operations.

### 3. Proven Validation Results
- **LAVA-M Validation**: Major breakthroughs on real datasets (e.g., `who` coverage improved 42x).
- **Full Suite Compatibility**: Successfully supports 15+ target programs, including Coreutils standard tools (`ls`, `cat`, `grep`) and custom vulnerable programs.

---

## 📂 Directory Structure

```
linux-user/rr_fuzzing/
├── src/                     # C language core implementation (core/engine/runtime/syscall/common)
├── include/                 # C header files
├── fuzzing/                 # Python Fuzzing engine
│   ├── conductor/          # Core logic (FuzzingCore, Mutator, Coverage, Executor)
│   ├── multiprocess/       # Multi-process management (FuzzMaster, DynamicForkController)
│   ├── config/             # target profiles / dictionary / schema
│   └── utils/              # Utility tools
├── tests/                   # Test cases and scripts
└── docs/                    # Architecture and analysis documents
```

## 🚦 Quick Start

### 1. Run Tests
We provide out-of-the-box test scripts:

```bash
# Single-process quick verification (/bin/ls)
./run_ls_fuzz_test.sh

# Multi-process stress testing (recommended)
./run_ls_fuzz_multiprocess.sh
```

### 2. View Reports
Detailed test results are summarized in the project root:
👉 **[FINAL_SUMMARY_REPORT.md](../FINAL_SUMMARY_REPORT.md)**

---

## 🔧 Architecture Design

RR-Fuzz uses a layered architecture:

1.  **Layer 1 (Trace Storage)**: Efficient Trace storage and indexing.
2.  **Layer 2 (Core Fuzzing)**: Main Fuzzing loop and mutation engine.
3.  **Layer 3 (QEMU Integration)**: Deterministic execution and coverage feedback.
4.  **Layer 4 (Multi-Process)**: Distributed coordination and resource synchronization (v7.0 focus).
5.  **Layer 5 (Analysis)**: Result analysis and visualization.

For detailed architecture, see: [DETAILED_ARCHITECTURE.md](../DETAILED_ARCHITECTURE.md)

---

## 🛠️ Troubleshooting

- **Worker Startup Failure**: Check if there are residual files in `/dev/shm/` (`rm /dev/shm/rr_fuzz_*`).
- **Coverage Not Increasing**: Check if the Trace file was generated in `record` mode, or try using `--smart` to enable PathFinder.
- **"Fork Fail"**: Ensure the target program does not contain unhooked IO system calls (currently the vast majority of Coreutils are supported).

---
**Maintainer**: WebFuzz Team
**Copyright**: Google DeepMind
