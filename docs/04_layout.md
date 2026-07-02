# layout

## top level

- `docs/`: ordered documentation
- `patches/`: authoritative integration patches
- `scripts/`: helper scripts
- `samples/`: all runnable packaged examples
- `rr_snapshot/`: trimmed source snapshot for code review
- `notes/`: supporting notes
- `base_commit.txt`: upstream base commit

## samples

- `samples/toy_record_replay/`: minimal rr record/replay smoke sample
- `samples/toy_fuzz/`: minimal end-to-end fuzzing smoke sample
- `samples/lightftp/`: real-world x86-64 sample
- `samples/totolink_boa/`: firmware-oriented sample

## naming

- All sample entry scripts are named `run.sh`.
- Each sample directory contains a small `readme.md` and `commands.txt`.
- Prepared firmware rootfs content should be distributed as an archive such as `sim_root.tar.xz`, not as a large unpacked tree.
