# manifest

## top level

- `readme.md`: short artifact entry point
- `docs/01_overview.md`: artifact overview
- `docs/02_install.md`: environment setup and build steps
- `docs/03_test_commands.md`: sample execution commands
- `docs/04_layout.md`: packaging layout
- `docs/05_rr_snapshot.md`: rr snapshot scope note
- `docs/06_manifest.md`: packaging inventory
- `base_commit.txt`: upstream QEMU base commit
- `patches/`: two patch files applied to upstream QEMU
- `scripts/`: helper scripts
- `samples/`: packaged toy and real-world samples
- `rr_snapshot/`: trimmed source snapshot for code review
- `notes/`: supporting notes

## packaging decisions

- `cases/` removed: replaced by `samples/toy_record_replay/` and `samples/toy_fuzz/`
- `demo-src/` removed: duplicated by `rr_snapshot/linux-user/rr_fuzzing/tests/programs/`
- `samples/lightftp/src/Release/*.o`, `*.d`, and prebuilt `fftp` removed: generated build artifacts
- `samples/totolink_boa/sim_root/` repackaged as `samples/totolink_boa/sim_root.tar.xz`
- `samples/totolink_boa/` launcher now auto-extracts the bundled rootfs archive into `/tmp/rrfuzz_totolink_rootfs/`
