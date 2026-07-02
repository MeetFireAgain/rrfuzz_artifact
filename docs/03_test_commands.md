# test commands

## all packaged samples

```bash
bash /path/to/rrfuzz_artifact/samples/toy_record_replay/run.sh /path/to/qemu-rrfuzz
bash /path/to/rrfuzz_artifact/samples/toy_fuzz/run.sh /path/to/qemu-rrfuzz
bash /path/to/rrfuzz_artifact/samples/lightftp/run.sh /path/to/qemu-rrfuzz
bash /path/to/rrfuzz_artifact/samples/totolink_boa/run.sh /path/to/qemu-rrfuzz
```

## current testability status

- `samples/toy_record_replay/`: runnable once patched `qemu-x86_64` is built
- `samples/toy_fuzz/`: runnable once patched `qemu-x86_64` is built
- `samples/lightftp/`: runnable once patched `qemu-x86_64` is built and `libgnutls28-dev` is installed
- `samples/totolink_boa/`: runnable once patched `qemu-mips` is built; bundled firmware image, trace, dictionary, and `sim_root.tar.xz` are already included

## notes

- The commands are present in this file and also duplicated in each sample directory.
- `samples/totolink_boa/run.sh` auto-extracts `sim_root.tar.xz` into `/tmp/rrfuzz_totolink_rootfs/` when no external rootfs is provided.
- `samples/lightftp/run.sh` builds fftp from source, records a fresh trace, then fuzzes. See `samples/lightftp/readme.md` for why local recording is required.
- All four samples have been reproduction-tested end-to-end on Ubuntu 22.04.
