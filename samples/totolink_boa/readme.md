# totolink boa sample

This is the firmware-oriented sample in the artifact.

Default run mode:
- `run.sh` automatically extracts `sim_root.tar.xz` to `/tmp/rrfuzz_totolink_rootfs/`
- the extracted `sim_root/` is then used as the runtime rootfs

Run with bundled archive:

```bash
bash run.sh /path/to/patched-qemu
```

Optional external rootfs override:

```bash
bash run.sh /path/to/patched-qemu /path/to/totolink-rootfs
```

Files:
- `commands.txt`: sample command list
- `run.sh`: sample launcher
- `firmware/`: raw firmware image
- `sim_root.tar.xz`: prepared runtime rootfs archive
- `seeds/`: RR trace and BB trace
- `config/`: dictionary
