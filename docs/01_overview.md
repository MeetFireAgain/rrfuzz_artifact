# overview

This artifact packages RRFuzz as a patch set against upstream QEMU.

Base commit:
`95b9e0d2ade5d633fd13ffba96a54e87c65baf39`

Release model:
- patch-based artifact
- upstream base: QEMU `master` at the commit above
- demo scope: `x86_64-linux-user` and `mips-linux-user`

Contents:
- `docs/`: ordered reading path
- `patches/`: patch files to apply onto upstream QEMU
- `scripts/apply_patches.sh`: applies the patch set to a clean QEMU checkout
- `samples/`: packaged toy and real-world samples
- `rr_snapshot/`: readable RR-Fuzz source snapshot for review
- `notes/`: small supporting notes

Important note:
- `rr_snapshot/` is not a full mirror of the live `linux-user/rr_fuzzing` tree.
- It is a trimmed review snapshot focused on the runtime, fuzzer, templates, and toy programs needed for artifact inspection.

Partial release during peer review; see `HOLDBACK.md`.
