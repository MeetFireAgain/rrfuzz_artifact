# Patch Notes

Base commit:
`95b9e0d2ade5d633fd13ffba96a54e87c65baf39`

The patch set is split into two parts.

## Patch 1: QEMU core integration

This patch modifies original QEMU files to add the RR-Fuzz hooks and build plumbing.

## Patch 2: RR-Fuzz runtime and toy demos

This patch adds:
- C-side RR core under `linux-user/rr_fuzzing/src/`
- headers under `linux-user/rr_fuzzing/include/`
- Python fuzzing driver under `linux-user/rr_fuzzing/fuzzing/`
- config templates under `linux-user/rr_fuzzing/config/template/`
- toy programs under `linux-user/rr_fuzzing/tests/programs/`

Some hunks are temporarily omitted during peer review; see
`HOLDBACK.md` at the artifact root.
