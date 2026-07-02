# rr snapshot

`rr_snapshot/` is a trimmed readable source snapshot of the RR-Fuzz subtree.

What it includes:
- C-side RR runtime and instrumentation sources
- Python fuzzing driver and orchestration code
- config templates
- toy test programs

What it is not:
- not a full mirror of the live `linux-user/rr_fuzzing` tree
- not a package of all live docs, crash triage data, campaign outputs, or auxiliary repository files

Current status:
- the core code files checked during packaging matched the live tree
- the surrounding live tree contains many more directories and files than this artifact snapshot
