# RR Snapshot

This directory contains a trimmed readable source snapshot of the RR-Fuzz subtree.

Purpose:
- let reviewers inspect RR-Fuzz code directly without reading large patch hunks
- mirror the main code added by `patches/0002-rrfuzz-runtime-and-demos.patch`

Scope:
- C-side RR runtime and instrumentation sources
- Python fuzzing driver and orchestration code
- config templates
- toy test programs

Not included:
- the full live documentation tree
- full crash triage and campaign data
- all auxiliary repository files from the working tree
