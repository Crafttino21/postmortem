# postmortem

Windows CLI tool for diagnosing machine-check exceptions and unexplained reboots.
Binary name: `pm`. Project/namespace/repo name: `postmortem`.

Full specification: `docs/postmortem-spec.md`. Consult it whenever anything is
unclear — do not guess at requirements.

## Hard rules

- **No kernel driver, no direct MSR access, ever.** WinRing0 and equivalents are
  on Microsoft's vulnerable-driver blocklist. WHEA already captured the MCA
  register contents in the event log; that is our data source. See spec §2.
- **No firmware or NVRAM writes.** BIOS-level settings are detect-and-advise only.
- **No silent state changes.** Every mutation is snapshotted, reversible, and
  gated behind confirmation or `--yes`.
- **Decoder logic stays platform-independent.** The CPER and MCA decoders are
  pure functions over byte buffers with no Windows headers, so their tests run
  anywhere.
- **No bit layouts from memory.** Every layout gets a spec reference in a comment
  (UEFI spec Appendix N for CPER, AMD PPR for SMCA, Intel SDM Vol. 3B Ch. 16 for
  architectural MCA).
- **Bounds-check everything read from a CPER record.** Offsets and lengths come
  from an untrusted file. Malformed input produces a diagnostic, never a crash.

## Workflow

Work one milestone from spec §8 at a time. Finish it — code compiles, tests
green — then stop and report. Do not start the next milestone unprompted.

## Build

```
cmake --preset debug && cmake --build --preset debug
ctest --preset debug --output-on-failure
```
