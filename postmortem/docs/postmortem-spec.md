# Project Brief: `postmortem` — Windows CPU/Platform Stability Diagnostic CLI

Build a single-binary Windows CLI tool in modern C++ for diagnosing machine-check
exceptions, unexplained reboots, and CPU stability problems. The tool must be
usable by someone debugging a machine that reboots without a BSOD, where the only
forensic evidence is what Windows persisted in the event log.

**Naming:** the project and repository are called `postmortem`. The binary is
`pm.exe`, invoked as `pm`. Use `postmortem` for the CMake project name, the
namespace, the `%ProgramData%` state directory, and all prose; use `pm` only for
the executable and in CLI examples. Do not introduce a third variant.

---

## 1. Motivation (read this — it shapes every design decision)

The concrete scenario driving this tool: a Ryzen 9 5950X resets roughly every
7–14 days with no bugcheck and no crash dump. Kernel-Power 41 reports
`BugcheckCode 0`. The only real evidence is a `Microsoft-Windows-WHEA-Logger`
Event ID 18 containing a base64/hex CPER blob, which Event Viewer displays as an
unreadable wall of hex.

Extracting the diagnosis by hand took: decoding the CPER header, walking the
section descriptors, decoding the IA32/X64 Processor Error section, decoding
`MCA_STATUS` bit by bit, un-mangling `MCA_ADDR` (the LSB field in bits [61:56]
means it is **not** a flat address), mapping APIC IDs to physical cores, and
correlating the whole thing against Kernel-Power/Kernel-Boot/EventLog-6008
timestamps.

**That entire process is what this tool automates.** Every feature below exists
because it was a manual step in that investigation.

---

## 2. Hard constraints

**Do not, under any circumstances:**

- Load, bundle, or depend on a kernel driver for direct MSR access. `WinRing0`,
  `InpOut32`, and similar are on Microsoft's vulnerable-driver blocklist and are
  actively blocked by HVCI/Smart App Control. This is a non-negotiable design
  boundary — see §4.3 for why we don't need MSR access anyway.
- Write to firmware, modify BIOS/UEFI variables, or touch NVRAM.
- Silently change system state. Every mutation is explicit, logged, reversible,
  and requires either an interactive confirmation or `--yes`.

**Do:**

- Use only documented Win32 / Windows SDK APIs.
- Ship as a standalone `.exe` with no runtime install step.
- Degrade gracefully without admin rights: read-only features must work as a
  standard user; only mutating commands require elevation, and the tool must
  detect and report this clearly rather than failing with an opaque error.

---

## 3. Tech stack

- **C++20**, MSVC toolchain (also keep clang-cl working if cheap).
- **CMake** ≥ 3.20, presets for `debug` / `release`.
- Dependencies: keep minimal. `wevtapi`, `powrprof`, `advapi32`, `version` from
  the SDK. For JSON output, vendor a single-header library (nlohmann/json) or
  hand-roll a small serializer — your call, but justify it in the README.
- No Boost, no Qt, no Python shelling out. Single binary, no runtime deps beyond
  the UCRT.
- `x64` only. Detect and refuse ARM64 cleanly (the MCA decoding is x86-specific).

---

## 4. Feature modules

### 4.1 WHEA event ingestion

Query the System log via the Windows Event Log API (`EvtQuery`, `EvtNext`,
`EvtRender`) — **not** by shelling out to PowerShell or `wevtutil`.

- Filter on `Microsoft-Windows-WHEA-Logger`, all event IDs (17, 18, 19, 20, 47).
- Parse the structured `EventData` fields: `ErrorSource`, `ApicId`, `MCABank`,
  `MciStat`, `MciAddr`, `MciMisc`, `ErrorType`, `TransactionType`,
  `Participation`, `RequestType`, `MemorIO`, `MemHierarchyLvl`, `Timeout`,
  `OperationType`, `Channel`, `Length`, `RawData`.
- Support reading from a **saved `.evtx` file** as well as the live log
  (`EvtQueryFilePath`). This is essential — people export logs and send them to
  someone else for analysis. Make offline analysis a first-class path.

### 4.2 CPER decoder

The `RawData` field is a UEFI Common Platform Error Record. Decode it fully:

- **Header**: signature (`CPER`), revision, section count, error severity,
  validation bits, record length, BCD timestamp, platform/partition/creator/
  notification GUIDs, record ID, flags.
- **Section descriptors** (72 bytes each): offset, length, revision, validation
  bits, flags, section type GUID, FRU ID, section severity, FRU text.
- **Section bodies**, at minimum:
  - `9876ccad-47b4-4bdb-b65e-16f193c4f3db` — Processor Generic. Extract
    `CPUVersion` and decode it as CPUID leaf 1 EAX into family/model/stepping,
    including the extended-family/extended-model arithmetic. Extract the
    128-byte CPU brand string when present.
  - `dc3ea0b0-a144-4797-b95b-53fa242b6e1d` — IA32/X64 Processor Error. Validation
    bits encode the error-info count in bits [7:2] and context-info count in
    bits [13:8]. Walk the 64-byte Processor Error Info structures.
  - Error-info check structures, dispatched by GUID:
    - `a55701f5-e3ef-43de-ac72-249b573fad2c` Cache Check
    - `fc06b535-5e1f-4562-9f25-0a3b9adb63c3` TLB Check
    - `1cf3f8b3-c5b1-49a2-aa59-5eef92ffa63c` Bus Check
    - `48ab7f57-dc34-4f6c-a7d3-b0b5b0a74314` Micro-Architectural Check
  - `a5bc1114-6f64-4ede-b863-3e83ed7c83b1` — Platform Memory Error (for the
    DIMM-failure case: node/card/module/bank/row/column/rank, DIMM label).
  - Unknown section GUIDs: do not fail. Emit the GUID, length, and a hex dump,
    and carry on. Real records contain vendor and Microsoft-private sections.

**Check-structure bit layout is a common source of bugs.** For the Cache Check
structure, validation bits occupy [7:0] and the actual fields start at bit 16:
transaction type [17:16], operation [19:18], level [23:20], processor context
corrupt [24], uncorrected [25], precise IP [26], restartable IP [27],
overflow [28]. Get this right and unit-test it.

### 4.3 MCA register decoder

This is the highest-value module. Decode `MciStat` / `MciAddr` / `MciMisc` from
the event data — **no MSR reads needed**, WHEA already captured the register
contents at fault time.

`MCA_STATUS` architectural bits: Val [63], Overflow [62], UC [61], Enabled [60],
MiscV [59], AddrV [58], PCC [57]. AMD SMCA adds Deferred/Poison/TCC/SyndV in
[56:53] — flag these as vendor-specific and label them accordingly rather than
asserting a single layout.

Decode the compound error code in `MCA_STATUS[15:0]` per the standard encodings:
- `0000 0000 0000 001x` — internal unclassified
- `0000 0000 0001 TTLL` — TLB error
- `0000 0001 RRRR TTLL` — memory hierarchy / cache error
- `0000 1PPT RRRR IILL` — bus/interconnect error
- `0000 0100 0000 xxxx` — internal watchdog / timer

with the TT (transaction type), LL (cache level), RRRR (request), PP
(participation), II (memory/IO) sub-fields expanded to text.

`MCA_ADDR` on AMD SMCA is **not** a flat address: bits [55:0] hold the address
and bits [61:56] hold an LSB field indicating the least-significant valid bit.
Extract [55:0], sign-extend from bit 47, and classify the result:
- `0x00007F..` / low canonical → user-mode VA
- `0xFFFF8...` → kernel-mode VA
- otherwise → likely physical address or a structure index

Then report the classification. This distinction is diagnostically decisive and
Event Viewer gives you nothing.

**Interpretation layer.** Beyond bit expansion, emit a plain-language verdict:
- `UC=1 && PCC=1` → "unrecoverable, processor context corrupt; CPU resets
  immediately, no bugcheck and no crash dump is possible"
- `UC=1 && PCC=0` → "uncorrected but context intact; expect bugcheck 0x124"
- `UC=0` → "corrected; logged for trending, no immediate impact"
- `Overflow=1` → "additional errors were lost before this one was read"

### 4.4 Topology mapping

APIC IDs are meaningless to a user. Map them to physical structure:

- Use `CPUID` leaf `0x8000001E` (AMD) and leaf `0x1F`/`0x0B` (Intel) for the
  extended topology enumeration, plus `GetLogicalProcessorInformationEx` for
  cache and group affinity.
- Derive: APIC ID → core, thread, and — where the cache topology allows it —
  the L3 complex (CCX/CCD on AMD, or cluster on Intel hybrid parts).
- On hybrid Intel parts, label P-cores vs E-cores.
- Where topology is ambiguous, say so rather than guessing.

### 4.5 Correlation & timeline

The single most useful output. Build a merged, chronological timeline from:

- WHEA-Logger 17/18/19/20/47
- Kernel-Power 41 (extract `BugcheckCode`, `PowerButtonTimestamp`,
  `BugcheckInfoFromEFI`, `WHEABootErrorCount`)
- BugCheck 1001
- EventLog 6008 (unexpected shutdown, with its embedded local timestamp)
- Kernel-Boot 20/27/124 and Hyper-V-Hypervisor 41/42 (boot markers and
  virtualization state)
- Kernel-General 12/13 (OS start/stop)
- Microsoft-Windows-Kernel-Processor-Power 37/55 (thermal/performance limits)

Automatically cluster events that share a timestamp (uncorrectable MCEs are
broadcast to all cores, producing one record per processor — the tool must
recognise this and present it as **one** incident with N reporting cores, not N
incidents). Distinguish pre-crash events from post-boot harvesting: MCA banks are
sticky across warm reset, so a WHEA record timestamped seconds after boot usually
belongs to the *previous* session's crash. Say this explicitly in the output.

### 4.6 Trend analysis

Given the incident history, compute and report:

- Per-core and per-bank incident frequency
- Inter-arrival intervals, and whether the rate is flat, accelerating, or
  decelerating (a flat rate argues against progressive silicon degradation; an
  accelerating rate argues for it — state this reasoning in the output)
- Whether the faulting addresses cluster or scatter (clustering suggests a
  defective physical structure; scattering suggests a timing/voltage marginality)
- Time-of-day and correlation with idle vs. load, if load data is available
- First-seen date relative to OS install date (`InstallDate` from the registry)

Frame conclusions as evidence with confidence levels, never as certainties.

### 4.7 Live watch mode

`pm watch` — push subscription via `EvtSubscribe` on the System channel.
When a matching event arrives, decode and print it immediately. Optional
`--log <path>` to append NDJSON. Optional `--exec <command>` hook.

Clean Ctrl+C handling; the subscription must be torn down properly.

### 4.8 System state inspection

`pm status` — a snapshot of everything relevant to crash forensics:

- CPU: brand, family/model/stepping, microcode revision, core/thread count
- BIOS: vendor, version, release date (`SMBIOS` via `GetSystemFirmwareTable`)
- OS build, install date, uptime, last boot time
- Crash dump config: read `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`
  (`CrashDumpEnabled`, `AutoReboot`, `DumpFile`, `NMICrashDump`,
  `CrashOnCtrlScroll`) and the pagefile configuration; **warn loudly** if the
  current settings mean a future crash would produce no dump
- Existing dumps in `C:\Windows\Minidump`, `MEMORY.DMP`, `LiveKernelReports`
- Power: active scheme, `PROCTHROTTLEMAX`/`PROCTHROTTLEMIN`, idle-disable state
- Idle state residency via `CallNtPowerInformation(ProcessorInformation)`
- Virtualization/VBS state (`Win32_DeviceGuard`, hypervisor presence via CPUID)
- Memory config: `SMBIOS` Type 17 for DIMM population, speed, part numbers

### 4.9 Mitigations (the "fixes" module)

A named-mitigation system, each with `status` / `apply` / `revert`:

| Name | Mechanism |
|---|---|
| `max-cpu-99` | `PowerWriteACValueIndex` / `PowerWriteDCValueIndex` on `GUID_PROCESSOR_THROTTLE_MAXIMUM` = 99 |
| `min-cpu-100` | `GUID_PROCESSOR_THROTTLE_MINIMUM` = 100 (keeps cores out of deep idle) |
| `idle-disable` | `GUID_PROCESSOR_IDLE_DISABLE` = 1 |
| `idle-promote` | Tune `GUID_PROCESSOR_IDLE_PROMOTE_THRESHOLD` / demote thresholds |
| `dumps-on` | `CrashDumpEnabled` = 1, `AutoReboot` = 0, verify pagefile ≥ RAM on system volume |
| `nmi-dump` | `NMICrashDump` = 1, `CrashOnCtrlScroll` = 1 |

Requirements:

- Before mutating, snapshot the current value into
  `%ProgramData%\postmortem\state.json` with a timestamp. `revert` restores from
  that snapshot, not from a hardcoded default.
- Apply to all power schemes by default (`--scheme all`), or a named one.
- After applying a CPU-limit mitigation, **verify** it took effect. On builds
  where CPPC overrides `PROCTHROTTLEMAX`, the setting is silently ignored —
  sample actual frequencies briefly and warn if they still exceed the cap.
- `pm mitigate list` shows each mitigation, its current state, what it
  does, its cost (e.g. "increases idle power draw"), and whether it is
  currently applied.

**Explicitly out of scope, but detect and advise:** BIOS-level settings such as
*Power Supply Idle Control*, *Global C-State Control*, *PBO*, and *Curve
Optimizer* cannot be changed from Windows. When the evidence points at these,
print a clear, specific instruction telling the user which BIOS setting to
change and why — including the menu path where it is commonly found.

### 4.10 Reporting

- `pm report --format json` — full structured dump, stable schema, suitable
  for diffing across time or feeding to another tool.
- `pm report --format md` — a Markdown report a human can paste into a
  forum or support ticket, with the raw hex preserved so someone else can
  re-verify the decode independently.
- `--redact` to strip hostname, usernames, serial numbers, and DIMM part numbers
  before sharing.

---

## 5. CLI surface

```
pm status                          System snapshot
pm scan [--since 90d] [--evtx F]   Decode all WHEA records
pm show <n>                        Full decode of one incident, all sections
pm timeline [--since 90d]          Merged crash timeline
pm analyze                         Trend analysis + evidence-weighted verdict
pm watch [--log F] [--exec CMD]    Live subscription
pm decode --cper <hex|@file>       Decode a CPER blob standalone
pm decode --mci-stat 0xbea...      Decode a single MCA register value
pm topology                        APIC → core/thread/CCD map
pm mitigate list|apply|revert <n>  Mitigation control
pm report [--format json|md]       Export
```

Global flags: `--json`, `--no-color`, `--verbose`, `--yes`, `--evtx <path>`.

`decode` operating on a value pasted from someone else's event log — with no
access to that machine — must work. That is a core use case, not an extra.

---

## 6. Output quality

Terminal output is the product. Requirements:

- ANSI colour with automatic detection, `--no-color`, and `NO_COLOR` env support.
- Bit-field decoding rendered as an aligned table: bit position, name, value,
  meaning. Not a wall of prose.
- Always show the raw hex alongside the interpretation, so the user can verify.
- Lead with the verdict, then the evidence. Someone running `pm analyze`
  should see the conclusion in the first three lines.
- Where the tool is uncertain — ambiguous bank mapping, vendor-specific bits,
  a section GUID it doesn't recognise — say so explicitly. A confidently wrong
  diagnosis is worse than an admitted gap.

---

## 7. Testing

- Unit-test the CPER and MCA decoders against fixture blobs. Decoding must be a
  pure function over a byte buffer with no Windows dependency, so tests run
  anywhere.
- Include these real vectors from a Ryzen 9 5950X (Family 19h, Model 21h,
  Stepping 2), all Bank 5, `ErrorType 9`, `TransactionType 2`:

  ```
  MciStat 0xbea0000000000108  MciAddr 0x1fff800b3409a9a   APIC 5
  MciStat 0xbea0000000000108  MciAddr 0x7fffc45c42fe      APIC 11
  MciStat 0xbea0000001000108  MciAddr 0x7ff913a99f3b      APIC 17
  MciStat 0xbea0000001000108  MciAddr 0x7ff9a369eec3      APIC 11
  MciStat 0xbea0000001000108  MciAddr 0x1fff85925d93b31   APIC 7
  MciStat 0xbea0000000000108  MciAddr 0x7ffd4a38145e      APIC 10
  MciStat 0xbea0000001000108  MciAddr 0x1fff800c062b2a9   APIC 11
  MciMisc for all: 0xd0130fff00000000
  ```

  Expected decode for `0xbea0000000000108`: Val=1, Overflow=0, UC=1, Enabled=1,
  MiscV=1, AddrV=1, PCC=1; error code `0x0108` = memory-hierarchy error,
  TT=Generic, LL=L0/L1.

  Expected decode for `MciAddr 0x1fff800c062b2a9`: LSB field = 1, address bits
  [55:0] = `0xFFF800C062B2A9`, sign-extended = `0xFFFFF800C062B2A9`,
  classification = kernel-mode virtual address.

  Expected decode for `MciAddr 0x7ffd4a38145e`: LSB field = 0, classification =
  user-mode virtual address.

- Fuzz the CPER parser. It consumes attacker-influenceable data from a log file;
  every offset and length read from the record must be bounds-checked against
  the buffer before use. Malformed input must produce a diagnostic, never a
  crash or an out-of-bounds read.
- Integration tests against a checked-in sample `.evtx`.

---

## 8. Build order

Do these in sequence and make each one work before moving on:

1. CMake skeleton, arg parsing, `status` with CPU/BIOS/OS info.
2. Pure CPER + MCA decoder library with the unit tests from §7. No Windows deps.
3. `decode` subcommand wired to that library. **First genuinely useful milestone.**
4. Event log ingestion (live + `.evtx`), then `scan` and `show`.
5. Topology mapping, integrated into `scan` output.
6. `timeline` with multi-provider correlation and same-timestamp clustering.
7. `analyze` trend logic.
8. `mitigate` with state snapshot/revert.
9. `watch`.
10. `report`, `--redact`, README.

---

## 9. Documentation

README covering: what problem this solves, install, each subcommand with real
example output, a "how to read an MCA decode" primer, the explicit statement that
no kernel driver is used and why, and a troubleshooting section for the
"my crash produced no dump" case.

Comment the decoder heavily with spec references (UEFI spec Appendix N for CPER,
AMD PPR for SMCA, Intel SDM Vol. 3B Ch. 16 for architectural MCA). Someone
reading the code in a year should be able to check it against the spec without
re-deriving the layouts.
