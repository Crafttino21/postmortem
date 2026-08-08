# postmortem

a windows cli tool made to debug and troubleshoot AMD Ryzen Zen3 CPUs, but can also be used for other CPU generations. An exact list of supported CPUs will come at some point.

## Will there be Linux support?
At some point, when I have the time and the mood, I plan to add Linux support and expand general debug functions for other CPU generations and manufacturers. The ZEN 3 generation is currently mainly supported by AMD


## The main problem it is supposed to solve or find

A machine resets every week or two. There is no blue screen, no minidump, and
nothing in `C:\Windows\Minidump`. Event Viewer shows Kernel-Power 41 with
`BugcheckCode 0`, which tells you only that Windows never got as far as
bugchecking.

The one piece of real evidence is a `Microsoft-Windows-WHEA-Logger` Event ID 18
containing a CPER blob, which Event Viewer renders as an unreadable wall of hex.
Extracting a diagnosis from it by hand means decoding the CPER header, walking
the section descriptors, decoding the IA32/X64 Processor Error section, taking
`MCA_STATUS` apart bit by bit, un-mangling `MCA_ADDR` (it is not a flat address
on AMD), mapping APIC IDs to physical cores, and correlating the whole thing
against the Kernel-Power, Kernel-Boot and EventLog timestamps around it.

That entire process is what this tool automates.

```
> pm analyze

Verdict

  Evidence points at a fixed marginality rather than a failing part:
  uncorrectable machine checks at a steady rate, scattered addresses, no
  single dominant core. The usual causes are core voltage or fabric/memory
  timing under light load. This is a weighing of evidence, not a diagnosis.
```

## Install

Copy `pm.exe` anywhere and run it. There is no installer and no runtime to
deploy: the C++ runtime is linked statically, so the only DLLs it needs are
ones Windows already has.

```
> dumpbin /DEPENDENTS pm.exe
    SHELL32.dll
    ADVAPI32.dll
    KERNEL32.dll
    POWRPROF.dll
    WEVTAPI.dll
    ole32.dll
```

Reading is a standard-user operation. Only `pm mitigate apply` and
`pm mitigate revert` need an elevated prompt, and they say so rather than
failing obscurely.



## Commands

```
pm status                          System snapshot
pm scan [--since 90d] [--evtx F]   Decode all WHEA records
pm scan --records                  Every raw record, one row each
pm scan --group-by event,bank,apic Frequency tally, most frequent first
pm show <n>                        Full decode of one incident, all sections
pm timeline [--since 90d]          Merged crash timeline
pm analyze                         Trend analysis + evidence-weighted verdict
pm watch [--log F] [--exec CMD]    Live subscription
pm decode --cper <hex|@file>       Decode a CPER blob standalone
pm decode --mci-stat 0xbea...      Decode a single MCA register value
pm topology                        APIC -> core/thread/CCD map
pm live [--interval 1s]            Live view of what the CPU is doing
pm live --stacks                   Live sampled call stacks (elevated)
pm watch-mem --pid P --at ADDR     Live byte view of a process's memory
pm mitigate list|apply|revert <n>  Mitigation control
pm report [--format json|md]       Export
```

Global flags: `--json`, `--no-color`, `--verbose`, `--yes`, `--evtx <path>`.

Colour is enabled when stdout is a console and disabled when it is a pipe;
`--no-color` and the `NO_COLOR` environment variable both override.

### `pm status`

What the machine is, and what state its crash forensics are in.

```
CPU
  Brand                  AMD Ryzen 9 5950X 16-Core Processor
  Vendor                 AuthenticAMD (AMD)
  Family / Model / Step  0x19 / 0x21 / 0x2  decimal 25 / 33 / 2, CPUID.1 EAX = 0x00A20F12
  Cores / Threads        16 / 32
  Microcode              0x0A201210
  Nominal clock          3400 MHz  firmware-reported base clock, not a live measurement
  Hypervisor             not present

Firmware
  BIOS vendor    American Megatrends Inc.
  BIOS version   3611
  BIOS date      09/29/2024
  Board          ASUSTeK COMPUTER INC. ROG STRIX B550-F GAMING Rev X.0x
  SMBIOS         3.3

Operating system
  Product    Windows 11 Pro 25H2  edition Professional
  Build      26200.8875  version 10.0
  Installed  2025-12-02 20:21:16  local time
  Booted     2026-08-08 13:46:22  local time
  Uptime     1h 42m
```

### `pm scan`

Every WHEA record in the range. An uncorrectable machine check is broadcast to
every core, so one fault writes one record per processor; those are collapsed
into a single incident with N reporting cores rather than listed N times.

```
> pm scan --since 90d

WHEA records from the live System log

  8 incidents, 8 unrecoverable with processor context corrupt.

  #  When                 Severity  Cores  Banks  Records  Note
  1  2026-06-06 17:56:01  FATAL     5      5      1
  2  2026-06-13 19:46:38  FATAL     11,17  5      2
  3  2026-06-26 20:38:52  FATAL     11     5      1
  4  2026-06-28 23:47:58  FATAL     7      5      1
  5  2026-07-04 18:22:54  FATAL     10     5      1
  6  2026-07-16 20:09:00  FATAL     11,18  5      2
  7  2026-07-25 19:57:39  FATAL     10,18  5      2
```

Records timestamped shortly after a boot are flagged. MCA banks survive a warm
reset, so Windows harvests them on the way up: a record written 19 seconds
after boot describes the crash that ended the *previous* session, not anything
that happened after this one started.

#### `--records` — every raw record, uncollapsed

Sometimes the folding is the wrong thing and you want the log as it stands:

```
> pm scan --records

  #   When                 APIC  Bank  MciStat             MciAddr             Type  Class
  1   2026-06-06 17:56:01  5     5     0xBEA0000000000108  0x01FFF800B3409A9A  9     kernel VA
  2   2026-06-13 19:46:38  11    5     0xBEA0000000000108  0x00007FFFC45C42FE  9     user VA
  3   2026-06-13 19:46:38  17    5     0xBEA0000001000108  0x00007FF913A99F3B  9     user VA
```

Eleven rows where `pm scan` shows eight incidents — rows 2 and 3 are one
broadcast fault. This replaces the `Get-WinEvent | Select-Object` pipeline you
would otherwise write by hand, and adds the address classification, which the
raw `EventData` cannot give you.

#### `--group-by` — frequency tally

The equivalent of `Group-Object … | Sort-Object Count -Descending`, over fields
the tool has already decoded:

```
> pm scan --group-by event,bank,apic

  Count  Share  Event  Bank  APIC  First seen           Last seen
  4      36%    18     5     11    2026-06-13 19:46:38  2026-08-08 13:46:35
  2      18%    18     5     10    2026-07-04 18:22:54  2026-07-25 19:57:39
  2      18%    18     5     18    2026-07-16 20:09:00  2026-07-25 19:57:39
  1      9%     18     5     17    2026-06-13 19:46:38  2026-06-13 19:46:38
```

| Field | Groups by |
|---|---|
| `apic` `bank` `event` `type` `transaction` | the raw EventData fields |
| `status` | the whole `MCA_STATUS` value |
| `code` | `MCA_STATUS[15:0]`, the compound error code |
| `address` `page` | the address, or the 4 KiB page it falls in |
| `class` | user VA / kernel VA / physical |
| `severity` | corrected, uncorrected, fatal |
| `day` `hour` | calendar day or hour of day, local time |

Combine them with commas. The decoded fields are where this beats a PowerShell
pipeline: `--group-by page` answers "do the faults cluster in one page" in one
command, and `--group-by status` separates register values that differ only in
their model-specific half.

Both views honour `--json`, `--since` and `--evtx`.

### `pm show <n>`

The full decode of one incident: every record, the MCA registers bit by bit,
and every CPER section. `--verbose` adds the raw hex of each section and the
original event XML.

### `pm timeline`

The merged, multi-provider view. WHEA records, Kernel-Power 41, BugCheck 1001,
EventLog 6008, Kernel-Boot, Kernel-General and Kernel-Processor-Power, grouped
into boot sessions.

```
  When                 Kind      What
                                 --- boot session 4 ---
  2026-06-26 17:42:46  boot      operating system started
  2026-06-26 17:42:49  throttle  processor power management reported a limit  (x32)
                                 --- boot session 5 ---
  2026-06-26 20:38:33  boot      operating system started
  2026-06-26 20:38:36  reset     the system rebooted without cleanly shutting down, and no bugcheck code was recorded
  2026-06-26 20:38:51  dirty     the previous system shutdown was unexpected
  2026-06-26 20:38:52  WHEA      unrecoverable machine check, processor context corrupt, reported by 1 core; no bugcheck and no crash dump was possible
```

Session 4 simply stops. Session 5 opens with the reset notice, the dirty
shutdown, and the WHEA record harvested from the previous session's banks
nineteen seconds after boot. That sequence is the whole story of one crash.

Events that fire once per logical processor are collapsed with an `(xN)`
marker; without that, 32 identical throttle notices bury everything else.

### `pm analyze`

The verdict first, then the evidence, each finding with its own reasoning and a
confidence level. It will say when it does not have enough data:

```
  [weak] there are too few incidents to judge the trend
      At least five incidents are needed before an accelerating and a flat
      rate can be told apart. Until then, no claim about degradation is
      supportable.
```

### `pm decode`

The command that works with no access to the affected machine. Paste a value
from someone else's event log and it decodes:

```
> pm decode --mci-stat 0xbea0000000000108 --mci-addr 0x1fff800c062b2a9 --vendor amd

MCA_STATUS  0xBEA0000000000108

  unrecoverable, processor context corrupt; the CPU resets immediately, so no
  bugcheck and no crash dump is possible

Architectural bits
  Bit  Name      Value  Meaning
  63   Val       1      this bank holds a valid error record
  62   Overflow  0      no errors were lost
  61   UC        1      the error was not corrected by hardware
  60   Enabled   1      reporting was enabled for this error
  59   MiscV     1      MCA_MISC holds valid information
  58   AddrV     1      MCA_ADDR holds a valid address
  57   PCC       1      processor context is corrupt; execution cannot resume

Error code  0x0108  memory hierarchy error
  Encoding: 0000 0001 RRRR TTLL

  Field                  Value   Meaning
  Request (RRRR)         0b0000  ERR - generic error, request type not specified
  Transaction type (TT)  0b10    Generic
  Cache level (LL)       0b00    L0 (nearest the core, usually the L1 cache)
```

Input handling is deliberately forgiving, because the input is whatever the
other person pasted:

- `--cper` takes hex, base64, or `@path` to a file. Whitespace, `0x` prefixes
  and commas are stripped, so text copied straight out of Event Viewer's
  Details pane works. If a string could be read as either hex or base64, the
  record's own `CPER` signature decides, and the output states which was used.
- `--mci-stat` and friends take `0x…` as hex, `0b…` as binary, and plain digits
  as **decimal**, because that is what Event Viewer's friendly view shows.
  A value that would not fit in 64 bits is rejected rather than wrapped.
- `--vendor amd|intel` decides how `MCA_ADDR` and the vendor-specific status
  bits are read. Left off, the AMD SMCA layout is assumed and said to be
  assumed.

`--walk` steps through a CPER record field by field instead of printing the
finished decode, showing each byte offset as it is consumed:

```
> pm decode --cper @record.bin --walk

  Offset  Len  Field             Value                                 Means
  0x0000  4    SignatureStart    CPER                                  valid
  0x000A  2    SectionCount      4
  0x0018  8    Timestamp (BCD)   0x2026080801150421                    2026-08-08 15:04:21
  0x0090  16   SectionType       dc3ea0b0-a144-4797-b95b-53fa242b6e1d  IA32/X64 Processor Error
  0x01A0  8      ValidationBits  0x000000000000017F                    APIC id valid, CPUID valid,
                                                                       [7:2] error-info count = 1
  0x01B0  8      CPUVersion      0x0000000000A20F12                    family 0x19, model 0x21, stepping 2
```

On a console it is interactive — `space`/`n` step, `p` back, `a` auto-advance,
`q` quit — and the hex dump marks the current field's bytes with a caret rule
underneath. Redirected, you get the whole listing at once.

The offsets are not a second copy of the layout tables: the decoder records
each field *as it reads it*, so what the walk highlights is literally what was
consumed. A test asserts that the traced and untraced decodes are identical.

### `pm live`

Watch what the CPU is doing, refreshing until you stop it.

```
> pm live

AMD Ryzen 9 5950X 16-Core Processor   nominal 3400 MHz   up 4h 29m
2026-08-08 18:15:26   1.0s refresh   ETW: on

 CPU   MHz   Perf  Load                        C1    C2    C3   Park   IRQ/s  DPC/s   CSw/s
   0   4779   141%  #.......................    0%   97%    0%    no    1.6k    497    3.1k
   1   4771   140%  ########################    0%    2%    0%    no    2.1k   3.2k    8.4k
   2   4441   131%  #.......................    0%   86%    0%    no    2.9k    310    2.2k

 Package load 14%    deep idle 18/32    parked 0
 Deep idle is what the BIOS-level fixes in 'pm mitigate list' target.

WHEA feed
 no machine check since this view started (8 already in the log)
```

Keys: `q` quit, `space` pause, `s` sort by load, `r` reset the feed.

The C-state columns are the reason this exists. The spec's thesis is
idle-state instability, and `analyze` can only infer that statistically after
the fact. Here you can watch cores sink into C2/C3 and see whether a machine
check lands at that moment — the WHEA feed at the bottom is a live
subscription, so a record appears the instant Windows writes it.

`MHz` is derived from `% Processor Performance` against the nominal clock, not
from the `Processor Frequency` counter — that counter is documented as the
slowest processor's frequency and in practice reports a static value.

Run **elevated** and it additionally starts an ETW kernel session, adding real
per-core context-switch, interrupt and DPC counts rather than sampled rates.
Without elevation it says so and shows the rest; `--no-etw` skips it entirely.

**What it cannot show:** the executed instruction stream, register contents, or
bus traffic. Watching instructions needs Intel PT or AMD IBS, and reading
registers needs MSR access — both require a kernel driver, which this tool does
not use. Actual bus traffic needs a logic analyzer on the board. Everything in
`pm live` comes from documented user-mode APIs: PDH counters,
`CallNtPowerInformation`, ETW and `EvtSubscribe`.

#### `--stacks` — live sampled call stacks

With `--stacks` (elevated), the ETW session additionally turns on sample-based
profiling with stack tracing. The kernel captures a full call stack **inside
the profiling interrupt**, so nothing is ever suspended:

```
> pm live --stacks

Hottest stacks   4180 samples this interval   kernel 62%  user 38%

    1204   29%  System (0)
                ntoskrnl!KiIdleLoop
                  ntoskrnl!KiIdleSchedule
     418   10%  myapp.exe (4812)
                myapp!compute_hash+0x2c
                  myapp!worker_loop+0x118
                    kernel32!BaseThreadInitThunk+0x1d
```

Innermost frame first, each deeper frame indented. `--verbose` shows 12 frames
per stack instead of 5. Kernel frames are highlighted.

Symbols come from DbgHelp using whatever is available locally — a PDB beside
the binary, or the module's export table. **No symbol server is contacted**, so
the view never stalls downloading PDBs; frames with no symbol read as
`module+0x1a2c40`, and the display says so when nothing could be named.

Symbolisation happens on the render thread, never in the ETW callback: a
DbgHelp lookup is orders of magnitude slower than the sampling rate and would
drop buffers.

### `pm watch-mem`

A live hex view of another process's memory, highlighting bytes as they change.

```
> pm watch-mem --pid explorer --at 0x7FFE0000 --len 48 --interval 300ms

explorer.exe (14700)   0x000000007FFE0000   48 bytes
2026-08-08 19:15:51   tick 8

  Offset    Bytes
  7FFE0000  00 00 00 00 00 00 A0 0F  33 47 81 07 2E 00 00 00  ........3G......
  7FFE0010  2E 00 00 00 33 8D 57 90  59 27 DD 01 59 27 DD 01  ....3.W.Y'..Y'..
  7FFE0020  00 30 77 3C EF FF FF FF  EF FF FF FF 64 86 64 86  .0w<........d.d.

  6 byte(s) changed this tick, 8 of 48 have ever changed
  red = changed this tick, yellow = changed earlier, ?? = not readable
```

That address is `KUSER_SHARED_DATA`, mapped into every process, and the six
moving bytes are its interrupt-time and system-time fields — a good way to
check the view is working.

Finding an address:

```
pm watch-mem --pid notepad --regions        list the committed regions
pm watch-mem --pid 4812 --at 0x7FF6A2C10000 --len 256
pm watch-mem --pid myapp --module myapp.exe --offset 0x1000
```

`--pid` takes a process id or an executable name; an ambiguous name lists the
candidates rather than picking one. Keys: `q` quit, `space` pause, `r` reset
the change history.

**The target is never suspended and nothing is ever written to it.** Because it
keeps running while being read, a multi-byte value can be caught mid-write and
read torn — you see a state the memory genuinely passed through, just not
necessarily one the program meant to be observable. Protected and
higher-integrity processes refuse to open at all, elevated or not.

### `pm mitigate`

Six named mitigations, each with `list`, `apply` and `revert`.

| Name | What it does |
|---|---|
| `max-cpu-99` | Caps the maximum processor state at 99%, disabling boost |
| `min-cpu-100` | Holds the minimum processor state at 100%, keeping cores out of deep idle |
| `idle-disable` | Disables processor idle states entirely |
| `idle-promote` | Raises the idle promote threshold |
| `dumps-on` | Kernel memory dump on, auto-reboot off |
| `nmi-dump` | Crash-on-NMI and Ctrl+Scroll-Lock on |

`list` shows each mitigation's current state and its cost, because every one of
them costs something.

Nothing changes without either an interactive confirmation or `--yes`. Before
each change the current value is snapshotted to
`%ProgramData%\postmortem\state.json` with a timestamp, written atomically, and
`revert` restores **from that snapshot** — never from a hardcoded default. If
there is no snapshot, `revert` refuses:

```
pm: no snapshot for 'max-cpu-99' - it was never applied by this tool, and
    reverting from a guessed default would be a second unannounced change
    rather than an undo
```

After applying `max-cpu-99` the tool samples actual core frequencies and warns
if they still exceed the cap: on builds where CPPC drives frequency,
`PROCTHROTTLEMAX` is silently ignored, and a mitigation that quietly did
nothing is worse than none.

`pm mitigate list` also prints the BIOS-level settings that cannot be changed
from Windows but which are the actual fix for an idle-instability pattern —
Power Supply Idle Control, Global C-State Control, PBO and Curve Optimizer —
including where they usually live in the menus.

### `pm report`

`--format md` produces something you can paste into a forum thread or a support
ticket, with the raw register values preserved so the reader can re-verify the
decode. `--format json` produces a stable, versioned schema suitable for
diffing two reports weeks apart.

`--redact` replaces the board model, hostname, user names and serial numbers
before you share it.

## How to read an MCA decode

`MCA_STATUS` is one 64-bit register. The top seven bits are architectural and
mean the same thing on Intel and AMD:

| Bit | Name | Meaning when set |
|---|---|---|
| 63 | Val | This bank holds a valid record |
| 62 | Overflow | Another error arrived and was lost before this was read |
| 61 | UC | Hardware could not correct it |
| 60 | Enabled | Reporting was enabled for this error |
| 59 | MiscV | `MCA_MISC` holds something meaningful |
| 58 | AddrV | `MCA_ADDR` holds a valid address |
| 57 | PCC | Processor context is corrupt |

The combination that matters is **UC=1 with PCC=1**. It means the CPU could not
continue and reset itself. That is precisely why the crash left no bugcheck and
no dump: by the time Windows could have written one, the processor had already
restarted. If you are chasing a machine that reboots with no evidence, this bit
pair is the evidence.

`UC=1, PCC=0` is different: the context survived, so Windows can bugcheck, and
you should expect a `0x124 WHEA_UNCORRECTABLE_ERROR` and a dump.

Bits `[15:0]` hold a compound error code. `0x0108` matches
`0000 0001 RRRR TTLL`, a memory-hierarchy error, with `RRRR=0000` (generic),
`TT=10` (generic transaction) and `LL=00` (level 0 — the encoding counts
outward from the core, so level 0 is the L1 cache).

`MCA_ADDR` on AMD SMCA parts is **not a flat address**. Bits `[61:56]` are an
LSB field naming the least significant *valid* bit, and bits `[55:0]` are the
address, which sign-extends from bit 47 into a canonical x86-64 address. So
`0x1fff800c062b2a9` is not an address near 2^57; it is LSB field 1 plus
`0xFFF800C062B2A9`, sign-extending to `0xFFFFF800C062B2A9` — a kernel-mode
virtual address. Reading it flat would put the fault in a completely different
place.

The tool classifies the result by checking whether bits `[55:48]` actually
agree with bit 47. If they do, it is a canonical virtual address, user-mode or
kernel-mode. If they do not, it cannot be a virtual address at all and is
reported as a physical address or a structure index.

## Troubleshooting: "my crash produced no dump"

Work through these in order.

**1. Is a dump even configured?** `pm mitigate list` shows the current
`CrashControl` state. "small memory dump (minidump), auto-reboot on" is the
Windows default and is nearly useless for this: a minidump omits the kernel
memory you would need. `pm mitigate apply dumps-on` switches to a kernel memory
dump and stops the automatic reboot.

**2. Is there a pagefile on the system volume?** Windows writes the crash dump
into the pagefile and moves it on the next boot. A machine with the pagefile
moved to another drive, or disabled, cannot write one at all.

**3. Does Kernel-Power 41 report `BugcheckCode 0`?** Run `pm timeline`. If the
code is zero, no amount of dump configuration will help — Windows never reached
the bugcheck. That is the case this tool exists for, and the next step is
`pm scan` rather than dump settings.

**4. Is there a WHEA record at all?** If `pm scan` finds uncorrectable machine
checks with PCC set, the CPU reset itself and no software-side setting can
capture more. If it finds *nothing*, the evidence points away from the CPU
entirely: power delivery, the PSU, or a board-level fault, none of which leave
software traces.

**5. Is the machine hanging rather than resetting?** A hang leaves no event at
all. `pm mitigate apply nmi-dump` enables Ctrl+Scroll-Lock so you can force a
bugcheck by hand and get a dump out of an otherwise silent hang.

## Building

```
cmake --preset debug && cmake --build --preset debug
ctest --preset debug --output-on-failure
```

Requires CMake 3.20+, the MSVC toolchain and C++20. x64 only — the MCA and CPER
decoding is x86-specific, so the build refuses any other architecture at
configure time, and an x64 binary running under emulation on an ARM64 host
refuses at startup.

A Visual Studio solution (`postmortem.slnx`) is kept in step with the CMake
build for IDE use. If you add a source file, add it to both, and keep every
`.cpp` basename unique across the repository: MSBuild puts all object files of
a project in one flat directory.

The `.vcxproj` files live in `postmortem/vs/` rather than beside `src/`.
Visual Studio offers every file under a project's directory as something to add
to that project, and it repeatedly swept `tests/*.cpp` into `pm.exe` — which
broke the link with *"main ist bereits in main.obj definiert"*, because
`tests/test_main.cpp` carries the test runner's own `main()`. With the project
files in a directory of their own, there is nothing beside them to sweep.

### Layout

```
src/core/       no Windows headers - decoders, parsers, rendering, CLI
src/platform/   everything that touches Win32
src/commands/   one file per subcommand
tests/          links core only, which is what enforces the split
vs/             Visual Studio project files, deliberately isolated
```

`postmortem_tests` links `postmortem_core` and nothing else. If a
`<windows.h>` ever creeps into `core/`, the test target stops linking — the
platform-independence rule is enforced by the build, not by review.

## Dependencies

None beyond the Windows SDK. The JSON writer, JSON reader and XML reader are
hand-rolled, each a few hundred lines. That is a deliberate trade: the
documents involved are our own, flat and small; the alternative is vendoring
tens of thousands of lines into a tool whose main virtue is being a single
copyable executable with no install step. The XML reader in particular only
needs the subset the Windows event schema emits, and rejects anything else
rather than guessing.

## Where the decoders are uncertain

A confidently wrong diagnosis is worse than an admitted gap, so the tool marks
what it is unsure of rather than smoothing over it:

- **`MCA_STATUS[56:53]`** is decoded with the AMD SMCA names
  Deferred/Poison/TCC/SyndV, but AMD assigns these per family. The values are
  correct; the labels are flagged as provisional and should be checked against
  the PPR for your family.
- **The Micro-Architectural check structure** places its fields at `[23:16]`
  rather than the `[28:16]` used by the cache, TLB and bus checks. This is
  flagged for verification against UEFI Appendix N.
- **Model-specific error codes** in `MCA_STATUS[31:16]` are reported raw. Their
  meaning is vendor- and family-defined and the tool does not guess.
- **Unrecognised CPER section GUIDs** are never dropped. The GUID, the length
  and a hex dump are emitted so nothing is hidden, and parsing continues.

Every layout in the decoders carries a spec reference in a comment: UEFI
Specification Appendix N for CPER, Intel SDM Vol. 3B ch. 16 for architectural
MCA, and the AMD PPR/APM for the SMCA additions.
