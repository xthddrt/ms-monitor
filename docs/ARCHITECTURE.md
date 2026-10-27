# Architecture and coverage

## Data path

Kernel callbacks create fixed-size, versioned `MSMON_EVENT` records. The driver assigns a monotonically increasing sequence number and queues records in a bounded nonpaged list (4,096 records). The collector waits briefly for data, drains up to 64 records per IOCTL, and writes UTF-8 JSON Lines.

If allocation fails or the queue is full, the event is lost and a drop counter increases. Sequence numbers are allocated when an event reaches the queue, so queue overflows appear as gaps. This is deliberate backpressure reporting, not lossless capture. A busy client can exceed the queue, especially with file-read and registry-query events enabled.

The agent adds a SHA-256 chain to each JSON object. A rotated file continues the preceding chain; supply all parts to `verify_log.py` in order. The chain detects accidental or later modification only when the trusted final hash is retained separately. It does not prevent a privileged attacker from rewriting the entire log.

## Process scope

New processes are tracked when their image basename is one of:

- `MapleStory.exe`
- `NGService.exe`
- `DwarfAxe.exe`
- `CrashReportClient.exe`

Children of tracked processes inherit tracking. At startup, the agent registers matching running processes and any `--pid` values. Process start time is retained to reduce PID-reuse ambiguity, although metadata sources that provide only a PID necessarily have weaker identity than a process handle. Exited processes are removed after their exit event.

Basename matching is a scope heuristic, not proof of publisher identity. For production use, add path and Authenticode publisher validation in the agent and register only verified PIDs.

## Event schema

Common fields are `protocol`, `sequence`, `timestamp`, `type`, `process_id`, `parent_process_id`, `thread_id`, `flags`, `status`, `value0`, `value1`, `text`, `detail`, and `chain`. Strings are truncated to the fixed protocol capacity; `MsMonFlagTruncatedPath` marks text truncation.

| Type | value0 | value1 | text/detail |
|---|---|---|---|
| process start | process start time | 0 | image / command line |
| image load | image base | image size | full image path |
| file create | create options | 0 | normalized path |
| file read/write | requested byte count | byte offset | normalized path |
| file information | information class | 0 | normalized path |
| registry set | data size | 0 | key path / value name |
| registry query | information class | 0 | key path / value name |
| registry enumerate | index | 0 | key path |
| network | IP protocol | local and remote ports | endpoints / direction |

## What “full capture” cannot mean here

The driver observes selected OS boundaries. It does not capture:

- every CPU instruction, function call, or in-memory state transition;
- keyboard/mouse intent, rendered content, or game-state semantics;
- file or registry value contents;
- named-pipe, ALPC, COM, or every other IPC payload;
- raw packets, TLS plaintext, or application protocol semantics;
- activity before driver startup or events dropped under overload;
- proof that a basename or PID belongs to a trusted publisher.

Adding SSDT hooks, patching the client, or bypassing GRAP would increase risk and is outside this project's design. A supported ETW/WFP extension can cover more network cases, while Ghidra analysis is required to interpret application logic.

## Reliability requirements before production use

The current deliverable is a compiled development prototype. Runtime unload races, WFP coexistence, minifilter altitude selection, stress behavior, and security-review findings must be tested in an isolated VM. A production driver needs publisher verification, configurable event filtering, a persistent loss-recovery strategy, cancellation-safe pending I/O, formal IRQL review, driver verifier/fuzz testing, and a proper signed deployment package.
