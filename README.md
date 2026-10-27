# ms-monitor

Application-scoped Windows telemetry for the MapleStoryCW client, with a WDM kernel driver, a Win32 JSONL collector, and a reproducible static inventory of the supplied installation.

The monitor observes `MapleStory.exe`, its descendants, and the Nexon security, overlay, and crash helpers. It does not inject code, bypass GRAP/Nexon security, disable driver signing, capture credentials, read file contents, or decrypt network traffic.

## What it captures

| Source | Events |
|---|---|
| Process callbacks | process start/exit, parent PID, creation time, image and command line when available |
| Thread callbacks | thread create/exit and owning PID |
| Image callbacks | module path, base address, and size |
| Filesystem minifilter | create/open, read/write offsets and lengths, file-information changes |
| Registry callbacks | open/create, value set/query, enumeration, delete, and rename metadata |
| Windows Filtering Platform | IPv4/IPv6 connect and receive/accept endpoints, protocol, ports, and PID |

This is broad OS telemetry, not a guarantee of every instruction, UI action, IPC message, or application-level decision. See `docs/ARCHITECTURE.md` for limitations and `analysis/CLIENT_ANALYSIS.md` for what the installed files actually establish.

## Build

Requirements: Visual Studio 2022 with MSVC and the Windows Kernel Mode Driver toolset, plus Windows SDK 10.0.26100.

```bat
build.cmd
```

Outputs:

- `build\Release\driver\msmon.sys`
- `build\Release\driver\msmon.inf`
- `build\Release\agent\msmon-agent.exe`

The default build is unsigned development output. Do not load it on a production machine. Use the isolated test-VM procedure in `docs/TEST_VM.md`; no driver was installed or loaded while developing this repository.

## Collect

Run elevated after properly signing and starting the driver in the test VM:

```bat
msmon-agent.exe --output session.jsonl
```

Options:

- `--pid PID` tracks an additional existing process explicitly;
- `--wait-ms N` sets the empty-queue wait, capped by the driver at 30 seconds;
- `--max-file-mb N` rotates output after the threshold, with a continuing hash chain;
- `--once` performs one read and exits.

Every line has a SHA-256 chain over the previous chain and the event JSON. Sequence gaps and driver drop counters make queue loss visible. Validate one or more rotated logs, in order:

```bat
python tools\verify_log.py session.jsonl session.jsonl.1
```

## Static client inventory

The analysis script requires Python and `pefile`:

```bat
python tools\analyze_client.py C:\Nexon\Library\maplestorycw analysis\pe-inventory.json
```

The committed inventory covers all 391 supplied files and 46 PE images, including the PE-formatted GRAP `.aes` payloads. No proprietary client binaries are included in this repository.

## Safety and privacy

Use only on systems and software you are authorized to inspect. Logs contain command lines, paths, registry activity, process relationships, and network endpoints. Restrict access, define a retention period, and avoid monitoring unrelated PIDs. The control device is intended for elevated collection, and the driver is not hidden or hardened against tampering.
