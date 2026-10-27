# Isolated test-VM procedure

The driver was compiled but **not installed or runtime-tested** during development. Do not first load it on a production host or alongside an active game session.

## Prepare

1. Use a disposable Windows x64 VM with a current snapshot, no production accounts, and no sensitive data. Keep networking disabled until basic load/unload testing succeeds.
2. Install Visual Studio 2022, MSVC, the WDK, and the matching Windows SDK. Build with `build.cmd`.
3. Copy `msmon.sys`, `msmon.inf`, and `msmon-agent.exe` into a test directory. Enable Windows test-signing mode using the VM's normal administrative boot configuration and reboot. Do not disable Secure Boot or third-party security software.
4. Create a test certificate, stage the package with the WDK's `Inf2Cat`, and sign the driver/catalog with `signtool` using SHA-256. Record the certificate only in the test VM's trusted store. Do not commit certificates or private keys.
5. Install the signed INF through Windows SetupAPI, or use the driver's test service entry. Confirm the minifilter instance/altitude does not conflict with other filters.

Example service management after signed installation:

```bat
sc.exe start msmon
sc.exe query msmon
msmon-agent.exe --output C:\msmon-logs\session.jsonl
sc.exe stop msmon
```

## Validation checklist

- Start the driver before the game and verify all four known helper basenames plus descendants.
- Confirm process/thread start and exit events, image paths, bases, and sizes.
- Perform controlled file reads/writes and registry operations; verify PID, path, length, offset, and value metadata without payload capture.
- Enable an isolated network and verify IPv4/IPv6 endpoints. Confirm the monitor does not alter connection policy.
- Stop the agent and driver repeatedly, including while the client is active, and check for hangs or bugchecks.
- Run Driver Verifier and controlled load/stress tests. Generate more events than the queue holds and verify sequence gaps and drop statistics.
- Validate logs with `python tools\verify_log.py <parts-in-order>` and retain the final chain separately as evidence.
- Review logs for sensitive paths or command lines before sharing them.

A successful compile is not evidence that kernel runtime behavior is safe. Production use requires the full checklist, independent driver review, and a production signing process.
