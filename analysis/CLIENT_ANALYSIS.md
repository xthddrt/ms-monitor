# MapleStoryCW static client analysis

## Scope and result

The supplied path is an installed client, not a source tree. `tools/analyze_client.py` processed every file under `C:\Nexon\Library\maplestorycw` and generated `pe-inventory.json` with paths, sizes, SHA-256 hashes, headers, and native PE metadata.

| Category | Count |
|---|---:|
| Total files | 391 |
| Total bytes | 1,205,006,566 |
| Native PE images | 46 |
| PKG1 `.wz` containers | 180 |
| `.ms` packs | 2 |
| `LastWzIndex` files | 91 |

No original C/C++ source, project files, symbols, or script source files were present. This inventory is not a decompilation and does not establish the complete game logic.

## Runtime component map

### Main client

`appdata/MapleStory.exe` is a 77,923,824-byte x86-64 GUI executable. Its direct imports show integration with:

- NGS-X security through `grap64.dll`;
- Nexon overlay through `NxOverlay_x64.dll`;
- crash reporting through `CrashReporter.dll`;
- resource/SOAP support through `WzMss.dll` and compression through `ZLZ64.dll`;
- machine identification through `MachineIdLib.dll`;
- HTTP through `libcurl.dll`;
- Nexon SDK/messenger through `nexon_api_x64.dll` and `nmcogame64.dll`;
- Steam through `steam_api64.dll`;
- Win32 networking, cryptography, input, COM, DirectInput, HID, and Windows hardware APIs.

The executable exports only allocator functions and GPU-selection markers. Its size and limited exports are consistent with most game logic being internal rather than exposed as a public API. PE imports alone cannot reconstruct that logic.

### Game support libraries

The client contains rendering, canvas, audio, resource, namespace, PCOM, compression, and DirectX support DLLs. `Canvas.dll`, `Gr2D_DX11.dll`, `ResMan.dll`, `Shape2D.dll`, and `Sound.dll` expose COM-style `DllGetClassObject`/`DllCanUnloadNow` entry points. `WzMss.dll` exports 20 SOAP/board-related operations. `NexonAnalytics64.dll` exports analytics and embedded cJSON APIs. `nmconew64.dll`, `nmcogame64.dll`, and `nps64.dll` implement messenger and survey integration. These are useful boundaries for later reversing work, but exported names do not prove call flows.

### Overlay and crash helpers

`NxOverlay/DwarfAxe.exe` imports CEF (`libcef.dll`) and `CrashReporter_64.dll`, making it a separate browser/rendering process to monitor. `CrashReportClient.exe` is another independent executable. `NxOverlay_x64.dll` exports DirectX overlay and screenshot functions. CEF resources include locale packs, V8 snapshots, ICU data, EGL/GLES libraries, and SwiftShader.

### Nexon security

`grap64.dll` identifies itself as NGS-X 1.5.3.1. `grap/NGService.exe` is a 32-bit Nexon Game Security service; the two batch files only invoke its `-install` and `-uninstall` options. `grap/BlackCat64.sys` is the NGS-X kernel driver. The monitor does not replace, hook, hide, disable, or bypass these components.

The `.aes` suffix does **not** mean these three payloads are merely encrypted data: `grap-core64.aes`, `grap-communicator64.aes`, and `grap-updater.aes` all have valid PE headers and are included among the 46 native images. Their limited exports indicate that deeper static reversing would be a separate, substantial effort. The GRAP log files are not normal UTF-8/UTF-16 text; no claim is made that their encoding or encryption has been decoded.

## Data formats

All 180 `.wz` files begin with `PKG1`. The sampled header contains a declared file size, a 60-byte header, and the banner `Package file v1.0 Copyright 2002 Wizet, ZMS`. The inventory records those fields for every container. Directory/property decoding, encryption selection, image/audio extraction, and semantic interpretation remain unimplemented.

The 91 `.ini` files are not Windows INI sections; each is a single `LastWzIndex|N` record. `Data/Packs/digest.md5` lists the two `.ms` packs. Those packs have no recognizable plain-text header in the sampled bytes and are classified as opaque containers, not decoded content.

## Recommended reversing workflow

1. Preserve the generated inventory and hashes so analysis is tied to this exact client build.
2. Import `MapleStory.exe` into Ghidra and apply full analysis, then work outward from the documented DLL boundaries. Do not expect automatic decompilation to recover original names or complete behavior.
3. Use `ResMan`, `Canvas`, `ZLZ64`, and the PKG1 reader as the resource-loading track; use `libcurl`, `WzMss`, Nexon SDK, and analytics boundaries as the network track; use `NxOverlay_x64` and CEF as the overlay track.
4. Correlate dynamic file, registry, module, process, and network metadata from `msmon-agent` with static functions. Network endpoints do not reveal application-level packet meaning, and this project does not intercept TLS plaintext.
5. Document conclusions with evidence levels: direct disassembly, observed runtime behavior, or inference. Do not treat PDB paths, imports, or encrypted/encoded artifacts as proof of complete logic.

## Practical conclusion

The monitor can provide broad application-scoped OS telemetry across the game and helper processes. Fully decoding the actual game logic is not achievable from this directory in a single pass, particularly without symbols and with protected security components. The generated inventory is a reproducible starting point for that longer reversing project, not a substitute for it.
