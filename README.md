# SchoolsOutPatch

Windows x64 patch package for the Rec Room client build
`20260323.01`. It redirects configured backend hostnames,
allows a public voice RSA key, suppresses an image-signature check and a DUID
mismatch check, and keeps the client alive through the managed quit paths that
were observed on the target build.

This repository contains source and build scripts. It does **not** contain a
server, a private key, a configured hostname, or game files.

## Package boundary

`build.cmd -Package` produces
`x64\Release\SchoolsOutPatch.zip` with exactly these five files:

- `2026patch.dll`
- `Injector.exe`
- `2026patch.ini`
- `RecRoomScreen.bat`
- `RecRoomVR.bat`

The bundled `2026patch.ini` is a blank template: `ApiHost` and `VoiceKeyXml`
are empty. Do not commit a configured INI or any private key.

## Requirements

- Windows x64.
- Visual Studio C++ x64 build tools (the build discovers them with `vswhere`).
- PowerShell 5.1 or newer.
- The target game build listed above. Other builds are not supported; the
  hard-coded RVAs and module hashes will not match.

The build compiles vendored MinHook as C and first-party C++17 sources with
`/W4 /O2 /MT /EHsc`. MinHook is vendored under
`2026Patch/src/Utils/deps/minhook`.

## Source layout

- `2026Patch/src/main.cpp` — DLL entry, early native Referee patches, hook
  startup.
- `2026Patch/src/RR/Config.h`, `NetworkConfig.h` — INI parsing and host
  rewriting.
- `2026Patch/src/RR/Methods.h`, `Offsets.h` — managed and native RVAs.
- `2026Patch/src/RR/Patches.cpp` — MinHook hooks, quit fixes, HTTP diagnostics.
- `Injector/injector.cpp` — debugger-based injection, session fix, detach.
- `build.ps1`, `build.cmd` — build/package entry points.
- `verify.ps1` — static source and package validation.
- `AGENTS.md`, `CLAUDE.md` — technical and AI-readable rules.

## Build

From the repository root:

```bat
build.cmd
```

This compiles `2026patch.dll` and `Injector.exe` into `x64\Release`.

To also produce the five-file drop-in ZIP:

```bat
build.cmd -Package
```

To build with a custom configuration file and/or a public voice key:

```bat
build.cmd -Package -ConfigurationFile .\my-config.ini -TachyonPublicKey .\public-key.xml
```

`VoiceKeyXml` accepts only public RSA `Modulus` and `Exponent`. Private fields
(`D`, `P`, `Q`, `DP`, `DQ`, `InverseQ`) are rejected by both the build and the
injector config check. Key contents are never logged.

## Verify

Static verification does not install, launch, or modify the game:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

To include the installed-folder fingerprint check:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1 -GameRoot "C:\path\to\game"
```

Verification checks the ZIP allowlist, INI keys, blank default configuration,
public/private key handling, launcher arguments, and the required source RVAs.

## Install

The developed target folder on this machine is:

```text
C:\Users\YourUser\Path\To\RecRoom
```

When deploying to another machine, use that machine's equivalent game folder.
Copy **only** these non-INI files from the package:

- `2026patch.dll`
- `Injector.exe`
- `RecRoomScreen.bat`
- `RecRoomVR.bat`

Never overwrite an existing `2026patch.ini`; it is user-configured. The bundled
INI is for a fresh install only. Never replace the real, roughly 62 MB
`Referee.dll` with a stub or patched copy. `Referee.dll` is patched only in
memory at runtime.

## Launch

Use only the provided launchers or the injector:

```bat
RecRoomScreen.bat
RecRoomVR.bat
Injector.exe --launch
```

Never launch `Recroom_Release.exe` directly. The injector starts
`RecRoom.exe` under a debugger with `DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS`,
injects through the initial breakpoint, applies the runtime session fix,
detaches cleanly, and waits for exit.

`RecRoomScreen.bat` preserves
`+forcemode:screen -screen-width 1280 -screen-height 720 -screen-fullscreen 1`.
`RecRoomVR.bat` preserves `+forcemode:vr`. Custom launch arguments are passed
through `SCHOOLSOUT_GAME_ARGS`.

### Quit fixes (on by default)

| Environment variable | Default | Effect |
| --- | --- | --- |
| `SCHOOLSOUT_TRACE_QUIT` | on | Logs managed and window quit paths with caller/stack details. |
| `SCHOOLSOUT_SUPPRESS_CHEAT_QUIT` | on | Suppresses the `0x1FC85836` fatal quit from `CheatManager.HRZIGTNFSHP.DCDTOGTESYJ`. |
| `SCHOOLSOUT_SUPPRESS_EXIT_STATE` | on | Suppresses `PreparingToExit`/`ReadyForExit` transitions from `OTBCUXXIPTI.UQNYTEAMCXI`; `Running` passes through. |

Both batch launchers explicitly set all three to `1`. To opt out, set the
variable to `0` before launching, for example:

```bat
set SCHOOLSOUT_SUPPRESS_EXIT_STATE=0
```

## INI keys

One `[config]` section is required.

| Key | Meaning |
| --- | --- |
| `ApiHost` | Bare `host[:port]` or full `http(s)` origin; redirects `ns.rec.net`. Blank keeps the original discovery origin. |
| `EnableSslPinning` | `true` enables a domain-scoped SSL pinning bypass. `DisableCertificatePinning` is accepted only as an inverted migration alias. |
| `VoiceKeyXml` | Public RSA XML with only `Modulus` and `Exponent`. Blank keeps the client key. Private fields are rejected. |
| `AllowUnsignedImages` | `true` accepts images not signed by the retired official image service. |
| `SuppressDuidMismatch` | `true` forces the DUID mismatch result to false. |
| `ServerDomain` | Optional scope for the TLS bypass; defaults to the `ApiHost` host. |
| `EnableTracing` | `true` enables extra hook diagnostics. Default `false`. |

Logs are written beside the DLL and injector as `2026patch.log` and
`Injector.log`. Game-side Referee status is in
`C:\ProgramData\Referee\Referee.Game.log`; Unity logs are under
`AppData\LocalLow\Against Gravity\Rec Room\Player.log`. HTTP/SignalR diagnostics
log only scheme, host, address family, and rewrite state. URLs, paths, queries,
headers, credentials, device IDs, and key contents are never logged.

## Safety notes

- Gate and arena patches are intentionally disabled. MinHook is used for
  managed hooks.
- The authoritative check RVAs are evidence only: `0x708490`, `0x708950`, and
  `0x21ED370`.
- Session initialization is fixed at runtime by clearing
  `OBJECT_ATTRIBUTES.SecurityDescriptor` and `ObjectName` at the resolved
  `ntdll!NtCreateSection`. No Referee code or on-disk file is modified.
- No hardware breakpoints remain armed after debugger detach; software
  breakpoints are restored.
- The build does not install, launch, start a server, or perform gameplay
  validation. Installation and launch are separate, explicit steps.

## Repository hygiene

Commit source, scripts, blank default INI, and documentation only. Do not
commit `x64\Build`, `x64\Release`, ZIPs, logs, configured INIs, keys, or game
files. This source tree is published at:

```text
https://github.com/Legacy95-ctrl/SchoolsOutPatch
```
