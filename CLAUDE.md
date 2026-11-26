# CLAUDE.md

AI/tool instructions for this repository. Read `README.md` and `AGENTS.md`
first, then follow these rules exactly.

## Scope and paths

- Repository root: `C:\Users\PC\Desktop\SchoolsOutPatch`.
- This directory has its own Git repository. The parent `C:\Users\PC` is a
  different repository; never publish from the parent.
- Target game build: `2026-03-31T03-05-36Z_473be467`.
- Install target on this machine:
  `C:\Users\PC\Desktop\2026-03-31T03-05-36Z_473be467`.
- Remotes: origin must be
  `https://github.com/Legacy95-ctrl/SchoolsOutPatch`.

## Build and verify

- Build: `build.cmd`
- Package: `build.cmd -Package`
- Verify: `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1`
- Optional install fingerprint check: add
  `-GameRoot "C:\Users\PC\Desktop\2026-03-31T03-05-36Z_473be467"`.
- Build output belongs in `x64\Build` and `x64\Release`; never commit it.
- Build discovery uses `vswhere`; Visual Studio C++ x64 tools are required.
- `build.cmd -Package` must produce exactly `2026patch.dll`, `Injector.exe`,
  `2026patch.ini`, `RecRoomScreen.bat`, and `RecRoomVR.bat`.
- Do not install, launch, or restart the game as part of a build. Installation
  and launch require separate explicit approval.

## Install/launch rules

- Copy only the four non-INI package files to the install target:
  `2026patch.dll`, `Injector.exe`, `RecRoomScreen.bat`, `RecRoomVR.bat`.
- Never overwrite the installed `2026patch.ini`; it is user-configured.
- Never replace, patch on disk, or stub the real `Referee.dll`.
- Never launch `Recroom_Release.exe`. Only use `Injector.exe --launch`,
  `RecRoomScreen.bat`, or `RecRoomVR.bat`; these start `RecRoom.exe`.
- Keep `RecRoomScreen.bat` arguments:
  `+forcemode:screen -screen-width 1280 -screen-height 720 -screen-fullscreen 1`.
- Keep `RecRoomVR.bat` argument `+forcemode:vr`.
- Custom launch arguments go through `SCHOOLSOUT_GAME_ARGS`.

## Runtime behavior

- Quit tracing and both suppressions are **on by default** in the patch and
  injector. `SCHOOLSOUT_TRACE_QUIT=0`,
  `SCHOOLSOUT_SUPPRESS_CHEAT_QUIT=0`, and
  `SCHOOLSOUT_SUPPRESS_EXIT_STATE=0` are explicit opt-outs.
- Both batch launchers set all three flags to `1` and include a one-second
  delay before `--wait-ready`.
- `SCHOOLSOUT_SUPPRESS_CHEAT_QUIT` hooks
  `CheatManager.HRZIGTNFSHP.DCDTOGTESYJ` and suppresses the `0x1FC85836` fatal
  quit.
- `SCHOOLSOUT_SUPPRESS_EXIT_STATE` hooks
  `OTBCUXXIPTI.UQNYTEAMCXI(ExitState)` at `0x1DF5310`; it suppresses states
  `1` and `2`, and passes state `0` (`Running`) through.
- Keep gate and arena patches disabled. Use MinHook for managed hooks.
- Authoritative check RVAs are evidence only: `0x708490`, `0x708950`,
  `0x21ED370`.
- No hardware breakpoints may remain armed after debugger detach. Software
  breakpoints are restored before detach.
- Session init is fixed in memory at the resolved `ntdll!NtCreateSection` by
  clearing `OBJECT_ATTRIBUTES.SecurityDescriptor` and `ObjectName`. Do not
  patch `Referee.dll` on disk.

## Configuration and privacy

- Preserve all INI keys: `ApiHost`, `EnableSslPinning`, `VoiceKeyXml`,
  `AllowUnsignedImages`, `SuppressDuidMismatch`, `ServerDomain`,
  `EnableTracing`.
- `VoiceKeyXml` accepts only public RSA `Modulus` and `Exponent`. Private
  fields are rejected. Never log key contents.
- Diagnostics log only scheme, host, family, and rewrite state. Never log
  URLs, paths, queries, headers, credentials, device IDs, or key contents.
- The distributed INI must remain blank for `ApiHost` and `VoiceKeyXml`.

## Git rules

- Commit and push only from this repository, never from `C:\Users\PC`.
- Do not commit build outputs, ZIPs, logs, configured INIs, private keys,
  game files, or the installed game folder.
- Push branch `main` to origin:
  `https://github.com/Legacy95-ctrl/SchoolsOutPatch`.
- Report the commit hash, remote URL, and pushed branch after publishing.
