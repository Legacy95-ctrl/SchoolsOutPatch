# SchoolsOutPatch technical notes

Target build: `2026-03-31T03-05-36Z_473be467`.

Game-side Referee logs are always written under `C:\ProgramData\Referee`;
the session status line appears in `Referee.Game.log`. Do not rely only on
`AppData\LocalLow\Against Gravity\Rec Room\Player.log`.

## Distribution boundary

`x64\Release\SchoolsOutPatch.zip` contains exactly:

- `2026patch.dll`
- `Injector.exe`
- `2026patch.ini`
- `RecRoomScreen.bat`
- `RecRoomVR.bat`

Build with `build.cmd -Package`. The build compiles vendored MinHook as C and
first-party C++17 sources with `/W4 /O2 /MT /EHsc`. No operator endpoint or RSA
private material is compiled in. The default INI has blank `ApiHost` and
`VoiceKeyXml`.

When installing, always copy the non-INI package files to
`C:\Users\PC\Desktop\2026-03-31T03-05-36Z_473be467`. Never overwrite that
folder's `2026patch.ini`; it is user-configured and must be preserved.

## Injector

Both launchers start `Injector.exe --launch`. The injector verifies the three
exact module hashes, signals a path-derived readiness event, then launches
`RecRoom.exe` with `DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS` and the launcher's
mode arguments from `SCHOOLSOUT_GAME_ARGS`. A plain suspended launch stops
before `PEB->Ldr` is initialized, so no module can be found there. The debugger's
initial `STATUS_BREAKPOINT` is the first usable window: static imports including
`Referee.dll` are mapped, but the executable entry point has not run. At that
breakpoint the injector changes the packed fail-fast byte at
`Referee+0x5AB2B90` from `0xFD` to `0xFF` in memory (or `0x02` to `0x00` if the
module is already unpacked). A remote thread cannot run while the debugger holds
the breakpoint, so the injector hijacks that stopped thread: it calls
`LoadLibraryW` with a controlled stack, traps the return with an `int3` stub,
restores the original context with every debug register clear, holds the main
thread for 1500 ms while pumping debug events so the patch threads can run, then
resumes it. This puts `2026patch.dll` and its early native thread in place before
the session initialization can fault. A one-byte software breakpoint (`int3`)
at `Referee+0x69A533` logs the return code and output pointer of the local
preparation call on whichever thread reaches it, without changing either. The
debugger restores the original byte and rewinds RIP before continuing; no
hardware debug register is armed and the append-helper address is never touched.
The six-byte `je` at `Referee+0x69A4E5` is patched by the monitor thread. The
success-path store at `Referee+0x69A7CD` is deliberately left intact so the
initialized local object is published through the owner pointer. The injector
requires both the monitor's byte-patch confirmation and an observed result-break
event before detaching; it fails injection if either is missing. After
confirmation it keeps the
debugger attached for up to 90 seconds to log first-chance native access
violations (registers, fault address, and session-object qwords) without arming
another trap; no register is modified by that diagnostic. That same window also
self-rearms a software `int3` on `user32!DispatchMessageW` to log
`WM_DESTROY`/`WM_CLOSE`/`WM_QUIT` with the return address; the byte is restored
before detach. `SCHOOLSOUT_TRACE_QUIT=0` disables this injector-side trace. The
patch DLL uses MinHook to trace `UnityEngine.Application.Quit(int)`,
`Quit()`, and `Internal_ApplicationQuit()` into `2026patch.log`, logging the
immediate caller and a short stack. It also traces the upstream chain:
`CheatManager.HRZIGTNFSHP.DCDTOGTESYJ`, `SessionManager.FatalApplicationQuit`,
`TryApplicationQuit(int)` and `()`, `SessionModel.ApplicationQuit`, and
`SessionManagerAccess.LHHRAFRXYAO`. Quit diagnostics and suppression are now
**on by default** in the patch; `SCHOOLSOUT_TRACE_QUIT`,
`SCHOOLSOUT_SUPPRESS_CHEAT_QUIT`, and `SCHOOLSOUT_SUPPRESS_EXIT_STATE` may be
set explicitly to `0` to disable them. Both batch launchers set all three to
`1`. The anti-cheat hook returns without calling the original, preventing the
hard-coded `0x1FC85836` fatal quit. The exit-state hook wraps
`OTBCUXXIPTI.UQNYTEAMCXI(ExitState)`, logs state transitions, and suppresses
transitions to `PreparingToExit`/`ReadyForExit` so focus-driven
`Application.Quit()` calls do not terminate the client. State `Running` is
always passed through. Exit codes are logged in decimal and hex; message
strings, credentials, paths, and full URLs are never logged. With
`EnableTracing=true`, HTTP/SignalR diagnostics log only scheme, host, family,
and rewrite state. It then detaches and
waits for exit before showing `Press any key to exit`. Attach mode
still waits for `GameAssembly.dll` before injecting. An injection failure terminates
the launched child instead of leaving it hung. Never launch
`Recroom_Release.exe`; only use `Injector.exe --launch` (directly or through the
two provided batch launchers), which starts `RecRoom.exe`.

`2026patch.dll` starts an early native thread that clears a still-unpacked
`Referee+0x5AB2B90` byte from `0x02` to `0x00` as a fallback. The injector's
suspended-process bootstrap is the primary clear because the pre-`GameAssembly`
fail-fast at `Referee+0x274BF99` (`0xC0000409`, data `7`) otherwise runs before
injected code can act. The same early thread waits for the unpacked bytes at
`Referee+0x69A4E5` and NOPs the six-byte `je` to the named-section fallback.
Fall-through enters the already-correct local initialization at `0x69A4EB`,
which fully initializes the object and reaches the success write at
`0x69A7CD`. No other Referee code or gate is patched. The authoritative check
RVAs remain recorded as evidence only: `0x708490`, `0x708950`, and `0x21ED370`;
the first two are void setup helpers and the third is the aggregate anchor. The
earlier gate and arena patches are intentionally disabled.

The derived session patch at `Referee+0x69A81A` was reverted. Disassembly shows
`mov rax, -99903` is the return value of a failed backend call at
`Referee+0x69A7F7`, not an independent failure constant. Forcing it to success
skips the success-path object write and produces `0xC0000005` at
`Referee+0x69A98D`, followed by the same fail-fast at `Referee+0x274BF99`. The
fallback call at `Referee+0x613130` opens/maps a named section but writes only
the first qword of the output object, leaving its vector bounds unset. The
current patch avoids that fallback entirely instead of fabricating a partial
object.

## Reverted on-disk byte patch

A one-byte on-disk patch at `Referee.dll` file offset `0x36EAD90`
(RVA `0x5AB2B90`, `0xFD` -> `0xFF`) was tested to force the decrypted fail-fast
flag to `0x00`. Themida detected the modification and showed `File corrupted!`,
so the change was reverted from
`C:\Users\PC\AppData\Local\Temp\opencode\Referee.dll.original.bak`. The installed
`Referee.dll` hash is back to
`8F37DFC94E416E3498C531EF9EBA2A01E1FD279299D198B73C7761B24A509287`.
Do not patch `Referee.dll` on disk again; runtime memory patching is required.

The patch DLL still guards managed hook installation by confirming
`GameAssembly.dll` is present; there is no fixed 15-second delay in the
injector.

`RecRoomScreen.bat` keeps `+forcemode:screen -screen-width 1280 -screen-height
720 -screen-fullscreen 1`; `RecRoomVR.bat` keeps `+forcemode:vr`.

## INI contract

One `[config]` section. Keys:

- `ApiHost` — bare `host[:port]` or full `http(s)` origin; redirects `ns.rec.net`.
- `EnableSslPinning` — `true` enables the SSL pinning patch for the configured
  service domain. `DisableCertificatePinning` is accepted only as a migration
  alias with inverted meaning.
- `VoiceKeyXml` — public RSA `Modulus`/`Exponent` only; private fields fail
  startup and packaging. Key contents are never logged.
- `AllowUnsignedImages` — global image-signature bypass.
- `SuppressDuidMismatch` — clears DUID mismatch outputs and returns false.
- `ServerDomain` — optional scope for TLS bypass; defaults to the `ApiHost` host.
- `EnableTracing` — verbose hook diagnostics.

## Validation status

Build/package and local static validation only. The build itself does not
install into the game folder, launch the client, start the server, or perform
gameplay validation. `RecRoomScreen.bat` keeps the 1280x720 fullscreen
arguments.

An earlier installed build crashed before `GameAssembly.dll` loaded with
`0xC0000409` at `Referee+0x274BF99`. The corrected gate/session/arena build,
the no-patch delayed-injection build, and the earlier suspended early-injection
build all hit the same fault, proving the fail-fast is not caused by the
package's gate edits. A normal-launch build with the flag clear was also tested:
the client reached the fail-fast before the injected `LoadLibraryW` returned, so
`2026patch.dll` never loaded. Suspended injection was then tested, but the
initial suspend happens before the loader initializes `PEB->Ldr`, so neither
Toolhelp nor the PEB loader list could see `Referee.dll` and the bootstrap never
ran. The launch path therefore uses a debugger initial breakpoint, where
`Referee.dll` is present with its packed byte still `0xFD`. A clean
`RecRoom.exe` launch with no injector and no patch DLL crashed with the
identical `0xC0000005` at `Referee+0x69A98D` and `0xC0000409` at
`Referee+0x274BF99`. The user clarified that the `-99903` session failure is a
patch problem, not a backend problem. A hardware execution trap showed that the
six-byte `je` is at `Referee+0x69A4E5`; the earlier `0x69A487` RVA landed on the
preceding `test cl, cl` and never matched. The earlier patch at `Referee+0x69A81A`
simply replaced the error constant with success and skipped the success-path
object write at `0x69A7CD`, which caused the `0xC0000005` at `0x69A98D`; it
remains reverted. The current session patch avoids the fallback call at
`Referee+0x613130` entirely: NOPing only the `0x69A4E5` branch keeps the local
initializer's publication store at `0x69A7CD` intact.
Observed runs also correlated hardware
execute traps at the session branch and append-helper fault with fatal
`0xC0000005` exits, while byte-only patching produced clean exits. No hardware
debug register is armed now. The debugger waits for both deterministic byte-patch
confirmation and one process-wide `int3` observation at the local call result;
that software breakpoint is restored before detach, with no append-helper trap
or leftover register.

A fabricated-object diagnostic then pre-populated the owner object reached
through `Referee+0x6B1E158` and NOPed the `0x69A7CD` store. Live fault capture
still showed `0xC0000005` at `Referee+0x69A98D`: the unpacker had replaced the
owner pointer with a new heap object whose first qword was zero, while the
prepared object was orphaned. That confirmed the store NOP blocked publication
of the real initialized session object. The fabricated allocation, owner-pointer
redirection, and store NOP were removed. A second diagnostic with only the
`0x69A4E5` branch NOP and the intact success store still faulted at
`Referee+0x69A98D`; the owner object's first qword remained zero. Disassembly
shows the local initializer returns early through `Referee+0x69A53E` when the
preparation call at `Referee+0x69A52E` reports a negative result, skipping the
store. A third diagnostic forced that `jns` to `jmp` and crashed earlier at
`Referee+0x69A592` with `rcx=0`: the failed call left the output pointer zero, so
the forced success path dereferenced a null object. That patch is reverted. The
object-producing call itself must be made to succeed; its success branch cannot
be forced safely. The original failure was traced to `ntdll!NtCreateSection`,
called through the obfuscated import wrapper at `Referee+0x21E3F40`. The
resolved indirect call is at `Referee+0x21E4053`; it is armed only after the
outer call trap at `Referee+0x612F4B` fires, because Themida rewrites the wrapper
region while the module unpacks and an earlier int3 there is overwritten. Live
capture confirms the resolved pointer matches local `ntdll!NtCreateSection`.
Its arguments are `DesiredAccess=0x000F001F` (`SECTION_ALL_ACCESS`),
`SectionPageProtection=4` (`PAGE_READWRITE`), `AllocationAttributes=0x08000000`
(`SEC_COMMIT`), `FileHandle=NULL`, and an `OBJECT_ATTRIBUTES` of length `0x48`
with `Attributes=0x40` (`OBJ_OPENIF`), a NULL `SecurityDescriptor` after the
runtime clear, and the name `\BaseNamedObjects\KjMpQrStUvWxYzAb`.

Clearing only `OBJECT_ATTRIBUTES.SecurityDescriptor` still returned
`C0000022`, proving the supplied DACL was not the blocker. The denial comes
from the already-existing named section's DACL being reopened through
`OBJ_OPENIF` with `SECTION_ALL_ACCESS`. Clearing
`OBJECT_ATTRIBUTES.ObjectName` at the inner trap makes the same call create a
fresh unnamed section with the process's default DACL. With that in-memory
change, `NtCreateSection` returns `0`, `NtMapViewOfSection` returns `0`, the
local preparation call at `Referee+0x69A52E` returns `0` with a non-null output
object, and the success store at `Referee+0x69A7CD` publishes it. The earlier
`0xC0000005` at `Referee+0x69A98D` no longer occurs, and `Referee.Game.log`
shows only `[Game] Started game.` with no `-99904`. No Referee code or on-disk
file is modified for this fix; only two stack `OBJECT_ATTRIBUTES` pointer fields
are cleared in memory at runtime.

The installed default-on build is `Injector.exe` SHA-256
`B03CDA415596815674EEADBE7E142131E3A6DC90A5F0A8889BD9BA087047E00A` and
`2026patch.dll` SHA-256
`A51582DBB289A01305632F4829B059CCBCDBB9DBD7C7D5EE398E1EE1BDC28DBC`.
The configured `2026patch.ini` and real `Referee.dll` are never overwritten.
Do not launch `Recroom_Release.exe`; its
client app fails with `-99962`/`-99986` because configuration blobs are missing.
Do not launch or relaunch as part of a build; installation is a separate,
explicitly approved step.
