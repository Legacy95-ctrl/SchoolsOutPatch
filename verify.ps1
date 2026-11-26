[CmdletBinding()]
param([string]$GameRoot = '')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$release = Join-Path $root 'x64\Release'
$zip = Join-Path $release 'SchoolsOutPatch.zip'
$expected = @('2026patch.dll', 'Injector.exe', '2026patch.ini', 'RecRoomScreen.bat', 'RecRoomVR.bat')

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $names = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
} finally { $archive.Dispose() }
if (($names -join ',') -ne (($expected | Sort-Object) -join ',')) {
    throw "Unexpected archive contents: $($names -join ',')"
}
Write-Host "PASS archive allowlist: $($names -join ', ')"

$ini = Join-Path $release '2026patch.ini'
$text = [IO.File]::ReadAllText($ini)
foreach ($key in @('ApiHost=', 'EnableSslPinning=', 'VoiceKeyXml=', 'AllowUnsignedImages=',
                   'SuppressDuidMismatch=')) {
    if ($text -notmatch "(?m)^$([regex]::Escape($key))") { throw "Missing INI key $key" }
}
$screen = [IO.File]::ReadAllText((Join-Path $release 'RecRoomScreen.bat'))
if ($screen -notmatch '-screen-width 1280 -screen-height 720 -screen-fullscreen 1') {
    throw 'Screen launcher lost the 1280x720 fullscreen arguments.'
}
Write-Host 'PASS INI keys and 1280x720 launcher'

$injector = Join-Path $release 'Injector.exe'
& $injector --check-config $release | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Packaged INI failed injector config check.' }
Write-Host 'PASS packaged INI config check'

$badDir = Join-Path $root 'x64\Build\verify-private-key'
New-Item -ItemType Directory -Force -Path $badDir | Out-Null
$copy = $text -replace '(?m)^VoiceKeyXml=.*$',
    'VoiceKeyXml=<RSAKeyValue><Modulus>AQAB</Modulus><Exponent>AQAB</Exponent><D>private</D></RSAKeyValue>'
[IO.File]::WriteAllText((Join-Path $badDir '2026patch.ini'), $copy, [Text.Encoding]::ASCII)
Copy-Item -LiteralPath (Join-Path $release 'Injector.exe') -Destination (Join-Path $badDir 'Injector.exe') -Force
$null = & (Join-Path $badDir 'Injector.exe') --check-config $badDir 2>&1
if ($LASTEXITCODE -eq 0) { throw 'Private RSA field was accepted.' }
Write-Host 'PASS private RSA key rejection'

$publicKey = '<RSAKeyValue><Modulus>AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
$goodDir = Join-Path $root 'x64\Build\verify-public-key'
New-Item -ItemType Directory -Force -Path $goodDir | Out-Null
$goodIni = $text -replace '(?m)^VoiceKeyXml=.*$', "VoiceKeyXml=$publicKey"
[IO.File]::WriteAllText((Join-Path $goodDir '2026patch.ini'), $goodIni, [Text.Encoding]::ASCII)
Copy-Item -LiteralPath (Join-Path $release 'Injector.exe') -Destination (Join-Path $goodDir 'Injector.exe') -Force
$null = & (Join-Path $goodDir 'Injector.exe') --check-config $goodDir 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Valid public RSA key with unpadded exponent was rejected.' }
Write-Host 'PASS public RSA key acceptance'

if ($GameRoot -and (Test-Path -LiteralPath $GameRoot)) {
    $null = & $injector --check-install $GameRoot
    if ($LASTEXITCODE -ne 0) { throw 'Target installation fingerprint check failed.' }
    Write-Host 'PASS target installation fingerprint check'
}

$source = [IO.File]::ReadAllText((Join-Path $root 'Injector\injector.cpp'))
$required = @('--launch', 'SCHOOLSOUT_GAME_ARGS', 'CreateProcessW',
              'DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS', 'launched RecRoom.exe under debugger',
              'WaitForInitialBreakpoint', 'BootstrapReferee', 'PatchRemoteByte',
              'PackedFailFastFlag', 'NtQueryInformationProcess', 'PEB loader list',
              'InjectAtBreakpoint', 'GetThreadContext', 'SetThreadContext',
              'LoadLibraryW entered from initial breakpoint',
              'loader returned at breakpoint stub', 'main thread held',
              'main thread resumed after patch startup hold', 'MonitorSessionBranch',
              'session branch monitor started', 'session fallback branch patched',
              'RemoteBytesEqual', 'g_monitorComplete', 'g_resultTrapObserved',
              'session result int3 armed', 'session result int3 removed',
              'local call result eax=', 'local call output=', 'HandleResultTrap',
              'MapViewCall', 'map view int3 armed', 'map view section=',
              'HandleMapViewTrap', 'map view int3 removed',
              'map view int3 restored before detach',
              'AllocateVirtualMemoryCall', 'allocate int3 armed', 'allocate process=',
              'HandleAllocTrap', 'allocate int3 removed',
              'allocate int3 restored before detach',
              'CreatorCreateSectionCall', 'create section int3 armed',
              'object attributes=%p security descriptor=%p',
              'security descriptor cleared', 'HandleCreateSectionTrap',
              'create section int3 removed', 'create section int3 restored before detach',
              'CreatorSectionApiCall', 'section api int3 armed at %p after create section call',
              'create section api trap byte=%02X', 'section api int3 late',
              'section api ptr=%p ntdll=%p match=%s',
              'section api args rcx=%p', 'section api object len=%lu',
              'section api object name cleared',
              'HandleSectionApiTrap', 'section api int3 removed',
              'section api int3 restored before detach',
              'HandleStatusTraps', 'object creator %s int3 armed',
              'object creator %s eax=', 'object creator %s int3 removed',
              'object creator %s int3 restored before detach',
              'deterministic session patch confirmed', 'deterministic session patch not confirmed',
              'no hardware breakpoints armed', 'debug register clear failed',
              'CONTEXT_DEBUG_REGISTERS', 'post-patch fault capture', 'LogNativeFault',
              'known append-helper fault reached', 'regs rip=', 'debug dr2=',
              'session owner object=', 'CreateLoaderThread',
              'FinishLoaderThread', 'WaitForLoaderThread', 'DetachDebugger',
              'DebugActiveProcessStop', 'InjectDll', 'waitForGameAssembly',
              'Kernel32.dll is mapped at the same base', 'Press any key to exit')
foreach ($token in $required) {
    if ($source -notmatch [regex]::Escape($token)) { throw "Normal-launch injector source is missing $token" }
}
$stale = @('InjectEarly', 'exceptionExit', 'RefereeBypassThread', 'GatePatches()',
           'kUnpatchedStartupDelayMs', 'startup delay complete',
           'CREATE_SUSPENDED', 'BootstrapSuspendedReferee',
           'injecting before resume', 'resumed game after early injection',
           'kDr7Local2Execute', 'SessionGlobalRead',
           'session slot read breakpoint armed', 'session slot redirected to',
           '0x21D7590', 'session execute breakpoint armed',
           'fault execute breakpoint armed', 'debug registers cleared after hardware trap',
            'branch-only execute breakpoint armed', 'session branch trap cleared',
            'session fallback patched at execute breakpoint',
            'session result execute breakpoint armed', 'session result trap cleared',
            'kDr7Local0Execute', 'clearHardwareBreakpoint',
            'session branch bytes did not match',
           'append-helper fault not observed', 'session branch execute trap not observed',
           'PrepareSessionObject', 'prepared session object', 'g_preparedSession', 'PatchSessionLocalSuccessBranch',
            'session local success branch patched', 'local success bytes=',
            'g_monitorLocalSuccess', 'forcedLocal',
           'PatchSessionGlobalStore', 'session global store patched',
           'session global store not patched', 'RestoreSessionGlobal',
           'session global restored to', 'session global slot=', '0x1500030',
           'SessionGlobalStore')
foreach ($token in $stale) {
    if ($source -match [regex]::Escape($token)) { throw "Injector source must no longer contain $token" }
}
foreach ($token in @('SCHOOLSOUT_TRACE_QUIT', 'HandleQuitTrace', 'RestoreQuitTrace')) {
    if ($source -notmatch [regex]::Escape($token)) {
        throw "Injector source is missing quit trace token $token"
    }
}

$patchSource = [IO.File]::ReadAllText((Join-Path $root '2026Patch\src\main.cpp'))
foreach ($token in @('EarlyRefereePatches', 'PatchBytes', 'Referee::FailFastFlag',
                     'Referee::SessionFallbackBranch', 'native patches: failFast',
                     'sessionBranch=%d', 'GetModuleHandleW(L"GameAssembly.dll")',
                     'referee flag=')) {
    if ($patchSource -notmatch [regex]::Escape($token)) {
        throw "Patch DLL source is missing $token"
    }
}
foreach ($token in @('NeutralizeReferee', 'SessionFailureResult', 'sessionOld',
                     'sessionNew', 'SessionLocalSuccessBranch', 'g_sessionLocalSuccessPatched',
                      'localSuccess=%d', '0x69A81A', 'g_sessionGlobalStorePatched',
                     'SessionGlobalStore', 'storeNops', 'expectedStore', 'globalStore=')) {
    if ($patchSource -match [regex]::Escape($token)) {
        throw "Patch DLL source must no longer contain $token"
    }
}
$offsetsSource = [IO.File]::ReadAllText((Join-Path $root '2026Patch\src\RR\Offsets.h'))
if ($offsetsSource -notmatch [regex]::Escape('0x5AB2B90')) {
    throw 'Referee fail-fast flag RVA is missing from Offsets.h'
}
if ($offsetsSource -notmatch [regex]::Escape('0x69A4E5')) {
    throw 'Referee session fallback branch RVA is missing from Offsets.h'
}
if ($offsetsSource -notmatch [regex]::Escape('0x69A533')) {
    throw 'Referee local call result RVA is missing from Offsets.h'
}
if ($offsetsSource -notmatch [regex]::Escape('MapViewCall') -or
    $offsetsSource -notmatch [regex]::Escape('0x21E4A2A')) {
    throw 'Referee NtMapViewOfSection call RVA is missing from Offsets.h'
}
if ($offsetsSource -notmatch [regex]::Escape('AllocateVirtualMemoryCall') -or
    $offsetsSource -notmatch [regex]::Escape('0x21E3A65')) {
    throw 'Referee NtAllocateVirtualMemory call RVA is missing from Offsets.h'
}
foreach ($token in @('CreatorCreateSidResult', 'CreatorSetAclResult',
                     'CreatorAllocateResult', 'CreatorInitSdResult',
                     'CreatorSetDaclResult', 'CreatorMapViewResult',
                     'CreatorCreateSectionCall', 'CreatorCreateSectionResult',
                     'CreatorSectionApiCall',
                     '0x612B9F', '0x612C14', '0x612D5A', '0x612DA0',
                     '0x612DE6', '0x612F4B', '0x612F50', '0x6130E2',
                     '0x21E4053')) {
    if ($offsetsSource -notmatch [regex]::Escape($token)) {
        throw "Object creator diagnostic RVA is missing from Offsets.h: $token"
    }
}
if ($offsetsSource -notmatch [regex]::Escape('0x69A53E')) {
    throw 'Referee failed local success branch note is missing from Offsets.h'
}
if ($offsetsSource -notmatch [regex]::Escape('0x69A98D')) {
    throw 'Referee append-helper fault RVA is missing from Offsets.h'
}
if ($offsetsSource -notmatch [regex]::Escape('0x6B1E158')) {
    throw 'Referee session object slot RVA is missing from Offsets.h'
}
if ($offsetsSource -match [regex]::Escape('0x69A7CD') -or
    $offsetsSource -match [regex]::Escape('SessionGlobalStore')) {
    throw 'Offsets.h must no longer patch or expose the session success store'
}
if ($offsetsSource -match [regex]::Escape('0x69A81A')) {
    throw 'Offsets.h must no longer contain the reverted session RVA'
}
$methodsSource = [IO.File]::ReadAllText((Join-Path $root '2026Patch\src\RR\Methods.h'))
if ($methodsSource -notmatch [regex]::Escape('0x7B44DC0')) {
    throw 'Methods.h is missing the WebSocketTransport.BuildUri RVA'
}
foreach ($token in @('0x9D93800', '0x9D93840', '0x9D930D0')) {
    if ($methodsSource -notmatch [regex]::Escape($token)) {
        throw "Methods.h is missing the managed quit trace RVA $token"
    }
}
foreach ($token in @('0x1DF1CC0', '0x1DF5310', '0x1E11AB0', '0x1E17CC0', '0x1E17E40', '0x26445C0', '0x1E0EF80')) {
    if ($methodsSource -notmatch [regex]::Escape($token)) {
        throw "Methods.h is missing the quit-chain RVA $token"
    }
}
$netSource = [IO.File]::ReadAllText((Join-Path $root '2026Patch\src\RR\NetworkConfig.h'))
foreach ($token in @('ParseUrlAny', 'RewriteSignalR', '"wss"')) {
    if ($netSource -notmatch [regex]::Escape($token)) {
        throw "NetworkConfig.h is missing $token"
    }
}
$patchesSource = [IO.File]::ReadAllText((Join-Path $root '2026Patch\src\RR\Patches.cpp'))
foreach ($token in @('WebSocketBuildUri', 'WebSocketTransport.BuildUri', 'RewriteSignalR',
                    '[SignalR] WebSocket base URI redirected to configured host')) {
    if ($patchesSource -notmatch [regex]::Escape($token)) {
        throw "Patches.cpp is missing $token"
    }
}
foreach ($token in @('SCHOOLSOUT_TRACE_QUIT', 'LogManagedQuit', 'RtlCaptureStackBackTrace',
                    'Application.Quit(int)', 'Application.Internal_ApplicationQuit()',
                     'CheatManager.HRZIGTNFSHP.DCDTOGTESYJ', 'SessionManager.FatalApplicationQuit',
                     'SessionManager.TryApplicationQuit(int)', 'SessionManagerAccess.LHHRAFRXYAO',
                     'SCHOOLSOUT_SUPPRESS_CHEAT_QUIT', 'suppressed anti-cheat fatal quit',
                     'SCHOOLSOUT_SUPPRESS_EXIT_STATE', 'OTBCUXXIPTI.SetExitState',
                     'suppressed exit-state quit', 'SafeAuthorityHost', 'LogHttpTarget',
                     'host=%s family=%s')) {
    if ($patchesSource -notmatch [regex]::Escape($token)) {
        throw "Patches.cpp is missing default-on quit fix token $token"
    }
}
Write-Host 'PASS normal-launch source check'

foreach ($name in @('RecRoomScreen.bat', 'RecRoomVR.bat')) {
    $batch = [IO.File]::ReadAllText((Join-Path $root $name))
    if ($batch -notmatch [regex]::Escape('Injector.exe" --launch')) {
        throw "$name must launch Injector.exe --launch"
    }
    foreach ($flag in @('SCHOOLSOUT_TRACE_QUIT=1', 'SCHOOLSOUT_SUPPRESS_CHEAT_QUIT=1',
                        'SCHOOLSOUT_SUPPRESS_EXIT_STATE=1')) {
        if ($batch -notmatch [regex]::Escape($flag)) {
            throw "$name is missing $flag"
        }
    }
    if ($batch -match [regex]::Escape('start "" "%~dp0RecRoom.exe"')) {
        throw "$name must not start RecRoom.exe directly"
    }
}
Write-Host 'PASS launchers delegate to injector'
