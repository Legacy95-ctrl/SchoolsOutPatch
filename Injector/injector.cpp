#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <string>

#include "..\2026Patch\src\RR\BuildGuard.h"
#include "..\2026Patch\src\RR\Config.h"
#include "..\2026Patch\src\RR\Offsets.h"

namespace
{
    using SchoolsOut::BuildGuard::SupportsInstallation;
    using SchoolsOut::Config::Settings;
    using SchoolsOut::Offsets::Referee::DecryptedFailFastOff;
    using SchoolsOut::Offsets::Referee::AllocateVirtualMemoryCall;
    using SchoolsOut::Offsets::Referee::FailFastFlag;
    using SchoolsOut::Offsets::Referee::MapViewCall;
    using SchoolsOut::Offsets::Referee::PackedFailFastFlag;
    using SchoolsOut::Offsets::Referee::SessionAppendFault;
    using SchoolsOut::Offsets::Referee::SessionObjectSlot;

    constexpr const wchar_t* kPatchDll = L"2026patch.dll";
    constexpr const wchar_t* kMutexName = L"Local\\SchoolsOutPatchInjector";
    constexpr const wchar_t* kGameArgsVariable = L"SCHOOLSOUT_GAME_ARGS";

    bool g_logging = false;
    std::wstring g_logPath;
    volatile LONG g_monitorStop = 0;
    volatile LONG g_monitorComplete = 0;
    HANDLE g_monitorThread = nullptr;
    HANDLE g_monitorProcess = nullptr;
    uintptr_t g_monitorBranch = 0;
    uintptr_t g_monitorResult = 0;
    unsigned char g_resultTrapOriginal = 0;
    volatile LONG g_resultTrapArmed = 0;
    volatile LONG g_resultTrapObserved = 0;
    uintptr_t g_mapViewTrap = 0;
    unsigned char g_mapViewTrapOriginal = 0;
    volatile LONG g_mapViewTrapArmed = 0;
    uintptr_t g_allocTrap = 0;
    unsigned char g_allocTrapOriginal = 0;
    volatile LONG g_allocTrapArmed = 0;
    uintptr_t g_createSectionTrap = 0;
    unsigned char g_createSectionOriginal = 0;
    volatile LONG g_createSectionArmed = 0;
    uintptr_t g_sectionApiTrap = 0;
    unsigned char g_sectionApiOriginal = 0;
    volatile LONG g_sectionApiArmed = 0;
    volatile LONG g_sectionApiObserved = 0;
    uintptr_t g_quitTraceTrap = 0;
    unsigned char g_quitTraceOriginal = 0;
    volatile LONG g_quitTraceArmed = 0;
    volatile LONG g_quitTraceStepping = 0;
    volatile LONG g_quitTraceSawFirst = 0;
    DWORD g_quitTraceThread = 0;

    struct StatusTrap
    {
        uintptr_t address = 0;
        const char* label = nullptr;
        unsigned char original = 0;
        volatile LONG armed = 0;
    };
    StatusTrap g_statusTraps[7];

    void Out(const char* format, ...)
    {
        char text[1024];
        va_list args;
        va_start(args, format);
        _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
        va_end(args);
        std::puts(text);
        std::fflush(stdout);
        if (!g_logging || g_logPath.empty()) { return; }
        FILE* file = nullptr;
        if (!_wfopen_s(&file, g_logPath.c_str(), L"a")) {
            std::fputs(text, file);
            std::fputc('\n', file);
            std::fclose(file);
        }
    }

    void Pause()
    {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input == INVALID_HANDLE_VALUE || input == nullptr) { return; }
        std::puts("Press any key to exit");
        std::fflush(stdout);
        _getch();
    }

    std::wstring ModuleDirectory()
    {
        wchar_t file[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(nullptr, file, MAX_PATH);
        if (!length || length >= MAX_PATH) { return {}; }
        const std::wstring full(file, length);
        const std::size_t separator = full.find_last_of(L"\\/");
        return separator == std::wstring::npos ? std::wstring() : full.substr(0, separator);
    }

    std::uint64_t RootHash(const std::wstring& root)
    {
        std::uint64_t hash = 1469598103934665603ULL;
        for (const wchar_t value : root) {
            const wchar_t lower = value >= L'A' && value <= L'Z' ? value + 32 : value;
            hash ^= static_cast<std::uint64_t>(lower & 0xFFFF);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    std::wstring ReadyEventName(const std::wstring& root)
    {
        wchar_t name[128] = {};
        _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\SchoolsOutPatchReady-%016llX",
                     static_cast<unsigned long long>(RootHash(root)));
        return name;
    }

    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    constexpr DWORD kExceptionDebugEvent = 1;
    constexpr DWORD kExitProcessDebugEvent = 5;
    constexpr DWORD kStatusBreakpoint = 0x80000003;
    constexpr DWORD kStatusSingleStep = 0x80000004;
    constexpr DWORD kStatusAccessViolation = 0xC0000005;
    constexpr DWORD kWmDestroy = 0x0002;
    constexpr DWORD kWmClose = 0x0010;
    constexpr DWORD kWmQuit = 0x0012;
    constexpr DWORD kDbgContinue = 0x00010002;
    constexpr DWORD kDbgExceptionNotHandled = 0x80010001;

    struct ProcessBasicInformation
    {
        NTSTATUS ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    };

    bool ReadRemote(HANDLE process, uintptr_t address, void* buffer, std::size_t size)
    {
        SIZE_T read = 0;
        return ReadProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, &read) &&
               read == size;
    }

    // Toolhelp has no module list for a process that is still suspended at its
    // entry point. Walk the PEB loader list instead; it is populated by the
    // time CreateProcessW returns.
    uintptr_t ModuleBase(HANDLE process, const wchar_t* name)
    {
        static auto query = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!query) { return 0; }
        ProcessBasicInformation info{};
        ULONG length = 0;
        if (query(process, 0, &info, sizeof(info), &length) != 0 || !info.PebBaseAddress) { return 0; }

        const auto peb = reinterpret_cast<uintptr_t>(info.PebBaseAddress);
        uintptr_t ldr = 0;
        if (!ReadRemote(process, peb + 0x18, &ldr, sizeof(ldr)) || !ldr) { return 0; }
        uintptr_t entry = 0;
        if (!ReadRemote(process, ldr + 0x10, &entry, sizeof(entry)) || !entry) { return 0; }

        for (int count = 0; count < 1024 && entry; ++count) {
            uintptr_t base = 0;
            unsigned short nameLength = 0;
            uintptr_t buffer = 0;
            if (!ReadRemote(process, entry + 0x30, &base, sizeof(base)) ||
                !ReadRemote(process, entry + 0x58, &nameLength, sizeof(nameLength)) ||
                !ReadRemote(process, entry + 0x60, &buffer, sizeof(buffer))) {
                return 0;
            }
            if (nameLength && nameLength < 512 && buffer) {
                std::wstring module(nameLength / sizeof(wchar_t), L'\0');
                if (ReadRemote(process, buffer, module.data(), nameLength) &&
                    _wcsicmp(module.c_str(), name) == 0) {
                    return base;
                }
            }
            if (!ReadRemote(process, entry, &entry, sizeof(entry))) { return 0; }
        }
        return 0;
    }

    std::wstring ProcessPath(HANDLE process)
    {
        wchar_t path[32768] = {};
        DWORD length = static_cast<DWORD>(_countof(path));
        if (!QueryFullProcessImageNameW(process, 0, path, &length) || length == 0) { return {}; }
        return std::wstring(path, length);
    }

    DWORD FindGame(const std::wstring& root)
    {
        const std::wstring expected = root + L"\\RecRoom.exe";
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) { return 0; }
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        DWORD found = 0;
        for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry)) {
            if (_wcsicmp(entry.szExeFile, L"RecRoom.exe") != 0) { continue; }
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE,
                                         entry.th32ProcessID);
            if (!process) { continue; }
            const std::wstring path = ProcessPath(process);
            CloseHandle(process);
            if (_wcsicmp(path.c_str(), expected.c_str()) != 0) { continue; }
            found = entry.th32ProcessID;
            break;
        }
        CloseHandle(snapshot);
        return found;
    }

    bool WriteRemote(HANDLE process, uintptr_t address, const void* buffer, std::size_t size)
    {
        SIZE_T written = 0;
        return WriteProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, &written) &&
               written == size;
    }

    bool PatchRemoteByte(HANDLE process, uintptr_t address, unsigned char expected,
                         unsigned char replacement, const char* label)
    {
        unsigned char actual = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<void*>(address), &actual, 1, &read) || read != 1) {
            Out("[bootstrap] %s read failed err=%lu", label, GetLastError());
            return false;
        }
        if (actual != expected) {
            Out("[bootstrap] %s byte=0x%02X expected=0x%02X; unchanged", label, actual, expected);
            return false;
        }
        DWORD previous = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), 1, PAGE_READWRITE, &previous)) {
            Out("[bootstrap] %s protect failed err=%lu", label, GetLastError());
            return false;
        }
        const bool written = WriteRemote(process, address, &replacement, 1);
        DWORD restored = 0;
        VirtualProtectEx(process, reinterpret_cast<void*>(address), 1, previous, &restored);
        Out("[bootstrap] %s 0x%02X -> 0x%02X %s", label, expected, replacement,
            written ? "applied" : "write failed");
        return written;
    }

    bool PatchRemoteBytes(HANDLE process, uintptr_t address, const unsigned char* expected,
                          const unsigned char* replacement, std::size_t size, const char* label)
    {
        unsigned char actual[16] = {};
        SIZE_T read = 0;
        if (size > sizeof(actual) ||
            !ReadProcessMemory(process, reinterpret_cast<void*>(address), actual, size, &read) ||
            read != size || std::memcmp(actual, expected, size) != 0) {
            return false;
        }
        DWORD previous = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), size,
                              PAGE_EXECUTE_READWRITE, &previous)) {
            return false;
        }
        const bool written = WriteRemote(process, address, replacement, size);
        DWORD restored = 0;
        VirtualProtectEx(process, reinterpret_cast<void*>(address), size, previous, &restored);
        if (written) { Out("[monitor] %s patched", label); }
        return written;
    }

    bool WriteCodeByte(HANDLE process, uintptr_t address, unsigned char value)
    {
        DWORD previous = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), 1,
                              PAGE_EXECUTE_READWRITE, &previous)) {
            return false;
        }
        const bool written = WriteRemote(process, address, &value, 1);
        DWORD restored = 0;
        VirtualProtectEx(process, reinterpret_cast<void*>(address), 1, previous, &restored);
        return written;
    }

    bool RemoteBytesEqual(HANDLE process, uintptr_t address, const unsigned char* expected,
                           std::size_t size)
    {
        unsigned char actual[16] = {};
        return size <= sizeof(actual) && ReadRemote(process, address, actual, size) &&
               std::memcmp(actual, expected, size) == 0;
    }

    // Consume a process-wide int3 at the local preparation call result. It can
    // fire on any thread, so the context comes from the debug event's thread,
    // not from the thread used for injection. Returns true only when this event
    // was ours; the caller must not continue it again.
    bool HandleResultTrap(HANDLE process, const DEBUG_EVENT& event, uintptr_t sessionTrap)
    {
        if (event.dwDebugEventCode != kExceptionDebugEvent) { return false; }
        const auto& info = event.u.Exception;
        if (info.ExceptionRecord.ExceptionCode != kStatusBreakpoint ||
            reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress) != sessionTrap ||
            InterlockedCompareExchange(&g_resultTrapArmed, 0, 0) == 0) {
            return false;
        }
        InterlockedExchange(&g_resultTrapArmed, 0);

        unsigned char current = 0;
        if (!ReadRemote(process, sessionTrap, &current, 1) || current != 0xCC) {
            Out("[debug] session result int3 byte missing at trap");
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }

        HANDLE eventThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                        event.dwThreadId);
        if (eventThread) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(eventThread, &context)) {
                Out("[debug] local call result eax=%08lX rsp=%p tid=%lu",
                    static_cast<unsigned long>(context.Rax),
                    reinterpret_cast<void*>(context.Rsp),
                    static_cast<unsigned long>(event.dwThreadId));
                ULONG_PTR output = 0;
                if (ReadRemote(process, static_cast<uintptr_t>(context.Rsp) + 0x28,
                               &output, sizeof(output))) {
                    Out("[debug] local call output=%p", reinterpret_cast<void*>(output));
                }
                // INT3 replaced the first byte of the seven-byte instruction at
                // 0x69A533, so RIP is one byte past the real address.
                context.Rip = static_cast<ULONG_PTR>(sessionTrap);
                context.Dr0 = 0;
                context.Dr1 = 0;
                context.Dr2 = 0;
                context.Dr3 = 0;
                context.Dr6 = 0;
                context.Dr7 = 0;
                Out("[debug] session result debug registers clear=%s",
                    SetThreadContext(eventThread, &context) != FALSE ? "yes" : "no");
                InterlockedExchange(&g_resultTrapObserved, 1);
            } else {
                Out("[debug] local call result context unreadable err=%lu", GetLastError());
            }
            CloseHandle(eventThread);
        } else {
            Out("[debug] OpenThread for result trap failed err=%lu", GetLastError());
        }

        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, sessionTrap, &trapByte, &g_resultTrapOriginal, 1,
                             "session result int3 restore")) {
            Out("[debug] session result int3 removed");
        } else {
            Out("[debug] session result int3 removal failed");
        }
        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
        return true;
    }

    void RestoreResultTrap(HANDLE process, uintptr_t address)
    {
        if (!address || InterlockedCompareExchange(&g_resultTrapArmed, 0, 0) == 0) { return; }
        unsigned char current = 0;
        if (!ReadRemote(process, address, &current, 1) || current != 0xCC) {
            InterlockedExchange(&g_resultTrapArmed, 0);
            return;
        }
        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, address, &trapByte, &g_resultTrapOriginal, 1,
                             "session result int3 cleanup")) {
            Out("[debug] session result int3 restored before detach");
        }
        InterlockedExchange(&g_resultTrapArmed, 0);
    }

    // Consume a one-shot int3 at the indirect NtMapViewOfSection call in the
    // object creator. It logs the handles and all x64 stack arguments without
    // changing them, then restores the original byte and rewinds RIP.
    bool HandleMapViewTrap(HANDLE process, const DEBUG_EVENT& event, uintptr_t mapTrap)
    {
        if (event.dwDebugEventCode != kExceptionDebugEvent) { return false; }
        const auto& info = event.u.Exception;
        if (info.ExceptionRecord.ExceptionCode != kStatusBreakpoint ||
            reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress) != mapTrap ||
            InterlockedCompareExchange(&g_mapViewTrapArmed, 0, 0) == 0) {
            return false;
        }
        InterlockedExchange(&g_mapViewTrapArmed, 0);

        unsigned char current = 0;
        if (!ReadRemote(process, mapTrap, &current, 1) || current != 0xCC) {
            Out("[debug] map view int3 byte missing at trap");
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }

        HANDLE eventThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                        event.dwThreadId);
        if (eventThread) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(eventThread, &context)) {
                Out("[debug] map view section=%p process=%p base=%p zeroBits=%p tid=%lu",
                    reinterpret_cast<void*>(context.Rcx), reinterpret_cast<void*>(context.Rdx),
                    reinterpret_cast<void*>(context.R8), reinterpret_cast<void*>(context.R9),
                    static_cast<unsigned long>(event.dwThreadId));

                ULONG_PTR stackArgs[6] = {};
                const uintptr_t rsp = static_cast<uintptr_t>(context.Rsp);
                if (ReadRemote(process, rsp + 0x20, stackArgs, sizeof(stackArgs))) {
                    Out("[debug] map view stack commit=%p offset=%p view=%p inherit=%llX alloc=%llX protect=%llX",
                        reinterpret_cast<void*>(stackArgs[0]),
                        reinterpret_cast<void*>(stackArgs[1]),
                        reinterpret_cast<void*>(stackArgs[2]),
                        static_cast<unsigned long long>(stackArgs[3]),
                        static_cast<unsigned long long>(stackArgs[4]),
                        static_cast<unsigned long long>(stackArgs[5]));

                    ULONG_PTR baseAddress = 0;
                    if (ReadRemote(process, static_cast<uintptr_t>(context.R8), &baseAddress,
                                   sizeof(baseAddress))) {
                        Out("[debug] map view base=%p", reinterpret_cast<void*>(baseAddress));
                    }
                    LARGE_INTEGER sectionOffset{};
                    if (ReadRemote(process, static_cast<uintptr_t>(stackArgs[1]), &sectionOffset,
                                   sizeof(sectionOffset))) {
                        Out("[debug] map view offset=%016llX",
                            static_cast<unsigned long long>(sectionOffset.QuadPart));
                    }
                    ULONG_PTR viewSize = 0;
                    if (ReadRemote(process, static_cast<uintptr_t>(stackArgs[2]), &viewSize,
                                   sizeof(viewSize))) {
                        Out("[debug] map view size=%p", reinterpret_cast<void*>(viewSize));
                    }
                } else {
                    Out("[debug] map view stack args unreadable err=%lu", GetLastError());
                }

                // INT3 replaced the first byte of the indirect call at mapTrap,
                // so RIP is one byte past the real instruction.
                context.Rip = static_cast<ULONG_PTR>(mapTrap);
                context.Dr0 = 0;
                context.Dr1 = 0;
                context.Dr2 = 0;
                context.Dr3 = 0;
                context.Dr6 = 0;
                context.Dr7 = 0;
                Out("[debug] map view debug registers clear=%s",
                    SetThreadContext(eventThread, &context) != FALSE ? "yes" : "no");
            } else {
                Out("[debug] map view context unreadable err=%lu", GetLastError());
            }
            CloseHandle(eventThread);
        } else {
            Out("[debug] OpenThread for map view trap failed err=%lu", GetLastError());
        }

        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, mapTrap, &trapByte, &g_mapViewTrapOriginal, 1,
                             "map view int3 restore")) {
            Out("[debug] map view int3 removed");
        } else {
            Out("[debug] map view int3 removal failed");
        }
        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
        return true;
    }

    void RestoreMapViewTrap(HANDLE process, uintptr_t address)
    {
        if (!address || InterlockedCompareExchange(&g_mapViewTrapArmed, 0, 0) == 0) { return; }
        unsigned char current = 0;
        if (!ReadRemote(process, address, &current, 1) || current != 0xCC) {
            InterlockedExchange(&g_mapViewTrapArmed, 0);
            return;
        }
        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, address, &trapByte, &g_mapViewTrapOriginal, 1,
                             "map view int3 cleanup")) {
            Out("[debug] map view int3 restored before detach");
        }
        InterlockedExchange(&g_mapViewTrapArmed, 0);
    }

    // The object creator allocates its security-descriptor buffer before it
    // maps the section. This one-shot int3 captures NtAllocateVirtualMemory's
    // arguments when the map-view call is never reached.
    bool HandleAllocTrap(HANDLE process, const DEBUG_EVENT& event, uintptr_t allocTrap)
    {
        if (event.dwDebugEventCode != kExceptionDebugEvent) { return false; }
        const auto& info = event.u.Exception;
        if (info.ExceptionRecord.ExceptionCode != kStatusBreakpoint ||
            reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress) != allocTrap ||
            InterlockedCompareExchange(&g_allocTrapArmed, 0, 0) == 0) {
            return false;
        }
        InterlockedExchange(&g_allocTrapArmed, 0);

        unsigned char current = 0;
        if (!ReadRemote(process, allocTrap, &current, 1) || current != 0xCC) {
            Out("[debug] allocate int3 byte missing at trap");
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }

        HANDLE eventThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                        event.dwThreadId);
        if (eventThread) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(eventThread, &context)) {
                Out("[debug] allocate process=%p base=%p zeroBits=%p size=%p tid=%lu",
                    reinterpret_cast<void*>(context.Rcx), reinterpret_cast<void*>(context.Rdx),
                    reinterpret_cast<void*>(context.R8), reinterpret_cast<void*>(context.R9),
                    static_cast<unsigned long>(event.dwThreadId));

                ULONG_PTR stackArgs[2] = {};
                const uintptr_t rsp = static_cast<uintptr_t>(context.Rsp);
                if (ReadRemote(process, rsp + 0x20, stackArgs, sizeof(stackArgs))) {
                    Out("[debug] allocate stack alloc=%llX protect=%llX",
                        static_cast<unsigned long long>(stackArgs[0]),
                        static_cast<unsigned long long>(stackArgs[1]));
                    ULONG_PTR baseAddress = 0;
                    if (ReadRemote(process, static_cast<uintptr_t>(context.Rdx), &baseAddress,
                                   sizeof(baseAddress))) {
                        Out("[debug] allocate baseValue=%p",
                            reinterpret_cast<void*>(baseAddress));
                    }
                    ULONG_PTR regionSize = 0;
                    if (ReadRemote(process, static_cast<uintptr_t>(context.R9), &regionSize,
                                   sizeof(regionSize))) {
                        Out("[debug] allocate sizeValue=%p",
                            reinterpret_cast<void*>(regionSize));
                    }
                } else {
                    Out("[debug] allocate stack args unreadable err=%lu", GetLastError());
                }

                context.Rip = static_cast<ULONG_PTR>(allocTrap);
                context.Dr0 = 0;
                context.Dr1 = 0;
                context.Dr2 = 0;
                context.Dr3 = 0;
                context.Dr6 = 0;
                context.Dr7 = 0;
                Out("[debug] allocate debug registers clear=%s",
                    SetThreadContext(eventThread, &context) != FALSE ? "yes" : "no");
            } else {
                Out("[debug] allocate context unreadable err=%lu", GetLastError());
            }
            CloseHandle(eventThread);
        } else {
            Out("[debug] OpenThread for allocate trap failed err=%lu", GetLastError());
        }

        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, allocTrap, &trapByte, &g_allocTrapOriginal, 1,
                             "allocate int3 restore")) {
            Out("[debug] allocate int3 removed");
        } else {
            Out("[debug] allocate int3 removal failed");
        }
        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
        return true;
    }

    void RestoreAllocTrap(HANDLE process, uintptr_t address)
    {
        if (!address || InterlockedCompareExchange(&g_allocTrapArmed, 0, 0) == 0) { return; }
        unsigned char current = 0;
        if (!ReadRemote(process, address, &current, 1) || current != 0xCC) {
            InterlockedExchange(&g_allocTrapArmed, 0);
            return;
        }
        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, address, &trapByte, &g_allocTrapOriginal, 1,
                             "allocate int3 cleanup")) {
            Out("[debug] allocate int3 restored before detach");
        }
        InterlockedExchange(&g_allocTrapArmed, 0);
    }

    // The object creator reaches Referee+0x612F4B with r8 pointing at a stack
    // OBJECT_ATTRIBUTES. Clear its +0x20 SecurityDescriptor so the supplied
    // DACL cannot deny creation, then arm the inner import trap after the
    // wrapper has been unpacked. ObjectName is cleared there too, because
    // reopening the pre-existing named section with SECTION_ALL_ACCESS is what
    // actually returns STATUS_ACCESS_DENIED. No Referee code byte is changed
    // and no object is fabricated.
    bool HandleCreateSectionTrap(HANDLE process, const DEBUG_EVENT& event)
    {
        if (event.dwDebugEventCode != kExceptionDebugEvent) { return false; }
        const auto& info = event.u.Exception;
        if (info.ExceptionRecord.ExceptionCode != kStatusBreakpoint ||
            reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress) !=
                g_createSectionTrap ||
            InterlockedCompareExchange(&g_createSectionArmed, 0, 0) == 0) {
            return false;
        }
        InterlockedExchange(&g_createSectionArmed, 0);

        unsigned char current = 0;
        if (!ReadRemote(process, g_createSectionTrap, &current, 1) || current != 0xCC) {
            Out("[debug] create section int3 byte missing at trap");
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }

        HANDLE eventThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                        event.dwThreadId);
        if (eventThread) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(eventThread, &context)) {
                const uintptr_t attributes = static_cast<uintptr_t>(context.R8);
                ULONG_PTR descriptor = 0;
                if (attributes && ReadRemote(process, attributes + 0x20, &descriptor,
                                             sizeof(descriptor))) {
                    Out("[debug] create section object attributes=%p security descriptor=%p",
                        reinterpret_cast<void*>(attributes),
                        reinterpret_cast<void*>(descriptor));
                    const ULONG_PTR cleared = 0;
                    if (WriteRemote(process, attributes + 0x20, &cleared, sizeof(cleared))) {
                        Out("[debug] create section security descriptor cleared");
                    } else {
                        Out("[debug] create section security descriptor clear failed err=%lu",
                            GetLastError());
                    }
                } else {
                    Out("[debug] create section object attributes unreadable=%p",
                        reinterpret_cast<void*>(attributes));
                }
                // INT3 replaced the first byte of the five-byte call, so RIP is
                // one byte past the real instruction.
                context.Rip = static_cast<ULONG_PTR>(g_createSectionTrap);
                context.Dr0 = 0;
                context.Dr1 = 0;
                context.Dr2 = 0;
                context.Dr3 = 0;
                context.Dr6 = 0;
                context.Dr7 = 0;
                Out("[debug] create section debug registers clear=%s",
                    SetThreadContext(eventThread, &context) != FALSE ? "yes" : "no");
            } else {
                Out("[debug] create section context unreadable err=%lu", GetLastError());
            }
            CloseHandle(eventThread);
        } else {
            Out("[debug] OpenThread for create section trap failed err=%lu", GetLastError());
        }

        // Arm the inner import trap now, after the caller has reached the
        // wrapper. The wrapper's code lives in a region Themida can rewrite
        // while the module unpacks, so an earlier int3 there is not reliable.
        unsigned char apiByte = 0;
        if (g_sectionApiTrap &&
            InterlockedCompareExchange(&g_sectionApiArmed, 0, 0) == 0 &&
            ReadRemote(process, g_sectionApiTrap, &apiByte, 1)) {
            Out("[debug] create section api trap byte=%02X", apiByte);
            if (apiByte != 0xCC) {
                g_sectionApiOriginal = apiByte;
                const unsigned char trap = 0xCC;
                if (PatchRemoteBytes(process, g_sectionApiTrap, &apiByte, &trap, 1,
                                     "section api int3 late")) {
                    InterlockedExchange(&g_sectionApiArmed, 1);
                    Out("[debug] section api int3 armed at %p after create section call",
                        reinterpret_cast<void*>(g_sectionApiTrap));
                } else {
                    Out("[debug] section api int3 late arm failed");
                }
            } else {
                InterlockedExchange(&g_sectionApiArmed, 1);
                Out("[debug] section api int3 already armed at outer trap");
            }
        }

        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, g_createSectionTrap, &trapByte,
                             &g_createSectionOriginal, 1, "create section int3 restore")) {
            Out("[debug] create section int3 removed");
        } else {
            Out("[debug] create section int3 removal failed");
        }
        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
        return true;
    }

    void RestoreCreateSectionTrap(HANDLE process)
    {
        if (!g_createSectionTrap ||
            InterlockedCompareExchange(&g_createSectionArmed, 0, 0) == 0) {
            return;
        }
        unsigned char current = 0;
        if (!ReadRemote(process, g_createSectionTrap, &current, 1) || current != 0xCC) {
            InterlockedExchange(&g_createSectionArmed, 0);
            return;
        }
        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, g_createSectionTrap, &trapByte,
                             &g_createSectionOriginal, 1, "create section int3 cleanup")) {
            Out("[debug] create section int3 restored before detach");
        }
        InterlockedExchange(&g_createSectionArmed, 0);
    }

    // The object creator's section wrapper resolves its import lazily and
    // calls it at Referee+0x21E4053. HandleCreateSectionTrap arms this site
    // after the wrapper is unpacked. The trap identifies the resolved function
    // and its seven arguments, then clears OBJECT_ATTRIBUTES.ObjectName so the
    // call creates a fresh unnamed section with the process default DACL.
    // ntdll is mapped at the same address in injector and target, so the local
    // NtCreateSection address is a valid comparison for the resolved pointer.
    bool HandleSectionApiTrap(HANDLE process, const DEBUG_EVENT& event)
    {
        if (event.dwDebugEventCode != kExceptionDebugEvent) { return false; }
        const auto& info = event.u.Exception;
        if (info.ExceptionRecord.ExceptionCode != kStatusBreakpoint ||
            reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress) !=
                g_sectionApiTrap ||
            InterlockedCompareExchange(&g_sectionApiArmed, 0, 0) == 0) {
            return false;
        }
        InterlockedExchange(&g_sectionApiArmed, 0);
        InterlockedExchange(&g_sectionApiObserved, 1);

        unsigned char current = 0;
        if (!ReadRemote(process, g_sectionApiTrap, &current, 1) || current != 0xCC) {
            Out("[debug] section api int3 byte missing at trap");
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }

        HANDLE eventThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                        event.dwThreadId);
        if (eventThread) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(eventThread, &context)) {
                ULONG_PTR api = 0;
                if (ReadRemote(process, static_cast<uintptr_t>(context.Rsp) + 0x60, &api,
                               sizeof(api))) {
                    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                    FARPROC local = ntdll ? GetProcAddress(ntdll, "NtCreateSection") : nullptr;
                    Out("[debug] section api ptr=%p ntdll=%p match=%s",
                        reinterpret_cast<void*>(api), reinterpret_cast<void*>(local),
                        local && api == reinterpret_cast<ULONG_PTR>(local) ? "yes" : "no");
                } else {
                    Out("[debug] section api pointer unreadable");
                }

                ULONG_PTR stackArgs[3] = {};
                if (ReadRemote(process, static_cast<uintptr_t>(context.Rsp) + 0x20, stackArgs,
                               sizeof(stackArgs))) {
                    Out("[debug] section api args rcx=%p access=%08lX attributes=%p "
                        "max_size=%p protect=%lu alloc=%08lX file=%p",
                        reinterpret_cast<void*>(context.Rcx),
                        static_cast<unsigned long>(context.Rdx),
                        reinterpret_cast<void*>(context.R8),
                        reinterpret_cast<void*>(context.R9),
                        static_cast<unsigned long>(stackArgs[0]),
                        static_cast<unsigned long>(stackArgs[1]),
                        reinterpret_cast<void*>(stackArgs[2]));
                }

                const uintptr_t attributes = static_cast<uintptr_t>(context.R8);
                ULONG_PTR fields[6] = {};
                if (attributes && ReadRemote(process, attributes, fields, sizeof(fields))) {
                    ULONG_PTR nameFields[2] = {};
                    wchar_t name[128] = {};
                    const uintptr_t objectName = static_cast<uintptr_t>(fields[2]);
                    if (objectName &&
                        ReadRemote(process, objectName, nameFields, sizeof(nameFields))) {
                        const unsigned short length =
                            static_cast<unsigned short>(nameFields[0] & 0xFFFF);
                        const std::size_t chars = length / sizeof(wchar_t);
                        const std::size_t take = chars < 127 ? chars : 127;
                        if (take && nameFields[1]) {
                            (void)ReadRemote(process, static_cast<uintptr_t>(nameFields[1]),
                                             name, take * sizeof(wchar_t));
                        }
                        name[take] = L'\0';
                    }
                    Out("[debug] section api object len=%lu root=%p name=%p attrs=%08lX "
                        "sd=%p qos=%p text='%ls'",
                        static_cast<unsigned long>(fields[0] & 0xFFFFFFFFULL),
                        reinterpret_cast<void*>(fields[1]),
                        reinterpret_cast<void*>(fields[2]),
                        static_cast<unsigned long>(fields[3] & 0xFFFFFFFFULL),
                        reinterpret_cast<void*>(fields[4]),
                        reinterpret_cast<void*>(fields[5]), name);

                    // A named section under \BaseNamedObjects can already
                    // exist with a DACL that denies SECTION_ALL_ACCESS. Clear
                    // the name so this call creates a fresh unnamed section
                    // with the process's default DACL instead of reopening it.
                    const ULONG_PTR noName = 0;
                    if (objectName &&
                        WriteRemote(process, attributes + 0x10, &noName, sizeof(noName))) {
                        Out("[debug] section api object name cleared");
                    } else {
                        Out("[debug] section api object name clear failed err=%lu",
                            GetLastError());
                    }
                }

                // INT3 replaced the first byte of the indirect call, so RIP is
                // one byte past the real instruction.
                context.Rip = static_cast<ULONG_PTR>(g_sectionApiTrap);
                context.Dr0 = 0;
                context.Dr1 = 0;
                context.Dr2 = 0;
                context.Dr3 = 0;
                context.Dr6 = 0;
                context.Dr7 = 0;
                Out("[debug] section api debug registers clear=%s",
                    SetThreadContext(eventThread, &context) != FALSE ? "yes" : "no");
            } else {
                Out("[debug] section api context unreadable err=%lu", GetLastError());
            }
            CloseHandle(eventThread);
        } else {
            Out("[debug] OpenThread for section api trap failed err=%lu", GetLastError());
        }

        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, g_sectionApiTrap, &trapByte, &g_sectionApiOriginal, 1,
                             "section api int3 restore")) {
            Out("[debug] section api int3 removed");
        } else {
            Out("[debug] section api int3 removal failed");
        }
        (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
        return true;
    }

    void RestoreSectionApiTrap(HANDLE process)
    {
        if (!g_sectionApiTrap ||
            InterlockedCompareExchange(&g_sectionApiArmed, 0, 0) == 0) {
            return;
        }
        unsigned char current = 0;
        if (!ReadRemote(process, g_sectionApiTrap, &current, 1) || current != 0xCC) {
            InterlockedExchange(&g_sectionApiArmed, 0);
            return;
        }
        const unsigned char trapByte = 0xCC;
        if (PatchRemoteBytes(process, g_sectionApiTrap, &trapByte, &g_sectionApiOriginal, 1,
                             "section api int3 cleanup")) {
            Out("[debug] section api int3 restored before detach");
        }
        InterlockedExchange(&g_sectionApiArmed, 0);
    }

    // Diagnostic is on by default; SCHOOLSOUT_TRACE_QUIT=0 disables it. A
    // self-rearming int3 on user32!DispatchMessageW logs WM_DESTROY/WM_CLOSE/
    // WM_QUIT with the return address into Unity's window procedure. No patch
    // decision depends on this trace, and the byte is restored before detach.
    bool QuitTraceEnabled()
    {
        wchar_t value[8] = {};
        const DWORD length =
            GetEnvironmentVariableW(L"SCHOOLSOUT_TRACE_QUIT", value, _countof(value));
        if (!length) { return true; }
        if (value[0] == L'0' || value[0] == L'f' || value[0] == L'F') { return false; }
        return value[0] == L'1' || value[0] == L't' || value[0] == L'T';
    }

    bool ArmQuitTrace(HANDLE process)
    {
        if (!QuitTraceEnabled()) { return false; }
        HMODULE user32 = LoadLibraryW(L"user32.dll");
        FARPROC proc = user32 ? GetProcAddress(user32, "DispatchMessageW") : nullptr;
        if (!proc) {
            Out("[quit] DispatchMessageW not found");
            return false;
        }
        g_quitTraceTrap = reinterpret_cast<uintptr_t>(proc);
        if (!ReadRemote(process, g_quitTraceTrap, &g_quitTraceOriginal, 1)) {
            Out("[quit] trap byte unreadable");
            g_quitTraceTrap = 0;
            return false;
        }
        const unsigned char trap = 0xCC;
        if (!PatchRemoteBytes(process, g_quitTraceTrap, &g_quitTraceOriginal, &trap, 1,
                              "quit trace int3")) {
            Out("[quit] trap arm failed");
            g_quitTraceTrap = 0;
            return false;
        }
        InterlockedExchange(&g_quitTraceArmed, 1);
        InterlockedExchange(&g_quitTraceStepping, 0);
        InterlockedExchange(&g_quitTraceSawFirst, 0);
        Out("[quit] DispatchMessageW trace armed at %p", reinterpret_cast<void*>(g_quitTraceTrap));
        return true;
    }

    void RestoreQuitTrace(HANDLE process)
    {
        if (!g_quitTraceTrap) { return; }
        unsigned char current = 0;
        if (ReadRemote(process, g_quitTraceTrap, &current, 1) && current == 0xCC) {
            if (WriteCodeByte(process, g_quitTraceTrap, g_quitTraceOriginal)) {
                Out("[quit] trace int3 restored before detach");
            } else {
                Out("[quit] trace restore failed err=%lu", GetLastError());
            }
        }
        if (InterlockedCompareExchange(&g_quitTraceStepping, 0, 0) != 0 && g_quitTraceThread) {
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                       g_quitTraceThread);
            if (thread) {
                CONTEXT context{};
                context.ContextFlags = CONTEXT_FULL;
                if (GetThreadContext(thread, &context)) {
                    context.EFlags &= ~0x100u;
                    (void)SetThreadContext(thread, &context);
                }
                CloseHandle(thread);
            }
        }
        InterlockedExchange(&g_quitTraceArmed, 0);
        InterlockedExchange(&g_quitTraceStepping, 0);
        g_quitTraceTrap = 0;
    }

    bool HandleQuitTrace(HANDLE process, const DEBUG_EVENT& event)
    {
        if (!g_quitTraceTrap || event.dwDebugEventCode != kExceptionDebugEvent) { return false; }
        const auto& info = event.u.Exception;
        const DWORD code = info.ExceptionRecord.ExceptionCode;
        const uintptr_t address =
            reinterpret_cast<uintptr_t>(info.ExceptionRecord.ExceptionAddress);

        if (code == kStatusBreakpoint && address == g_quitTraceTrap &&
            InterlockedCompareExchange(&g_quitTraceArmed, 0, 0) != 0) {
            InterlockedExchange(&g_quitTraceArmed, 0);
            unsigned char current = 0;
            if (!ReadRemote(process, g_quitTraceTrap, &current, 1) || current != 0xCC) {
                Out("[quit] trap byte missing at hit");
                (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
                return true;
            }

            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                       event.dwThreadId);
            bool stepping = false;
            if (thread) {
                CONTEXT context{};
                context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(thread, &context)) {
                    const uintptr_t msg = static_cast<uintptr_t>(context.Rcx);
                    DWORD message = 0;
                    ULONG_PTR messageWords[4] = {};
                    ULONG_PTR returnAddress = 0;
                    (void)ReadRemote(process, msg, messageWords, sizeof(messageWords));
                    (void)ReadRemote(process, msg + 8, &message, sizeof(message));
                    (void)ReadRemote(process, static_cast<uintptr_t>(context.Rsp),
                                     &returnAddress, sizeof(returnAddress));
                    if (!InterlockedCompareExchange(&g_quitTraceSawFirst, 1, 0)) {
                        Out("[quit] first DispatchMessage msg=%04lX",
                            static_cast<unsigned long>(message));
                    }
                    if (message == kWmDestroy || message == kWmClose || message == kWmQuit) {
                        Out("[quit] DispatchMessage hwnd=%p msg=%04lX wParam=%p lParam=%p "
                            "from=%p",
                            reinterpret_cast<void*>(messageWords[0]),
                            static_cast<unsigned long>(message),
                            reinterpret_cast<void*>(messageWords[2]),
                            reinterpret_cast<void*>(messageWords[3]),
                            reinterpret_cast<void*>(returnAddress));
                    }
                    if (!WriteCodeByte(process, g_quitTraceTrap, g_quitTraceOriginal)) {
                        Out("[quit] trap restore failed err=%lu", GetLastError());
                    }
                    context.Rip = static_cast<ULONG_PTR>(g_quitTraceTrap);
                    context.Dr0 = 0;
                    context.Dr1 = 0;
                    context.Dr2 = 0;
                    context.Dr3 = 0;
                    context.Dr6 = 0;
                    context.Dr7 = 0;
                    context.EFlags |= 0x100u;
                    g_quitTraceThread = event.dwThreadId;
                    InterlockedExchange(&g_quitTraceStepping, 1);
                    stepping = SetThreadContext(thread, &context) != FALSE;
                    if (!stepping) {
                        Out("[quit] single-step setup failed err=%lu", GetLastError());
                        InterlockedExchange(&g_quitTraceStepping, 0);
                    }
                } else {
                    Out("[quit] context unreadable err=%lu", GetLastError());
                }
                CloseHandle(thread);
            } else {
                Out("[quit] OpenThread failed err=%lu", GetLastError());
            }
            if (!stepping) {
                const unsigned char trap = 0xCC;
                if (WriteCodeByte(process, g_quitTraceTrap, trap)) {
                    InterlockedExchange(&g_quitTraceArmed, 1);
                }
            }
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }

        if (code == kStatusSingleStep &&
            InterlockedCompareExchange(&g_quitTraceStepping, 0, 0) != 0 &&
            event.dwThreadId == g_quitTraceThread) {
            InterlockedExchange(&g_quitTraceStepping, 0);
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                       event.dwThreadId);
            if (thread) {
                CONTEXT context{};
                context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(thread, &context)) {
                    context.EFlags &= ~0x100u;
                    context.Dr0 = 0;
                    context.Dr1 = 0;
                    context.Dr2 = 0;
                    context.Dr3 = 0;
                    context.Dr6 = 0;
                    context.Dr7 = 0;
                    if (!SetThreadContext(thread, &context)) {
                        Out("[quit] single-step clear failed err=%lu", GetLastError());
                    }
                } else {
                    Out("[quit] single-step context unreadable err=%lu", GetLastError());
                }
                CloseHandle(thread);
            }
            const unsigned char trap = 0xCC;
            if (WriteCodeByte(process, g_quitTraceTrap, trap)) {
                InterlockedExchange(&g_quitTraceArmed, 1);
            } else {
                Out("[quit] rearm failed err=%lu", GetLastError());
            }
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }
        return false;
    }

    // One-shot int3 sites immediately after each API call in the object
    // creator. They log eax even if the call began before the traps were armed,
    // so the helper returning STATUS_ACCESS_DENIED can be identified without
    // changing any argument or result.
    bool HandleStatusTraps(HANDLE process, const DEBUG_EVENT& event)
    {
        if (event.dwDebugEventCode != kExceptionDebugEvent ||
            event.u.Exception.ExceptionRecord.ExceptionCode != kStatusBreakpoint) {
            return false;
        }
        const uintptr_t address = reinterpret_cast<uintptr_t>(
            event.u.Exception.ExceptionRecord.ExceptionAddress);
        for (StatusTrap& trap : g_statusTraps) {
            if (!trap.address || address != trap.address ||
                InterlockedCompareExchange(&trap.armed, 0, 0) == 0) {
                continue;
            }
            InterlockedExchange(&trap.armed, 0);

            unsigned char current = 0;
            if (!ReadRemote(process, trap.address, &current, 1) || current != 0xCC) {
                Out("[debug] object creator %s int3 byte missing at trap", trap.label);
                (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
                return true;
            }

            HANDLE eventThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
                                            event.dwThreadId);
            if (eventThread) {
                CONTEXT context{};
                context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(eventThread, &context)) {
                    Out("[debug] object creator %s eax=%08lX rsp=%p tid=%lu", trap.label,
                        static_cast<unsigned long>(context.Rax),
                        reinterpret_cast<void*>(context.Rsp),
                        static_cast<unsigned long>(event.dwThreadId));
                    context.Rip = static_cast<ULONG_PTR>(trap.address);
                    context.Dr0 = 0;
                    context.Dr1 = 0;
                    context.Dr2 = 0;
                    context.Dr3 = 0;
                    context.Dr6 = 0;
                    context.Dr7 = 0;
                    Out("[debug] object creator %s debug registers clear=%s", trap.label,
                        SetThreadContext(eventThread, &context) != FALSE ? "yes" : "no");
                } else {
                    Out("[debug] object creator %s context unreadable err=%lu", trap.label,
                        GetLastError());
                }
                CloseHandle(eventThread);
            } else {
                Out("[debug] OpenThread for object creator %s trap failed err=%lu", trap.label,
                    GetLastError());
            }

            const unsigned char trapByte = 0xCC;
            if (PatchRemoteBytes(process, trap.address, &trapByte, &trap.original, 1,
                                 trap.label)) {
                Out("[debug] object creator %s int3 removed", trap.label);
            } else {
                Out("[debug] object creator %s int3 removal failed", trap.label);
            }
            (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
            return true;
        }
        return false;
    }

    void RestoreStatusTraps(HANDLE process)
    {
        for (StatusTrap& trap : g_statusTraps) {
            if (!trap.address || InterlockedCompareExchange(&trap.armed, 0, 0) == 0) { continue; }
            unsigned char current = 0;
            if (!ReadRemote(process, trap.address, &current, 1) || current != 0xCC) {
                InterlockedExchange(&trap.armed, 0);
                continue;
            }
            const unsigned char trapByte = 0xCC;
            if (PatchRemoteBytes(process, trap.address, &trapByte, &trap.original, 1,
                                 trap.label)) {
                Out("[debug] object creator %s int3 restored before detach", trap.label);
            }
            InterlockedExchange(&trap.armed, 0);
        }
    }

    DWORD WINAPI MonitorSessionBranch(LPVOID)
    {
        const unsigned char expected[SchoolsOut::Offsets::Referee::SessionFallbackBranchSize] = {
            0x0F, 0x84, 0x07, 0x03, 0x00, 0x00};
        const unsigned char nops[SchoolsOut::Offsets::Referee::SessionFallbackBranchSize] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (!InterlockedCompareExchange(&g_monitorStop, 0, 0) && GetTickCount64() < deadline) {
            // Only the fallback branch is changed. The success-path store at
            // Referee+0x69A7CD stays intact so the initialized local object is
            // published through the owner pointer.
            bool branchPatched = false;
            if (RemoteBytesEqual(g_monitorProcess, g_monitorBranch, nops, sizeof(nops))) {
                branchPatched = true;
            } else if (PatchRemoteBytes(g_monitorProcess, g_monitorBranch, expected, nops,
                                        SchoolsOut::Offsets::Referee::SessionFallbackBranchSize,
                                        "session fallback branch")) {
                branchPatched = true;
            }
            if (branchPatched) {
                Out("[monitor] session fallback branch patched%s",
                    RemoteBytesEqual(g_monitorProcess, g_monitorBranch, nops, sizeof(nops))
                        ? " (already confirmed)"
                        : "");
                // A software breakpoint is process-wide, unlike a hardware debug
                // register, so it cannot miss the thread that runs session init.
                // The original byte is saved and restored by the debugger.
                if (!InterlockedCompareExchange(&g_resultTrapArmed, 0, 0) &&
                    g_monitorResult &&
                    ReadRemote(g_monitorProcess, g_monitorResult, &g_resultTrapOriginal, 1) &&
                    g_resultTrapOriginal != 0xCC) {
                    const unsigned char trap = 0xCC;
                    if (PatchRemoteBytes(g_monitorProcess, g_monitorResult,
                                         &g_resultTrapOriginal, &trap, 1,
                                         "session result int3")) {
                        InterlockedExchange(&g_resultTrapArmed, 1);
                        Out("[monitor] session result int3 armed at %p",
                            reinterpret_cast<void*>(g_monitorResult));
                    } else {
                        Out("[monitor] session result int3 arm failed");
                    }
                }
                // The same process-wide technique captures the arguments of the
                // indirect NtMapViewOfSection call made by the failing object
                // creator. Both traps are one-shot and are restored by the
                // debugger, so neither survives detach.
                if (!InterlockedCompareExchange(&g_mapViewTrapArmed, 0, 0) &&
                    g_mapViewTrap &&
                    ReadRemote(g_monitorProcess, g_mapViewTrap, &g_mapViewTrapOriginal, 1) &&
                    g_mapViewTrapOriginal != 0xCC) {
                    const unsigned char trap = 0xCC;
                    if (PatchRemoteBytes(g_monitorProcess, g_mapViewTrap,
                                         &g_mapViewTrapOriginal, &trap, 1,
                                         "map view int3")) {
                        InterlockedExchange(&g_mapViewTrapArmed, 1);
                        Out("[monitor] map view int3 armed at %p",
                            reinterpret_cast<void*>(g_mapViewTrap));
                    } else {
                        Out("[monitor] map view int3 arm failed");
                    }
                }
                if (!InterlockedCompareExchange(&g_allocTrapArmed, 0, 0) &&
                    g_allocTrap &&
                    ReadRemote(g_monitorProcess, g_allocTrap, &g_allocTrapOriginal, 1) &&
                    g_allocTrapOriginal != 0xCC) {
                    const unsigned char trap = 0xCC;
                    if (PatchRemoteBytes(g_monitorProcess, g_allocTrap,
                                         &g_allocTrapOriginal, &trap, 1,
                                         "allocate int3")) {
                        InterlockedExchange(&g_allocTrapArmed, 1);
                        Out("[monitor] allocate int3 armed at %p",
                            reinterpret_cast<void*>(g_allocTrap));
                    } else {
                        Out("[monitor] allocate int3 arm failed");
                    }
                }
                if (!InterlockedCompareExchange(&g_createSectionArmed, 0, 0) &&
                    g_createSectionTrap &&
                    ReadRemote(g_monitorProcess, g_createSectionTrap,
                               &g_createSectionOriginal, 1) &&
                    g_createSectionOriginal != 0xCC) {
                    const unsigned char trap = 0xCC;
                    if (PatchRemoteBytes(g_monitorProcess, g_createSectionTrap,
                                         &g_createSectionOriginal, &trap, 1,
                                         "create section int3")) {
                        InterlockedExchange(&g_createSectionArmed, 1);
                        Out("[monitor] create section int3 armed at %p",
                            reinterpret_cast<void*>(g_createSectionTrap));
                    } else {
                        Out("[monitor] create section int3 arm failed");
                    }
                }
                // The inner import call is armed by HandleCreateSectionTrap,
                // immediately before the wrapper runs. Arming it while the
                // module is still packed lets Themida overwrite the int3.
                for (StatusTrap& trap : g_statusTraps) {
                    if (!trap.address || InterlockedCompareExchange(&trap.armed, 0, 0)) { continue; }
                    if (!ReadRemote(g_monitorProcess, trap.address, &trap.original, 1) ||
                        trap.original == 0xCC) {
                        continue;
                    }
                    const unsigned char trapByte = 0xCC;
                    if (PatchRemoteBytes(g_monitorProcess, trap.address, &trap.original,
                                         &trapByte, 1, trap.label)) {
                        InterlockedExchange(&trap.armed, 1);
                        Out("[monitor] object creator %s int3 armed at %p", trap.label,
                            reinterpret_cast<void*>(trap.address));
                    } else {
                        Out("[monitor] object creator %s int3 arm failed", trap.label);
                    }
                }
                InterlockedExchange(&g_monitorComplete, 1);
                return 0;
            }
            Sleep(1);
        }
        return 1;
    }

    void StopMonitor()
    {
        InterlockedExchange(&g_monitorStop, 1);
        if (!g_monitorThread) { return; }
        WaitForSingleObject(g_monitorThread, 2000);
        CloseHandle(g_monitorThread);
        g_monitorThread = nullptr;
    }

    uintptr_t BootstrapReferee(HANDLE process)
    {
        const uintptr_t referee = ModuleBase(process, L"Referee.dll");
        if (!referee) {
            Out("[bootstrap] Referee.dll not visible at debugger breakpoint");
            return 0;
        }
        Out("[bootstrap] Referee.dll base=%016llX", static_cast<unsigned long long>(referee));
        const uintptr_t flag = referee + FailFastFlag;
        unsigned char value = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<void*>(flag), &value, 1, &read) || read != 1) {
            Out("[bootstrap] fail-fast flag read failed err=%lu", GetLastError());
            return 0;
        }
        if (value == PackedFailFastFlag) {
            PatchRemoteByte(process, flag, PackedFailFastFlag, DecryptedFailFastOff, "packed fail-fast");
        } else if (value == 0x02) {
            PatchRemoteByte(process, flag, 0x02, 0x00, "unpacked fail-fast");
        } else {
            Out("[bootstrap] fail-fast byte=0x%02X; no change", value);
        }
        return referee;
    }

    DWORD DebugContinueStatus(const DEBUG_EVENT& event)
    {
        return event.dwDebugEventCode == kExceptionDebugEvent ? kDbgExceptionNotHandled : kDbgContinue;
    }

    bool ContinueEvent(const DEBUG_EVENT& event)
    {
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DebugContinueStatus(event))) {
            Out("[debug] ContinueDebugEvent failed err=%lu", GetLastError());
            return false;
        }
        return true;
    }

    // With DEBUG_PROCESS, the initial STATUS_BREAKPOINT is delivered after the
    // loader has mapped every static import but before the executable's entry
    // point runs. That is the first point where Referee.dll is both visible and
    // still carrying its packed fail-fast byte.
    bool WaitForInitialBreakpoint(DWORD pid, DWORD& threadId)
    {
        for (int count = 0; count < 128; ++count) {
            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, INFINITE)) {
                Out("[debug] WaitForDebugEvent failed err=%lu", GetLastError());
                return false;
            }
            if (event.dwDebugEventCode == kExceptionDebugEvent) {
                const auto& info = event.u.Exception;
                if (info.ExceptionRecord.ExceptionCode == kStatusBreakpoint) {
                    Out("[debug] initial breakpoint at %p",
                        info.ExceptionRecord.ExceptionAddress);
                    threadId = event.dwThreadId;
                    return true;
                }
                Out("[debug] pre-breakpoint exception %08lX at %p",
                    info.ExceptionRecord.ExceptionCode,
                    info.ExceptionRecord.ExceptionAddress);
            }
            if (!ContinueEvent(event)) { return false; }
        }
        Out("[debug] initial breakpoint not observed for pid %lu", pid);
        return false;
    }

    bool ContinueInitialBreakpoint(DWORD pid, DWORD threadId)
    {
        if (!ContinueDebugEvent(pid, threadId, kDbgContinue)) {
            Out("[debug] initial breakpoint continue failed err=%lu", GetLastError());
            return false;
        }
        Out("[debug] resumed from initial breakpoint");
        return true;
    }

    bool WaitForLoaderThread(HANDLE process, HANDLE loaderThread, bool debuggerAttached,
                             uintptr_t sessionTrap, uintptr_t mapViewTrap, uintptr_t allocTrap)
    {
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (GetTickCount64() < deadline) {
            if (WaitForSingleObject(loaderThread, 0) != WAIT_TIMEOUT) { return true; }
            if (debuggerAttached) {
                DEBUG_EVENT event{};
                if (WaitForDebugEvent(&event, 50)) {
                    if (HandleResultTrap(process, event, sessionTrap)) { continue; }
                    if (HandleMapViewTrap(process, event, mapViewTrap)) { continue; }
                    if (HandleAllocTrap(process, event, allocTrap)) { continue; }
                    if (HandleCreateSectionTrap(process, event)) { continue; }
                    if (HandleSectionApiTrap(process, event)) { continue; }
                    if (HandleStatusTraps(process, event)) { continue; }
                    if (event.dwDebugEventCode == kExceptionDebugEvent) {
                        const auto& info = event.u.Exception;
                        Out("[debug] exception %08lX at %p first=%lu",
                            info.ExceptionRecord.ExceptionCode,
                            info.ExceptionRecord.ExceptionAddress,
                            static_cast<unsigned long>(info.dwFirstChance));
                    } else if (event.dwDebugEventCode == kExitProcessDebugEvent) {
                        Out("[debug] target exited during injection");
                    }
                    (void)ContinueEvent(event);
                }
            } else {
                Sleep(20);
            }
        }
        return false;
    }

    void DrainDebugEvents()
    {
        for (int count = 0; count < 512; ++count) {
            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, 0)) { return; }
            (void)ContinueEvent(event);
        }
    }

    void DetachDebugger(DWORD pid, bool& attached)
    {
        if (!attached) { return; }
        DrainDebugEvents();
        if (!DebugActiveProcessStop(pid)) {
            Out("[debug] detach failed err=%lu", GetLastError());
            return;
        }
        attached = false;
        Out("[debug] debugger detached");
    }

    void LogMemoryQwords(HANDLE process, const char* label, uintptr_t address, int count)
    {
        unsigned long long values[8] = {};
        if (!address || count <= 0 || count > 8 ||
            !ReadRemote(process, address, values, sizeof(values[0]) * count)) {
            Out("[fault] %s @%p unreadable", label, reinterpret_cast<void*>(address));
            return;
        }
        Out("[fault] %s @%p %016llX %016llX %016llX %016llX", label,
            reinterpret_cast<void*>(address), values[0], values[1], values[2], values[3]);
        if (count > 4) {
            Out("[fault] %s+0x20 %016llX %016llX %016llX %016llX", label,
                values[4], values[5], values[6], values[7]);
        }
    }

    void LogFaultBytes(HANDLE process, const char* label, uintptr_t address, std::size_t size)
    {
        unsigned char bytes[64] = {};
        if (!address || size > sizeof(bytes) || !ReadRemote(process, address, bytes, size)) {
            Out("[fault] %s @%p unreadable", label, reinterpret_cast<void*>(address));
            return;
        }
        char text[192] = {};
        std::size_t used = 0;
        for (std::size_t index = 0; index < size && used + 4 < sizeof(text); ++index) {
            used += static_cast<std::size_t>(_snprintf_s(text + used, sizeof(text) - used,
                                                        _TRUNCATE, "%02X ", bytes[index]));
        }
        Out("[fault] %s @%p %s", label, reinterpret_cast<void*>(address), text);
    }

    // Capture first-chance native access violations after the deterministic
    // patch is confirmed. This logger never arms a trap or changes registers;
    // it only records the faulting context while the debugger is still attached.
    void LogNativeFault(HANDLE process, const DEBUG_EVENT& event, uintptr_t referee)
    {
        const EXCEPTION_RECORD& record = event.u.Exception.ExceptionRecord;
        const uintptr_t address = reinterpret_cast<uintptr_t>(record.ExceptionAddress);
        const unsigned long long rva = address >= referee && address - referee < 0x10000000
            ? static_cast<unsigned long long>(address - referee) : 0;
        Out("[fault] code=%08lX at %p referee_rva=%016llX tid=%lu first=%lu type=%llX access=%p",
            record.ExceptionCode, record.ExceptionAddress, rva, event.dwThreadId,
            static_cast<unsigned long>(event.u.Exception.dwFirstChance),
            static_cast<unsigned long long>(record.ExceptionInformation[0]),
            reinterpret_cast<void*>(record.ExceptionInformation[1]));
        if (address == referee + SessionAppendFault) {
            Out("[fault] known append-helper fault reached");
        }

        HANDLE faultThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE,
                                        event.dwThreadId);
        if (faultThread) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(faultThread, &context)) {
                Out("[fault] regs rip=%p rax=%p rcx=%p rdx=%p r8=%p r9=%p",
                    reinterpret_cast<void*>(context.Rip), reinterpret_cast<void*>(context.Rax),
                    reinterpret_cast<void*>(context.Rcx), reinterpret_cast<void*>(context.Rdx),
                    reinterpret_cast<void*>(context.R8), reinterpret_cast<void*>(context.R9));
                Out("[fault] regs r10=%p r11=%p rsp=%p rbp=%p dr0=%p dr1=%p",
                    reinterpret_cast<void*>(context.R10), reinterpret_cast<void*>(context.R11),
                    reinterpret_cast<void*>(context.Rsp), reinterpret_cast<void*>(context.Rbp),
                    reinterpret_cast<void*>(context.Dr0), reinterpret_cast<void*>(context.Dr1));
                Out("[fault] debug dr2=%p dr3=%p dr6=%llX dr7=%llX",
                    reinterpret_cast<void*>(context.Dr2), reinterpret_cast<void*>(context.Dr3),
                    static_cast<unsigned long long>(context.Dr6),
                    static_cast<unsigned long long>(context.Dr7));
                LogMemoryQwords(process, "rcx", static_cast<uintptr_t>(context.Rcx), 8);
                LogMemoryQwords(process, "rdx", static_cast<uintptr_t>(context.Rdx), 8);
                LogMemoryQwords(process, "r8", static_cast<uintptr_t>(context.R8), 8);
            } else {
                Out("[fault] GetThreadContext failed err=%lu", GetLastError());
            }
            CloseHandle(faultThread);
        } else {
            Out("[fault] OpenThread for fault tid failed err=%lu", GetLastError());
        }

        uintptr_t owner = 0;
        if (ReadRemote(process, referee + SessionObjectSlot, &owner, sizeof(owner))) {
            Out("[fault] session owner object=%p", reinterpret_cast<void*>(owner));
            LogMemoryQwords(process, "owner", owner, 8);
        } else {
            Out("[fault] session owner pointer unreadable");
        }
        LogFaultBytes(process, "access", static_cast<uintptr_t>(record.ExceptionInformation[1]), 32);
    }

    void CapturePostPatchFaults(HANDLE process, DWORD pid, uintptr_t referee, DWORD windowMs)
    {
        Out("[debug] post-patch fault capture for pid=%lu window=%lums", pid, windowMs);
        (void)ArmQuitTrace(process);
        const ULONGLONG deadline = GetTickCount64() + windowMs;
        int logged = 0;
        while (GetTickCount64() < deadline) {
            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, 50)) { continue; }
            if (HandleQuitTrace(process, event)) { continue; }
            if (event.dwDebugEventCode == kExceptionDebugEvent) {
                const DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
                if (code == kStatusAccessViolation) {
                    if (logged < 8) {
                        LogNativeFault(process, event, referee);
                        ++logged;
                    } else {
                        Out("[fault] additional access violations suppressed");
                    }
                } else {
                    Out("[debug] post-patch exception %08lX at %p first=%lu", code,
                        event.u.Exception.ExceptionRecord.ExceptionAddress,
                        static_cast<unsigned long>(event.u.Exception.dwFirstChance));
                }
                (void)ContinueEvent(event);
                continue;
            }
            if (event.dwDebugEventCode == kExitProcessDebugEvent) {
                Out("[debug] target exited during fault capture");
                (void)ContinueEvent(event);
                break;
            }
            (void)ContinueEvent(event);
        }
        RestoreQuitTrace(process);
        Out("[debug] post-patch fault capture window ended");
    }

    std::wstring EnvironmentVariable(const wchar_t* name)
    {
        const DWORD length = GetEnvironmentVariableW(name, nullptr, 0);
        if (!length) { return {}; }
        std::wstring value(length - 1, L'\0');
        if (!GetEnvironmentVariableW(name, value.data(), length)) { return {}; }
        return value;
    }

    bool LaunchGame(const std::wstring& root, const std::wstring& args, DWORD& pid, HANDLE& process,
                    HANDLE& thread)
    {
        const std::wstring executable = root + L"\\RecRoom.exe";
        std::wstring command = L"\"" + executable + L"\"";
        if (!args.empty()) {
            command += L" ";
            command += args;
        }

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION child{};
        // A debugger gives an initial breakpoint after the loader has mapped
        // Referee.dll but before the executable's entry point runs. A plain
        // suspended-process stop is too early: PEB->Ldr is still null there.
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                            DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, nullptr, root.c_str(),
                            &startup, &child)) {
            Out("[inject] CreateProcessW failed err=%lu", GetLastError());
            return false;
        }
        pid = child.dwProcessId;
        process = child.hProcess;
        thread = child.hThread;
        Out("[inject] launched RecRoom.exe under debugger pid=%lu args=%ls", pid, args.c_str());
        return true;
    }

    bool CreateLoaderThread(HANDLE process, const std::wstring& dllPath, HANDLE& loaderThread)
    {
        void* remotePath = VirtualAllocEx(process, nullptr, (dllPath.size() + 1) * sizeof(wchar_t),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath || !WriteRemote(process, reinterpret_cast<uintptr_t>(remotePath), dllPath.c_str(),
                                         (dllPath.size() + 1) * sizeof(wchar_t))) {
            Out("[inject] remote path write failed err=%lu", GetLastError());
            return false;
        }

        HMODULE owner = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(&LoadLibraryW), &owner)) {
            Out("[inject] LoadLibraryW owner lookup failed err=%lu", GetLastError());
            return false;
        }
        // Kernel32.dll is mapped at the same base in every process. The early
        // injection path runs before Toolhelp has a usable module list, so the
        // PEB loader list is used for module discovery.
        const uintptr_t ownerBase = reinterpret_cast<uintptr_t>(owner);
        const uintptr_t offset = reinterpret_cast<uintptr_t>(&LoadLibraryW) - ownerBase;
        const uintptr_t remoteLoad = ownerBase + offset;

        loaderThread = CreateRemoteThread(process, nullptr, 0,
                                          reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteLoad), remotePath, 0,
                                          nullptr);
        if (!loaderThread) {
            Out("[inject] CreateRemoteThread failed err=%lu", GetLastError());
            return false;
        }
        Out("[inject] loader thread created");
        return true;
    }

    bool FinishLoaderThread(HANDLE process, HANDLE loaderThread, bool debuggerAttached)
    {
        const bool completed = WaitForLoaderThread(process, loaderThread, debuggerAttached,
                                                    g_monitorResult, g_mapViewTrap, g_allocTrap);
        DWORD exitCode = 0;
        GetExitCodeThread(loaderThread, &exitCode);
        CloseHandle(loaderThread);
        Out("[inject] loader wait=%s exit=%llX", completed ? "OK" : "TIMEOUT",
            static_cast<unsigned long long>(exitCode));
        const bool present = ModuleBase(process, kPatchDll) != 0;
        Out("[inject] 2026patch.dll present=%s", present ? "yes" : "no");
        return completed && present;
    }

    // A remote thread cannot run while the debugger holds the initial
    // breakpoint event. Hijack that stopped thread instead: call LoadLibraryW
    // with a controlled stack and trap the return with an int3 stub. Restore
    // the original context with every debug register clear; the monitor thread
    // applies the branch byte patch and arms one-byte int3 traps at the local
    // preparation call result, the indirect NtMapViewOfSection and
    // NtAllocateVirtualMemory calls, and the post-call sites inside the object
    // creator. The section-create call trap clears the supplied security
    // descriptor and then arms the inner import trap, which clears the named
    // section's OBJECT_ATTRIBUTES.ObjectName so the call creates a fresh
    // unnamed section instead of reopening a denied one. Those software
    // breakpoints are process-wide, so they catch whichever thread runs session
    // initialization.
    bool InjectAtBreakpoint(HANDLE process, DWORD pid, DWORD breakpointThread,
                            const std::wstring& dllPath, uintptr_t referee)
    {
        const uintptr_t sessionTrap = referee +
            SchoolsOut::Offsets::Referee::SessionLocalCallResult;
        const std::size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
        void* remotePath = VirtualAllocEx(process, nullptr, pathBytes,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        void* stub = VirtualAllocEx(process, nullptr, 1, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
        const unsigned char trap = 0xCC;
        if (!remotePath || !stub ||
            !WriteRemote(process, reinterpret_cast<uintptr_t>(remotePath), dllPath.c_str(), pathBytes) ||
            !WriteRemote(process, reinterpret_cast<uintptr_t>(stub), &trap, 1)) {
            Out("[inject] breakpoint injection memory setup failed err=%lu", GetLastError());
            return false;
        }

        HMODULE owner = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 reinterpret_cast<LPCWSTR>(&LoadLibraryW), &owner)) {
            Out("[inject] LoadLibraryW owner lookup failed err=%lu", GetLastError());
            return false;
        }
        const uintptr_t ownerBase = reinterpret_cast<uintptr_t>(owner);
        const uintptr_t remoteLoad = ownerBase +
            (reinterpret_cast<uintptr_t>(&LoadLibraryW) - ownerBase);
        const uintptr_t stubAddress = reinterpret_cast<uintptr_t>(stub);

        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                   THREAD_SUSPEND_RESUME, FALSE, breakpointThread);
        if (!thread) {
            Out("[inject] OpenThread for breakpoint failed err=%lu", GetLastError());
            return false;
        }
        CONTEXT original{};
        original.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &original)) {
            Out("[inject] GetThreadContext failed err=%lu", GetLastError());
            CloseHandle(thread);
            return false;
        }

        CONTEXT hijack = original;
        const uintptr_t stack = (static_cast<uintptr_t>(original.Rsp) - 0x200) &
                                ~static_cast<uintptr_t>(0xF);
        hijack.Rsp = stack + 8;
        hijack.Rip = remoteLoad;
        hijack.Rcx = static_cast<ULONG_PTR>(reinterpret_cast<uintptr_t>(remotePath));
        hijack.Rdx = 0;
        hijack.R8 = 0;
        hijack.R9 = 0;
        if (!WriteRemote(process, static_cast<uintptr_t>(hijack.Rsp), &stubAddress,
                         sizeof(stubAddress)) ||
            !SetThreadContext(thread, &hijack)) {
            Out("[inject] SetThreadContext for loader failed err=%lu", GetLastError());
            CloseHandle(thread);
            return false;
        }

        if (!ContinueDebugEvent(pid, breakpointThread, kDbgContinue)) {
            Out("[debug] breakpoint continue for loader failed err=%lu", GetLastError());
            CloseHandle(thread);
            return false;
        }
        Out("[inject] LoadLibraryW entered from initial breakpoint");

        bool restored = false;
        ULONGLONG holdUntil = 0;
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (GetTickCount64() < deadline) {
            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, 50)) { continue; }
            if (HandleResultTrap(process, event, sessionTrap)) { continue; }
            if (HandleMapViewTrap(process, event, g_mapViewTrap)) { continue; }
            if (HandleAllocTrap(process, event, g_allocTrap)) { continue; }
            if (HandleCreateSectionTrap(process, event)) { continue; }
            if (HandleSectionApiTrap(process, event)) { continue; }
            if (HandleStatusTraps(process, event)) { continue; }
            const bool loaderReturned =
                event.dwDebugEventCode == kExceptionDebugEvent &&
                event.u.Exception.ExceptionRecord.ExceptionCode == kStatusBreakpoint &&
                reinterpret_cast<uintptr_t>(event.u.Exception.ExceptionRecord.ExceptionAddress) ==
                    stubAddress;
            if (loaderReturned) {
                Out("[inject] loader returned at breakpoint stub");
                // No hardware debug register is armed. Hardware registers are
                // per-thread and the earlier attempt missed the session thread;
                // the monitor arms a process-wide int3 instead. Restore every
                // register clear so nothing can remain armed after detach.
                original.Dr0 = 0;
                original.Dr1 = 0;
                original.Dr2 = 0;
                original.Dr3 = 0;
                original.Dr6 = 0;
                original.Dr7 = 0;
                Out("[inject] original context restored with debug registers clear");
                if (!SetThreadContext(thread, &original)) {
                    Out("[inject] original context restore failed err=%lu", GetLastError());
                } else {
                    restored = true;
                    if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
                        holdUntil = GetTickCount64() + 1500;
                        Out("[inject] main thread held 1500ms for patch startup");
                    } else {
                        Out("[inject] SuspendThread failed err=%lu", GetLastError());
                    }
                }
                (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, kDbgContinue);
                break;
            }
            if (event.dwDebugEventCode == kExceptionDebugEvent) {
                const auto& info = event.u.Exception;
                Out("[debug] exception %08lX at %p first=%lu",
                    info.ExceptionRecord.ExceptionCode,
                    info.ExceptionRecord.ExceptionAddress,
                    static_cast<unsigned long>(info.dwFirstChance));
            }
            (void)ContinueEvent(event);
        }
        auto clearInitialDebugRegisters = [&]() {
            if (SuspendThread(thread) == static_cast<DWORD>(-1)) { return; }
            CONTEXT clear{};
            clear.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &clear)) {
                clear.Dr0 = 0;
                clear.Dr1 = 0;
                clear.Dr2 = 0;
                clear.Dr3 = 0;
                clear.Dr6 = 0;
                clear.Dr7 = 0;
                if (!SetThreadContext(thread, &clear)) {
                    Out("[debug] debug register clear failed err=%lu", GetLastError());
                }
            }
            (void)ResumeThread(thread);
        };

        bool patchConfirmed = false;
        if (restored) {
            while (holdUntil && GetTickCount64() < holdUntil) {
                DEBUG_EVENT event{};
                if (!WaitForDebugEvent(&event, 25)) { continue; }
                if (HandleResultTrap(process, event, sessionTrap)) { continue; }
                if (HandleMapViewTrap(process, event, g_mapViewTrap)) { continue; }
                if (HandleAllocTrap(process, event, g_allocTrap)) { continue; }
                if (HandleCreateSectionTrap(process, event)) { continue; }
                if (HandleSectionApiTrap(process, event)) { continue; }
                if (HandleStatusTraps(process, event)) { continue; }
                (void)ContinueEvent(event);
            }
            if (holdUntil && ResumeThread(thread) == static_cast<DWORD>(-1)) {
                Out("[inject] ResumeThread failed err=%lu", GetLastError());
            } else {
                Out("[inject] main thread resumed after patch startup hold");
            }

            // Require both confirmations: the monitor's byte patch and the
            // process-wide int3 observation. The map-view trap is diagnostic
            // only; neither a hardware register nor the append-helper address
            // is armed.
            bool monitorConfirmed = false;
            const ULONGLONG patchDeadline = GetTickCount64() + 30000;
            while (GetTickCount64() < patchDeadline) {
                if (InterlockedCompareExchange(&g_monitorComplete, 0, 0)) {
                    monitorConfirmed = true;
                }
                if (monitorConfirmed &&
                    InterlockedCompareExchange(&g_resultTrapObserved, 0, 0)) {
                    patchConfirmed = true;
                    break;
                }
                DEBUG_EVENT event{};
                if (!WaitForDebugEvent(&event, 50)) { continue; }
                if (HandleResultTrap(process, event, sessionTrap)) { continue; }
                if (HandleMapViewTrap(process, event, g_mapViewTrap)) { continue; }
                if (HandleAllocTrap(process, event, g_allocTrap)) { continue; }
                if (HandleCreateSectionTrap(process, event)) { continue; }
                if (HandleSectionApiTrap(process, event)) { continue; }
                if (HandleStatusTraps(process, event)) { continue; }
                if (event.dwDebugEventCode == kExceptionDebugEvent) {
                    const auto& info = event.u.Exception;
                    Out("[debug] exception %08lX at %p first=%lu",
                        info.ExceptionRecord.ExceptionCode,
                        info.ExceptionRecord.ExceptionAddress,
                        static_cast<unsigned long>(info.dwFirstChance));
                    (void)ContinueEvent(event);
                    continue;
                }
                if (event.dwDebugEventCode == kExitProcessDebugEvent) {
                    Out("[debug] target exited before deterministic patch confirmation");
                    (void)ContinueEvent(event);
                    break;
                }
                (void)ContinueEvent(event);
            }
        }
        RestoreResultTrap(process, sessionTrap);
        RestoreMapViewTrap(process, g_mapViewTrap);
        RestoreAllocTrap(process, g_allocTrap);
        RestoreCreateSectionTrap(process);
        RestoreSectionApiTrap(process);
        RestoreStatusTraps(process);
        clearInitialDebugRegisters();
        CloseHandle(thread);
        if (!restored) {
            Out("[inject] loader did not return to breakpoint stub");
            return false;
        }
        if (!patchConfirmed) {
            Out("[debug] deterministic session patch not confirmed; refusing to detach");
            return false;
        }
        const bool present = ModuleBase(process, kPatchDll) != 0;
        Out("[inject] 2026patch.dll present=%s", present ? "yes" : "no");
        Out("[debug] deterministic session patch confirmed; no hardware breakpoints armed");
        CapturePostPatchFaults(process, pid, referee, 90000);
        return present;
    }

    bool InjectDll(HANDLE process, const std::wstring& dllPath, bool waitForGameAssembly)
    {
        if (waitForGameAssembly) {
            const ULONGLONG deadline = GetTickCount64() + 30000;
            while (GetTickCount64() < deadline && WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
                if (ModuleBase(process, L"GameAssembly.dll")) { break; }
                Sleep(20);
            }
            const uintptr_t gameBase = ModuleBase(process, L"GameAssembly.dll");
            if (!gameBase) {
                Out("[inject] GameAssembly.dll not found before timeout");
                return false;
            }
            Out("[inject] GameAssembly.dll base=%016llX",
                static_cast<unsigned long long>(gameBase));
        } else {
            Out("[inject] injecting without GameAssembly wait");
        }

        HANDLE loaderThread = nullptr;
        if (!CreateLoaderThread(process, dllPath, loaderThread)) { return false; }
        return FinishLoaderThread(process, loaderThread, false);
    }

    int CheckConfig(const std::wstring& root)
    {
        try {
            Settings settings;
            SchoolsOut::Config::Load(SchoolsOut::Config::Utf8(root) + "\\2026patch.ini", settings);
            std::printf("[config] ApiHost=%s EnableSslPinning=%s VoiceKeyXml=%s AllowUnsignedImages=%s SuppressDuidMismatch=%s\n",
                        settings.routing.api.host.empty() ? "blank" : "set",
                        settings.sslPinningPatch ? "true" : "false",
                        settings.voiceKeyXml.empty() ? "blank" : "public-key",
                        settings.allowUnsignedImages ? "true" : "false",
                        settings.suppressDuidMismatch ? "true" : "false");
            return 0;
        } catch (const std::exception& error) {
            std::printf("[config] FAIL: %s\n", error.what());
            return 1;
        }
    }

    int Interactive(const std::wstring& root, bool launchGame, const std::wstring& gameArgs)
    {
        if (!SupportsInstallation(root)) {
            Out("[preflight] module fingerprint mismatch");
            Pause();
            return 1;
        }
        if (CheckConfig(root) != 0) {
            Out("[preflight] configuration invalid");
            Pause();
            return 1;
        }

        InterlockedExchange(&g_monitorStop, 0);
        InterlockedExchange(&g_monitorComplete, 0);
        InterlockedExchange(&g_resultTrapArmed, 0);
        InterlockedExchange(&g_resultTrapObserved, 0);
        InterlockedExchange(&g_mapViewTrapArmed, 0);
        InterlockedExchange(&g_allocTrapArmed, 0);
        g_monitorBranch = 0;
        g_monitorResult = 0;
        g_mapViewTrap = 0;
        g_allocTrap = 0;
        g_resultTrapOriginal = 0;
        g_mapViewTrapOriginal = 0;
        g_allocTrapOriginal = 0;
        g_createSectionTrap = 0;
        g_createSectionOriginal = 0;
        InterlockedExchange(&g_createSectionArmed, 0);
        g_sectionApiTrap = 0;
        g_sectionApiOriginal = 0;
        InterlockedExchange(&g_sectionApiArmed, 0);
        InterlockedExchange(&g_sectionApiObserved, 0);
        for (StatusTrap& trap : g_statusTraps) {
            trap.address = 0;
            trap.label = nullptr;
            trap.original = 0;
            InterlockedExchange(&trap.armed, 0);
        }

        HANDLE mutex = CreateMutexW(nullptr, FALSE, kMutexName);
        if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
            Out("[inject] another injector is already active");
            Pause();
            return 1;
        }
        HANDLE ready = CreateEventW(nullptr, TRUE, TRUE, ReadyEventName(root).c_str());
        if (!ready) {
            Out("[inject] ready event creation failed err=%lu", GetLastError());
            Pause();
            return 1;
        }
        // Keep the named event alive for the batch launcher's --wait-ready call.
        (void)ready;
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        Out("[inject] mode=%s", launchGame ? "auto-launch" : "attach");
        Out("[inject] watching %ls", root.c_str());
        Out("[inject] ready event signaled");

        DWORD pid = 0;
        HANDLE process = nullptr;
        HANDLE mainThread = nullptr;
        bool debuggerAttached = false;
        bool injected = false;
        const std::wstring dllPath = root + L"\\" + kPatchDll;
        if (launchGame) {
            if (FindGame(root)) {
                Out("[inject] RecRoom.exe is already running; close it before using auto-launch");
                Pause();
                return 1;
            }
            if (!LaunchGame(root, gameArgs, pid, process, mainThread)) {
                Pause();
                return 1;
            }
            debuggerAttached = true;
            DWORD breakpointThread = 0;
            if (!WaitForInitialBreakpoint(pid, breakpointThread)) {
                Out("[result] initial debugger breakpoint failed");
            } else {
                const uintptr_t referee = BootstrapReferee(process);
                if (referee) {
                    g_monitorProcess = process;
                    g_monitorBranch = referee +
                        SchoolsOut::Offsets::Referee::SessionFallbackBranch;
                    g_monitorResult = referee +
                        SchoolsOut::Offsets::Referee::SessionLocalCallResult;
                    g_mapViewTrap = referee + MapViewCall;
                    g_allocTrap = referee + AllocateVirtualMemoryCall;
                    g_createSectionTrap = referee +
                        SchoolsOut::Offsets::Referee::CreatorCreateSectionCall;
                    g_sectionApiTrap = referee +
                        SchoolsOut::Offsets::Referee::CreatorSectionApiCall;
                    g_resultTrapOriginal = 0;
                    g_mapViewTrapOriginal = 0;
                    g_allocTrapOriginal = 0;
                    g_createSectionOriginal = 0;
                    g_sectionApiOriginal = 0;
                    InterlockedExchange(&g_resultTrapArmed, 0);
                    InterlockedExchange(&g_resultTrapObserved, 0);
                    InterlockedExchange(&g_mapViewTrapArmed, 0);
                    InterlockedExchange(&g_allocTrapArmed, 0);
                    InterlockedExchange(&g_createSectionArmed, 0);
                    InterlockedExchange(&g_sectionApiArmed, 0);
                    InterlockedExchange(&g_sectionApiObserved, 0);

                    const uintptr_t creator = referee;
                    g_statusTraps[0].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorCreateSidResult;
                    g_statusTraps[0].label = "create well-known sid";
                    g_statusTraps[1].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorSetAclResult;
                    g_statusTraps[1].label = "set ACL";
                    g_statusTraps[2].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorAllocateResult;
                    g_statusTraps[2].label = "allocate";
                    g_statusTraps[3].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorInitSdResult;
                    g_statusTraps[3].label = "initialize SD";
                    g_statusTraps[4].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorSetDaclResult;
                    g_statusTraps[4].label = "set DACL";
                    g_statusTraps[5].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorMapViewResult;
                    g_statusTraps[5].label = "map view";
                    g_statusTraps[6].address = creator +
                        SchoolsOut::Offsets::Referee::CreatorCreateSectionResult;
                    g_statusTraps[6].label = "create section";
                    for (StatusTrap& trap : g_statusTraps) {
                        trap.original = 0;
                        InterlockedExchange(&trap.armed, 0);
                    }

                    g_monitorThread = CreateThread(nullptr, 0, MonitorSessionBranch,
                                                   nullptr, 0, nullptr);
                    if (g_monitorThread) {
                        Out("[inject] session branch monitor started");
                    }
                }
                injected = InjectAtBreakpoint(process, pid, breakpointThread, dllPath, referee);
            }
            if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
                DetachDebugger(pid, debuggerAttached);
            } else if (debuggerAttached) {
                debuggerAttached = false;
                Out("[debug] detach skipped; target already exited");
            }
        } else {
            while (!(pid = FindGame(root))) { Sleep(50); }
            Out("[inject] found pid %lu", pid);
            process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                  PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
            if (!process) {
                Out("[inject] OpenProcess failed err=%lu", GetLastError());
                Pause();
                return 1;
            }
            injected = InjectDll(process, dllPath, true);
        }

        Out("[result] injector=%s", injected ? "OK" : "FAIL");
        if (!injected) {
            Out("[result] startup incomplete; injector stopping");
            if (launchGame && process) { TerminateProcess(process, 0); }
            StopMonitor();
            if (mainThread) { CloseHandle(mainThread); }
            if (process) { CloseHandle(process); }
            Pause();
            return 1;
        }
        if (mainThread) { CloseHandle(mainThread); }
        if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) {
            DWORD exitCode = STILL_ACTIVE;
            GetExitCodeProcess(process, &exitCode);
            Out("[result] game process exited (pid %lu) exit=%lu", pid, exitCode);
            StopMonitor();
            CloseHandle(process);
            Pause();
            return 0;
        }
        Out("[inject] waiting for game process to exit");
        WaitForSingleObject(process, INFINITE);
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(process, &exitCode);
        Out("[result] game process exited (pid %lu) exit=%lu", pid, exitCode);
        StopMonitor();
        CloseHandle(process);
        Pause();
        return 0;
    }
}

int wmain(int argc, wchar_t** argv)
{
    const std::wstring root = argc > 2 ? std::wstring(argv[2]) : ModuleDirectory();
    const std::wstring mode = argc > 1 ? std::wstring(argv[1]) : L"";
    if (mode == L"--wait-ready") {
        HANDLE ready = OpenEventW(SYNCHRONIZE, FALSE, ReadyEventName(root).c_str());
        if (!ready) { return 1; }
        const DWORD result = WaitForSingleObject(ready, 30000);
        CloseHandle(ready);
        return result == WAIT_OBJECT_0 ? 0 : 1;
    }
    if (mode == L"--check-install") {
        return SupportsInstallation(root) ? 0 : 1;
    }
    if (mode == L"--check-config") {
        return CheckConfig(root);
    }

    wchar_t logPath[MAX_PATH] = {};
    _snwprintf_s(logPath, _countof(logPath), _TRUNCATE, L"%s\\Injector.log", root.c_str());
    FILE* log = nullptr;
    if (!_wfopen_s(&log, logPath, L"a")) {
        fputs("\n==== SchoolsOutPatch injector session ====\n", log);
        fclose(log);
    }
    g_logPath = logPath;
    g_logging = true;

    if (mode == L"--launch") {
        return Interactive(root, true, EnvironmentVariable(kGameArgsVariable));
    }
    return Interactive(root, false, L"");
}
