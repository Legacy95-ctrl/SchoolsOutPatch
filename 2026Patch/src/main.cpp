#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <exception>
#include <string>

#include "RR/BuildGuard.h"
#include "RR/Offsets.h"
#include "RR/Patches.h"
#include "Utils/Logging.h"

namespace
{
    volatile LONG g_sessionBranchPatched = 0;
    volatile LONG g_failFastCleared = 0;

    bool PatchBytes(uintptr_t address, const unsigned char* expected,
                    const unsigned char* replacement, std::size_t size)
    {
        unsigned char actual[16] = {};
        SIZE_T read = 0;
        if (size > sizeof(actual) ||
            !ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), actual, size,
                               &read) ||
            read != size || std::memcmp(actual, expected, size) != 0) {
            return false;
        }
        DWORD previous = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &previous)) {
            return false;
        }
        std::memcpy(reinterpret_cast<void*>(address), replacement, size);
        DWORD restored = 0;
        VirtualProtect(reinterpret_cast<void*>(address), size, previous, &restored);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size);
        return true;
    }

    DWORD WINAPI EarlyRefereePatches(LPVOID)
    {
        HMODULE referee = nullptr;
        for (int attempt = 0; attempt < 500 && !referee; ++attempt) {
            referee = GetModuleHandleW(L"Referee.dll");
            if (!referee) { Sleep(10); }
        }
        if (!referee) { return 1; }

        const uintptr_t base = reinterpret_cast<uintptr_t>(referee);
        const uintptr_t flag = base + SchoolsOut::Offsets::Referee::FailFastFlag;
        const unsigned char expectedFlag = 0x02;
        const unsigned char clearedFlag = 0x00;
        if (PatchBytes(flag, &expectedFlag, &clearedFlag, 1)) {
            InterlockedExchange(&g_failFastCleared, 1);
        }

        // Only the fallback branch is changed. The success-path store at
        // Referee+0x69A7CD stays intact so the fully initialized local object
        // is published through the owner pointer.
        const uintptr_t branch = base + SchoolsOut::Offsets::Referee::SessionFallbackBranch;
        const unsigned char expectedBranch[SchoolsOut::Offsets::Referee::SessionFallbackBranchSize] = {
            0x0F, 0x84, 0x07, 0x03, 0x00, 0x00};
        const unsigned char nops[SchoolsOut::Offsets::Referee::SessionFallbackBranchSize] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        for (int attempt = 0; attempt < 4000; ++attempt) {
            if (PatchBytes(branch, expectedBranch, nops,
                           SchoolsOut::Offsets::Referee::SessionFallbackBranchSize)) {
                InterlockedExchange(&g_sessionBranchPatched, 1);
                return 0;
            }
            Sleep(5);
        }
        return 2;
    }

    DWORD WINAPI InitializePatch(LPVOID parameter)
    {
        const HMODULE module = static_cast<HMODULE>(parameter);
        try {
            wchar_t file[MAX_PATH] = {};
            const DWORD length = GetModuleFileNameW(module, file, MAX_PATH);
            if (!length || length >= MAX_PATH) {
                return 7;
            }
            const std::wstring full(file, length);
            const std::size_t separator = full.find_last_of(L"\\/");
            if (separator == std::wstring::npos || separator == 0) {
                return 7;
            }
            const std::wstring directory = full.substr(0, separator);

            if (SchoolsOut::Log::path.empty()) { SchoolsOut::Log::Begin(directory); }
            SchoolsOut::Log::Line("startup build=2026-03-31T03-05-36Z_473be467");

            SchoolsOut::Config::Settings settings;
            SchoolsOut::Config::Load(SchoolsOut::Config::Utf8(directory) + "\\2026patch.ini", settings);
            SchoolsOut::Log::verbose = settings.verbose;
            SchoolsOut::Log::Line("config loaded: redirect=%s sslPatch=%s images=%s duid=%s key=%s",
                                  settings.routing.api.host.empty() ? "off" : "on",
                                  settings.sslPinningPatch ? "on" : "off",
                                  settings.allowUnsignedImages ? "on" : "off",
                                  settings.suppressDuidMismatch ? "on" : "off",
                                  settings.voiceKeyXml.empty() ? "off" : "on");

            for (int attempt = 0; attempt < 600 && !GetModuleHandleW(L"GameAssembly.dll"); ++attempt) {
                Sleep(50);
            }
            if (!GetModuleHandleW(L"GameAssembly.dll") || !SchoolsOut::BuildGuard::SupportsLoadedClient()) {
                SchoolsOut::Log::Line("fingerprint mismatch; no hooks installed");
                return 1;
            }
            const HMODULE referee = GetModuleHandleW(L"Referee.dll");
            if (referee) {
                const uintptr_t flag = reinterpret_cast<uintptr_t>(referee) +
                                       SchoolsOut::Offsets::Referee::FailFastFlag;
                SchoolsOut::Log::Line("referee flag=0x%02X",
                                      *reinterpret_cast<const volatile unsigned char*>(flag));
            }
            SchoolsOut::Log::Line("native patches: failFast=%d sessionBranch=%d",
                                  InterlockedCompareExchange(&g_failFastCleared, 0, 0),
                                  InterlockedCompareExchange(&g_sessionBranchPatched, 0, 0));
            const int status = SchoolsOut::Patches::Initialize(settings);
            SchoolsOut::Log::Line("initialization complete status=%d", status);
            return static_cast<DWORD>(status);
        } catch (const std::exception& error) {
            SchoolsOut::Log::Line("startup failed: %s", error.what());
            return 7;
        } catch (...) {
            SchoolsOut::Log::Line("startup failed: unknown exception");
            return 7;
        }
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t file[MAX_PATH] = {};
        const DWORD length = GetModuleFileNameW(module, file, MAX_PATH);
        if (length && length < MAX_PATH) {
            const std::wstring full(file, length);
            const std::size_t separator = full.find_last_of(L"\\/");
            if (separator != std::wstring::npos && separator > 0) {
                SchoolsOut::Log::Begin(full.substr(0, separator));
                SchoolsOut::Log::Line("dll attach");
            }
        }
        DisableThreadLibraryCalls(module);
        HANDLE early = CreateThread(nullptr, 0, EarlyRefereePatches, nullptr, 0, nullptr);
        SchoolsOut::Log::Line("early thread created=%d", early ? 1 : 0);
        if (early) { CloseHandle(early); }
        HANDLE thread = CreateThread(nullptr, 0, InitializePatch, module, 0, nullptr);
        SchoolsOut::Log::Line("init thread created=%d", thread ? 1 : 0);
        if (thread) { CloseHandle(thread); }
    }
    return TRUE;
}
