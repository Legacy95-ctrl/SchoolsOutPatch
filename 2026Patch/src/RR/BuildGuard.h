#pragma once

#include <Windows.h>
#include <bcrypt.h>

#include <cstring>
#include <string>

#pragma comment(lib, "bcrypt.lib")

namespace SchoolsOut
{
    namespace BuildGuard
    {
        struct Fingerprint
        {
            const wchar_t* name;
            const char* hash;
        };

        // On-disk hashes of 2026-03-31T03-05-36Z_473be467. All native RVAs in
        // Methods.h and the injector are valid only for this exact image set.
        inline constexpr Fingerprint Modules[] = {
            {L"GameAssembly.dll",
             "8EFDE88E39A0E6F2B810D089496E262354D3DF8CD0FC2C783D4309B936B55B49"},
            {L"Referee.dll",
             "8F37DFC94E416E3498C531EF9EBA2A01E1FD279299D198B73C7761B24A509287"},
            {L"UnityPlayer.dll",
             "782012743B7127DF15F2E461219A5CCFFF6BA495BFD197DB10EB9637EE86A599"}};

        inline bool MatchesPath(const wchar_t* path, const char* expected)
        {
            HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (file == INVALID_HANDLE_VALUE) { return false; }
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0;
            if (ok) { ok = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0; }
            unsigned char buffer[65536];
            DWORD count = 0;
            while (ok) {
                if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) { ok = false; break; }
                if (!count) { break; }
                ok = BCryptHashData(hash, buffer, count, 0) >= 0;
            }
            unsigned char digest[32] = {};
            if (ok) { ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0; }
            if (hash) { BCryptDestroyHash(hash); }
            if (algorithm) { BCryptCloseAlgorithmProvider(algorithm, 0); }
            CloseHandle(file);
            char actual[65] = {};
            constexpr char hex[] = "0123456789ABCDEF";
            for (std::size_t i = 0; i < sizeof(digest); ++i) {
                actual[2 * i] = hex[digest[i] >> 4];
                actual[2 * i + 1] = hex[digest[i] & 15];
            }
            return ok && std::strcmp(actual, expected) == 0;
        }

        inline bool MatchesLoaded(const wchar_t* name, const char* expected)
        {
            wchar_t path[MAX_PATH] = {};
            HMODULE module = GetModuleHandleW(name);
            DWORD length = module ? GetModuleFileNameW(module, path, MAX_PATH) : 0;
            return length && length < MAX_PATH && MatchesPath(path, expected);
        }

        inline bool SupportsLoadedClient()
        {
            for (const auto& module : Modules) {
                if (!MatchesLoaded(module.name, module.hash)) { return false; }
            }
            return true;
        }

        inline bool SupportsInstallation(const std::wstring& root)
        {
            for (const auto& module : Modules) {
                if (!MatchesPath((root + L"\\" + module.name).c_str(), module.hash)) { return false; }
            }
            return true;
        }
    }
}
