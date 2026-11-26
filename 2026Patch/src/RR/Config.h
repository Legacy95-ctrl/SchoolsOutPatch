#pragma once

#include <Windows.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "NetworkConfig.h"

namespace SchoolsOut
{
    namespace Config
    {
        struct Settings
        {
            NetworkConfig::Routing routing;
            std::string voiceKeyXml;
            bool sslPinningPatch = true;
            bool allowUnsignedImages = true;
            bool suppressDuidMismatch = true;
            bool verbose = false;
        };

        inline std::string Narrow(const std::wstring& value)
        {
            if (value.empty()) { return {}; }
            const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                                 static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
            if (size <= 0) { throw std::runtime_error("INI value is not valid UTF-16."); }
            std::string result(static_cast<std::size_t>(size), '\0');
            if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                    static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) != size) {
                throw std::runtime_error("INI value could not be converted.");
            }
            return result;
        }

        inline std::string Utf8(const std::wstring& value)
        {
            return Narrow(value);
        }

        inline std::string ReadValue(const std::string& path, const char* key)
        {
            std::wstring wideKey;
            for (const char c : std::string(key)) { wideKey.push_back(static_cast<wchar_t>(c)); }
            std::vector<wchar_t> buffer(4098, L'\0');
            const DWORD length = GetPrivateProfileStringW(L"config", wideKey.c_str(), L"", buffer.data(),
                                                           static_cast<DWORD>(buffer.size()),
                                                           std::wstring(path.begin(), path.end()).c_str());
            if (length >= buffer.size() - 1) { throw std::runtime_error("INI value is too long."); }
            return NetworkConfig::Trim(Narrow(std::wstring(buffer.data(), length)));
        }

        inline bool ReadFlag(const std::string& path, const char* key, bool fallback, bool& present)
        {
            const std::string value = NetworkConfig::Lower(ReadValue(path, key));
            present = !value.empty();
            if (!present) { return fallback; }
            if (value == "true" || value == "1" || value == "yes" || value == "on") { return true; }
            if (value == "false" || value == "0" || value == "no" || value == "off") { return false; }
            throw std::runtime_error(std::string("Invalid boolean for ") + key + ".");
        }

        inline void RejectLegacySections(const std::string& path)
        {
            std::vector<wchar_t> names(4096, L'\0');
            const DWORD length = GetPrivateProfileSectionNamesW(names.data(), static_cast<DWORD>(names.size()),
                                                                std::wstring(path.begin(), path.end()).c_str());
            if (length == 0 || length >= names.size() - 2) { return; }
            for (const wchar_t* name = names.data(); *name; name += std::wcslen(name) + 1) {
                const std::string section = Narrow(name);
                if (section == "Network" || section == "ScreenShare" || section == "Logging") {
                    throw std::runtime_error("Legacy INI section detected; use [config] only.");
                }
            }
        }

        inline void ApplyPublicKeyOverride(Settings& settings)
        {
            char* value = nullptr;
            std::size_t valueSize = 0;
            if (_dupenv_s(&value, &valueSize, "PATCH26_TACHYON_PUBLIC_KEY") != 0 || !value || !*value) {
                free(value);
                return;
            }
            std::string path(value, valueSize ? valueSize - 1 : 0);
            free(value);
            if (path.size() > 32767) { throw std::runtime_error("Public key path is too long."); }
            HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) { throw std::runtime_error("Public key file could not be read."); }
            std::vector<char> bytes(4097, '\0');
            DWORD read = 0;
            const bool ok = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size() - 1), &read, nullptr) != FALSE;
            CloseHandle(file);
            if (!ok || read == 0 || read >= bytes.size() - 1) {
                throw std::runtime_error("Public key file is unreadable or too large.");
            }
            settings.voiceKeyXml = NetworkConfig::Trim(std::string(bytes.data(), read));
        }

        inline void Load(const std::string& path, Settings& settings)
        {
            if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                throw std::runtime_error("2026patch.ini is missing beside 2026patch.dll.");
            }
            RejectLegacySections(path);

            const std::string apiHost = ReadValue(path, "ApiHost");
            const std::string domain = ReadValue(path, "ServerDomain");
            settings.routing.api = NetworkConfig::ParseApiHost(apiHost);
            settings.routing.serverDomain = NetworkConfig::ParseDomain(domain);
            if (!settings.routing.serverDomain.empty() &&
                !NetworkConfig::InDomain(settings.routing.api.host, settings.routing.serverDomain)) {
                throw std::runtime_error("ApiHost must be inside ServerDomain.");
            }

            bool canonicalPresent = false;
            bool aliasPresent = false;
            const bool canonical = ReadFlag(path, "EnableSslPinning", true, canonicalPresent);
            const bool alias = ReadFlag(path, "DisableCertificatePinning", false, aliasPresent);
            if (canonicalPresent && aliasPresent && canonical == alias) {
                throw std::runtime_error("EnableSslPinning and DisableCertificatePinning disagree.");
            }
            settings.sslPinningPatch = canonicalPresent ? canonical : (aliasPresent ? !alias : true);
            settings.allowUnsignedImages = ReadFlag(path, "AllowUnsignedImages", true, canonicalPresent);
            settings.suppressDuidMismatch = ReadFlag(path, "SuppressDuidMismatch", true, canonicalPresent);
            settings.verbose = ReadFlag(path, "EnableTracing", false, canonicalPresent);

            settings.voiceKeyXml = ReadValue(path, "VoiceKeyXml");
            ApplyPublicKeyOverride(settings);
            if (!NetworkConfig::ValidPublicKey(settings.voiceKeyXml)) {
                throw std::runtime_error("VoiceKeyXml must contain only public RSA Modulus and Exponent.");
            }
        }
    }
}
