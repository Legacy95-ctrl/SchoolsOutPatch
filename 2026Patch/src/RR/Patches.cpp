#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <cwchar>
#include <intrin.h>
#include <string>

#include "Config.h"
#include "Methods.h"
#include "Offsets.h"
#include "Patches.h"
#include "../Utils/Logging.h"
#include "../Utils/deps/minhook/include/MinHook.h"

namespace SchoolsOut
{
    namespace Patches
    {
        namespace
        {
            uintptr_t game = 0;
            Config::Settings config;
            std::string nameServerOrigin;

            void* (*stringNew)(const char*) = nullptr;
            void* (*uriString)(void*, void*) = nullptr;
            void (*uriCtor)(void*, void*, void*) = nullptr;

            void* (*nameServerOriginal)() = nullptr;
            void* (*sendOriginal)(void*, void*) = nullptr;
            void* (*buildUriOriginal)(void*, void*, void*) = nullptr;
            void (*certificateOriginal)(void*, void*, void*) = nullptr;
            bool (*duidOriginal)(void*, void**, void**, void*) = nullptr;
            void (*tachyonCtorOriginal)(void*, void*, void*, void*) = nullptr;
            void (*rsaImportXml)(void*, void*) = nullptr;
            void (*applicationQuitWithExitCodeOriginal)(int) = nullptr;
            void (*applicationQuitOriginal)() = nullptr;
            void (*applicationInternalQuitOriginal)() = nullptr;
            void (*cheatManagerFatalQuitOriginal)(void*) = nullptr;
            void (*exitStateOriginal)(int) = nullptr;
            void (*sessionFatalQuitOriginal)(int, void*) = nullptr;
            void (*sessionTryQuitWithCodeOriginal)(int) = nullptr;
            void (*sessionTryQuitOriginal)() = nullptr;
            void (*sessionModelQuitOriginal)(void*) = nullptr;
            void* (*sessionManagerAccessJoinOriginal)(void*, void*, bool, int) = nullptr;

            void* Gate(void* source)
            {
                if (!source) { return nullptr; }
                auto* gate = reinterpret_cast<unsigned char*>(
                    VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
                if (!gate) { return nullptr; }
                unsigned char code[22] = {0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8, 0,    0,    0,    0, 0,
                                          0,    0,    0,    0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3};
                std::memcpy(code + 6, &source, sizeof(source));
                std::memcpy(gate, code, sizeof(code));
                FlushInstructionCache(GetCurrentProcess(), gate, sizeof(code));
                DWORD previous = 0;
                VirtualProtect(gate, 32, PAGE_EXECUTE_READ, &previous);
                return gate;
            }

            void* GaExport(const char* name)
            {
                if (HMODULE module = GetModuleHandleW(L"GameAssembly.dll")) {
                    if (void* proc = reinterpret_cast<void*>(GetProcAddress(module, name))) { return proc; }
                }
                if (HMODULE module = GetModuleHandleW(L"UnityPlayer.dll")) {
                    return reinterpret_cast<void*>(GetProcAddress(module, name));
                }
                return nullptr;
            }

            // Quit diagnostics and suppression are enabled by default. An
            // explicit environment value of 0/false disables the corresponding
            // switch. The batch launchers also set all three to 1.
            bool EnvFlag(const wchar_t* name, bool fallback)
            {
                wchar_t value[8] = {};
                const DWORD length = GetEnvironmentVariableW(name, value, _countof(value));
                if (!length) { return fallback; }
                if (value[0] == L'0' || value[0] == L'f' || value[0] == L'F') { return false; }
                return value[0] == L'1' || value[0] == L't' || value[0] == L'T' || fallback;
            }

            bool QuitTraceEnabled()
            {
                static const bool enabled = EnvFlag(L"SCHOOLSOUT_TRACE_QUIT", true);
                return enabled;
            }

            // Suppress the anti-cheat fatal-quit callback that loads
            // 0x1FC85836. Set SCHOOLSOUT_SUPPRESS_CHEAT_QUIT=0 to opt out.
            bool SuppressCheatQuitEnabled()
            {
                static const bool enabled = EnvFlag(L"SCHOOLSOUT_SUPPRESS_CHEAT_QUIT", true);
                return enabled;
            }

            // Suppress focus/exit-state driven quits. State 0 (Running) is
            // always allowed through; only transitions to PreparingToExit or
            // ReadyForExit are suppressed. Set SCHOOLSOUT_SUPPRESS_EXIT_STATE=0
            // to opt out.
            bool SuppressExitStateEnabled()
            {
                static const bool enabled = EnvFlag(L"SCHOOLSOUT_SUPPRESS_EXIT_STATE", true);
                return enabled;
            }

            const void* ReturnAddress()
            {
                void* address = nullptr;
                __try { address = *reinterpret_cast<void**>(_AddressOfReturnAddress()); }
                __except (EXCEPTION_EXECUTE_HANDLER) { address = nullptr; }
                return address;
            }

            void LogQuitFrame(const char* label, const void* address)
            {
                if (!address) {
                    Log::Line("[QuitTrace] %s=null", label);
                    return;
                }
                HMODULE module = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        reinterpret_cast<LPCWSTR>(address), &module)) {
                    Log::Line("[QuitTrace] %s=%p module=?", label, address);
                    return;
                }
                wchar_t wide[MAX_PATH] = {};
                const DWORD length = GetModuleFileNameW(module, wide, _countof(wide));
                char name[MAX_PATH] = {};
                if (length && length < _countof(wide)) {
                    const wchar_t* slash = std::wcsrchr(wide, L'\\');
                    const wchar_t* base = slash ? slash + 1 : wide;
                    WideCharToMultiByte(CP_UTF8, 0, base, -1, name, sizeof(name), nullptr, nullptr);
                } else {
                    WideCharToMultiByte(CP_UTF8, 0, L"?", -1, name, sizeof(name), nullptr, nullptr);
                }
                const uintptr_t rva = reinterpret_cast<uintptr_t>(address) -
                                      reinterpret_cast<uintptr_t>(module);
                Log::Line("[QuitTrace] %s=%p module=%s rva=0x%llX", label, address, name,
                          static_cast<unsigned long long>(rva));
            }

            void LogManagedQuit(const char* overload, const void* immediateCaller)
            {
                static volatile LONG logged = 0;
                if (InterlockedIncrement(&logged) > 24) { return; }
                Log::Line("[QuitTrace] %s invoked", overload);
                LogQuitFrame("caller", immediateCaller);
                void* frames[10] = {};
                const USHORT count = RtlCaptureStackBackTrace(
                    1, static_cast<ULONG>(_countof(frames)), frames, nullptr);
                for (USHORT index = 0; index < count; ++index) {
                    char label[24] = {};
                    _snprintf_s(label, _countof(label), _TRUNCATE, "frame%u",
                                static_cast<unsigned int>(index));
                    LogQuitFrame(label, frames[index]);
                }
            }

            void ApplicationQuitWithExitCodeTrace(int exitCode)
            {
                Log::Line("[QuitTrace] Application.Quit(int) exitCode=%d (0x%X)", exitCode,
                          static_cast<unsigned int>(exitCode));
                LogManagedQuit("Application.Quit(int)", ReturnAddress());
                if (applicationQuitWithExitCodeOriginal) { applicationQuitWithExitCodeOriginal(exitCode); }
            }

            void ApplicationQuitTrace()
            {
                LogManagedQuit("Application.Quit()", ReturnAddress());
                if (applicationQuitOriginal) { applicationQuitOriginal(); }
            }

            void ApplicationInternalQuitTrace()
            {
                LogManagedQuit("Application.Internal_ApplicationQuit()", ReturnAddress());
                if (applicationInternalQuitOriginal) { applicationInternalQuitOriginal(); }
            }

            void CheatManagerFatalQuitTrace(void* instance)
            {
                LogManagedQuit("CheatManager.HRZIGTNFSHP.DCDTOGTESYJ", ReturnAddress());
                if (SuppressCheatQuitEnabled()) {
                    Log::Line("[QuitFix] suppressed anti-cheat fatal quit status=0x1FC85836");
                    return;
                }
                if (cheatManagerFatalQuitOriginal) { cheatManagerFatalQuitOriginal(instance); }
            }

            void ExitStateTrace(int state)
            {
                const char* name = state == 0 ? "Running"
                                      : state == 1 ? "PreparingToExit"
                                      : state == 2 ? "ReadyForExit" : "Unknown";
                Log::Line("[QuitTrace] ExitState state=%d (%s)", state, name);
                LogManagedQuit("OTBCUXXIPTI.SetExitState", ReturnAddress());
                if (SuppressExitStateEnabled() && state != 0) {
                    Log::Line("[QuitFix] suppressed exit-state quit state=%d", state);
                    return;
                }
                if (exitStateOriginal) { exitStateOriginal(state); }
            }

            void SessionFatalQuitTrace(int statusCode, void* message)
            {
                Log::Line("[QuitTrace] SessionManager.FatalApplicationQuit status=%d (0x%X)",
                          statusCode, static_cast<unsigned int>(statusCode));
                LogManagedQuit("SessionManager.FatalApplicationQuit", ReturnAddress());
                if (sessionFatalQuitOriginal) { sessionFatalQuitOriginal(statusCode, message); }
            }

            void SessionTryQuitWithCodeTrace(int statusCode)
            {
                Log::Line("[QuitTrace] SessionManager.TryApplicationQuit(int) status=%d (0x%X)",
                          statusCode, static_cast<unsigned int>(statusCode));
                LogManagedQuit("SessionManager.TryApplicationQuit(int)", ReturnAddress());
                if (sessionTryQuitWithCodeOriginal) { sessionTryQuitWithCodeOriginal(statusCode); }
            }

            void SessionTryQuitTrace()
            {
                LogManagedQuit("SessionManager.TryApplicationQuit()", ReturnAddress());
                if (sessionTryQuitOriginal) { sessionTryQuitOriginal(); }
            }

            void SessionModelQuitTrace(void* instance)
            {
                LogManagedQuit("RRUI.Data.SessionModel.ApplicationQuit", ReturnAddress());
                if (sessionModelQuitOriginal) { sessionModelQuitOriginal(instance); }
            }

            void* SessionManagerAccessJoinTrace(void* instance, void* rooms, bool forceNewInstance,
                                                int inviteMode)
            {
                LogManagedQuit("SessionManagerAccess.LHHRAFRXYAO", ReturnAddress());
                Log::Verbose("[QuitTrace] join rooms=%d forceNew=%d inviteMode=%d",
                             rooms ? 1 : 0, forceNewInstance ? 1 : 0, inviteMode);
                return sessionManagerAccessJoinOriginal
                           ? sessionManagerAccessJoinOriginal(instance, rooms, forceNewInstance, inviteMode)
                           : nullptr;
            }

            bool TryReadUriText(void* uri, char* output, std::size_t capacity)
            {
                bool ok = false;
                __try {
                    if (uri && uriString && capacity > 1) {
                        void* managed = uriString(uri, nullptr);
                        if (managed) {
                            const auto address = reinterpret_cast<uintptr_t>(managed);
                            const int length = *reinterpret_cast<int*>(address + Offsets::String::Length);
                            if (length >= 0 && length < 8191) {
                                const auto* chars = reinterpret_cast<const wchar_t*>(
                                    address + Offsets::String::Characters);
                                const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, chars,
                                                                      length, output, static_cast<int>(capacity - 1),
                                                                      nullptr, nullptr);
                                if (bytes > 0) {
                                    output[bytes] = '\0';
                                    ok = true;
                                }
                            }
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    ok = false;
                }
                return ok;
            }

            void* SafeRequestUri(void* request)
            {
                void* uri = nullptr;
                __try {
                    if (request) {
                        uri = *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(request) +
                                                        Offsets::HTTPRequest::Uri);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    uri = nullptr;
                }
                return uri;
            }

            bool TryRequestUri(void* request, char* output, std::size_t capacity)
            {
                return TryReadUriText(SafeRequestUri(request), output, capacity);
            }

            bool TryTlsUri(void* instance, char* output, std::size_t capacity)
            {
                bool ok = false;
                __try {
                    if (instance) {
                        void* uri = *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(instance) +
                                                              Offsets::TlsAuthentication::TargetUri);
                        ok = TryReadUriText(uri, output, capacity);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    ok = false;
                }
                return ok;
            }

            // Log only scheme, host, and rewrite state. Never log a full URL,
            // path, query, or userinfo.
            std::string SafeAuthorityHost(const std::string& authority)
            {
                const std::size_t at = authority.rfind('@');
                return NetworkConfig::HostOf(at == std::string::npos ? authority
                                                                     : authority.substr(at + 1));
            }

            void LogHttpTarget(const char* label, const std::string& url, bool rewritten)
            {
                static volatile LONG logged = 0;
                if (InterlockedIncrement(&logged) > 40) { return; }
                std::string scheme;
                std::string authority;
                std::string suffix;
                if (!NetworkConfig::ParseUrlAny(url, scheme, authority, suffix)) {
                    Log::Verbose("[HTTP] %s scheme=? host=? family=unparsed rewritten=%d", label,
                                 rewritten ? 1 : 0);
                    return;
                }
                const std::string host = SafeAuthorityHost(authority);
                const char* family = host == "ns.rec.net"
                                         ? "ns.rec.net"
                                         : (config.routing.CertificateScope(host) ? "configured" : "other");
                Log::Verbose("[HTTP] %s scheme=%s host=%s family=%s rewritten=%d", label,
                             scheme.c_str(), host.c_str(), family, rewritten ? 1 : 0);
            }

            void* SafeNewString(const char* text)
            {
                void* result = nullptr;
                __try {
                    if (stringNew && text) { result = stringNew(text); }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    result = nullptr;
                }
                return result;
            }

            bool SafeReinitUri(void* uri, const char* text)
            {
                bool ok = false;
                __try {
                    void* managed = SafeNewString(text);
                    if (managed && uri && uriCtor) {
                        uriCtor(uri, managed, nullptr);
                        ok = true;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    ok = false;
                }
                return ok;
            }

            void* NameServerOverride()
            {
                static LONG logged = 0;
                if (!nameServerOrigin.empty()) {
                    void* value = SafeNewString(nameServerOrigin.c_str());
                    if (value) {
                        if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                            Log::Line("[Net] boot discovery uses configured name server host=%s",
                                      config.routing.api.host.c_str());
                        }
                        return value;
                    }
                    if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                        Log::Line("[Net] name server string allocation failed; native default retained");
                    }
                }
                return nameServerOriginal ? nameServerOriginal() : nullptr;
            }

            void* Send(void* request, void* method)
            {
                char text[8192] = {};
                if (TryRequestUri(request, text, sizeof(text))) {
                    const std::string url(text);
                    const std::string rewritten = NetworkConfig::Rewrite(url, config.routing.api);
                    LogHttpTarget("send", url, rewritten != url);
                    if (rewritten != url) {
                        void* uri = SafeRequestUri(request);
                        if (SafeReinitUri(uri, rewritten.c_str())) {
                            Log::Verbose("[HTTP] ns.rec.net request redirected");
                        }
                    }
                }
                return sendOriginal ? sendOriginal(request, method) : request;
            }

            void* BuildUri(void* transport, void* baseUri, void* method)
            {
                // REST requests are rewritten inside HTTPManager.SendRequest, but
                // SignalR constructs its own ws(s) URL before that hook sees it.
                // Rewrite the base object first so the derived socket URL uses
                // the configured host and the TLS bypass scope matches.
                if (baseUri) {
                    char text[8192] = {};
                    if (TryReadUriText(baseUri, text, sizeof(text))) {
                        const std::string rewritten = NetworkConfig::RewriteSignalR(text, config.routing.api);
                        LogHttpTarget("signalr-base", text, rewritten != text);
                        if (rewritten != text && SafeReinitUri(baseUri, rewritten.c_str())) {
                            static LONG logged = 0;
                            if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                                Log::Line("[SignalR] WebSocket base URI redirected to configured host");
                            }
                        }
                    }
                }
                void* uri = buildUriOriginal ? buildUriOriginal(transport, baseUri, method) : nullptr;
                // BuildUri may ignore the parameter and derive from the hub's
                // stored Uri, so normalize the result too.
                if (uri) {
                    char text[8192] = {};
                    if (TryReadUriText(uri, text, sizeof(text))) {
                        const std::string rewritten = NetworkConfig::RewriteSignalR(text, config.routing.api);
                        LogHttpTarget("signalr-result", text, rewritten != text);
                        if (rewritten != text) { (void)SafeReinitUri(uri, rewritten.c_str()); }
                    }
                }
                return uri;
            }

            void Certificate(void* instance, void* certificate, void* method)
            {
                char text[8192] = {};
                bool bypass = false;
                if (TryTlsUri(instance, text, sizeof(text))) {
                    std::string scheme;
                    std::string authority;
                    std::string suffix;
                    if (NetworkConfig::ParseUrlAny(text, scheme, authority, suffix) &&
                        config.routing.CertificateScope(SafeAuthorityHost(authority))) {
                        bypass = true;
                    }
                }
                if (bypass) {
                    static LONG logged = 0;
                    if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                        Log::Line("[TLS] SSL pinning patch active for configured domain");
                    }
                    return;
                }
                if (certificateOriginal) { certificateOriginal(instance, certificate, method); }
            }

            bool ImageVerify(void* data, void*, void*)
            {
                static LONG logged = 0;
                if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                    Log::Line("[Images] unsigned image acceptance active");
                }
                return data != nullptr;
            }

            bool DuidMismatch(void* instance, void** mismatched, void** actual, void* method)
            {
                bool original = false;
                __try {
                    if (duidOriginal) { original = duidOriginal(instance, mismatched, actual, method); }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    original = false;
                }
                static LONG logged = 0;
                if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                    Log::Line("[DUID] mismatch check forced false original=%d", original ? 1 : 0);
                }
                if (mismatched) { *mismatched = nullptr; }
                if (actual) { *actual = nullptr; }
                return false;
            }

            void TachyonCtor(void* instance, void* networking, void* dependencies, void* method)
            {
                if (tachyonCtorOriginal) {
                    tachyonCtorOriginal(instance, networking, dependencies, method);
                }
                if (config.voiceKeyXml.empty() || !stringNew || !instance) { return; }
                __try {
                    const auto provider = *reinterpret_cast<uintptr_t*>(
                        reinterpret_cast<uintptr_t>(instance) + Offsets::Tachyon::RsaProvider);
                    if (!provider) { return; }
                    const auto klass = *reinterpret_cast<uintptr_t*>(provider);
                    if (!klass) { return; }
                    const auto import = *reinterpret_cast<uintptr_t*>(klass + Offsets::RsaClass::ImportXml);
                    if (import != game + Methods::Rsa::FromXmlString) {
                        static LONG logged = 0;
                        if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                            Log::Line("[Voice] RSA signature unavailable; native key retained");
                        }
                        return;
                    }
                    void* xml = stringNew(config.voiceKeyXml.c_str());
                    if (!xml) { return; }
                    if (!rsaImportXml) {
                        rsaImportXml = reinterpret_cast<void (*)(void*, void*)>(
                            Gate(reinterpret_cast<void*>(import)));
                    }
                    if (!rsaImportXml) { return; }
                    rsaImportXml(reinterpret_cast<void*>(provider), xml);
                    static LONG logged = 0;
                    if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                        Log::Line("[Voice] configured public key applied to verified RSA provider");
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    static LONG logged = 0;
                    if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
                        Log::Line("[Voice] key import fault; native key retained");
                    }
                }
            }

            bool Hook(uintptr_t rva, void* callback, void** original, const char* name)
            {
                void* target = reinterpret_cast<void*>(game + rva);
                const MH_STATUS status = MH_CreateHook(target, callback, original);
                if (status == MH_OK) {
                    const MH_STATUS queued = MH_QueueEnableHook(target);
                    if (queued == MH_OK) {
                        Log::Verbose("[Hook] %s rva=0x%llX queued", name,
                                     static_cast<unsigned long long>(rva));
                        return true;
                    }
                    Log::Line("[Hook] %s queue failed status=%d", name, queued);
                    return false;
                }
                Log::Line("[Hook] %s create failed status=%d", name, status);
                return false;
            }
        }

        int Initialize(const Config::Settings& settings)
        {
            config = settings;
            nameServerOrigin = config.routing.NameServerOrigin();
            game = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"GameAssembly.dll"));
            if (!game) { return 2; }

            // This client has no IL2CPP exports; use the dump-derived managed
            // trampolines. MinHook detours stolen entry points, while gates
            // forward register arguments and supply x64 shadow space.
            stringNew = reinterpret_cast<void* (*)(const char*)>(GaExport("il2cpp_string_new"));
            if (!stringNew) {
                stringNew = reinterpret_cast<void* (*)(const char*)>(
                    Gate(reinterpret_cast<void*>(game + Methods::Interop::PtrToStringAnsi)));
            }
            uriString = reinterpret_cast<void* (*)(void*, void*)>(
                Gate(reinterpret_cast<void*>(game + Methods::Uri::ToString)));
            uriCtor = reinterpret_cast<void (*)(void*, void*, void*)>(
                Gate(reinterpret_cast<void*>(game + Methods::Uri::Constructor)));

            Log::Line("[Build] helpers string=%d uriString=%d uriCtor=%d",
                      stringNew ? 1 : 0, uriString ? 1 : 0, uriCtor ? 1 : 0);

            if (MH_Initialize() != MH_OK) {
                Log::Line("[Hook] MinHook initialize failed");
                return 4;
            }

            const bool wantRedirect = !config.routing.api.host.empty();
            bool anyHook = false;
            if (wantRedirect && stringNew) {
                anyHook = Hook(Methods::RecNet::NameServerOverrideGetter,
                               reinterpret_cast<void*>(NameServerOverride),
                               reinterpret_cast<void**>(&nameServerOriginal),
                               "RecNet.BLIBQRTNFZC") || anyHook;
            } else if (wantRedirect) {
                Log::Line("[Hook] name-server override skipped (string helper unavailable)");
            }

            if (wantRedirect && stringNew && uriString && uriCtor) {
                anyHook = Hook(Methods::HTTP::SendRequest, reinterpret_cast<void*>(Send),
                               reinterpret_cast<void**>(&sendOriginal),
                               "HTTPManager.SendRequest") || anyHook;
                anyHook = Hook(Methods::SignalR::WebSocketBuildUri, reinterpret_cast<void*>(BuildUri),
                               reinterpret_cast<void**>(&buildUriOriginal),
                               "WebSocketTransport.BuildUri") || anyHook;
            } else if (wantRedirect) {
                Log::Line("[Hook] HTTPManager.SendRequest skipped (URI helpers unavailable)");
            }

            const bool wantSsl = config.sslPinningPatch && !config.routing.SslDomain().empty();
            if (wantSsl && uriString) {
                anyHook = Hook(Methods::HTTP::NotifyServerCertificate,
                               reinterpret_cast<void*>(Certificate),
                               reinterpret_cast<void**>(&certificateOriginal),
                               "NotifyServerCertificate") || anyHook;
            } else if (config.sslPinningPatch) {
                Log::Line("[Hook] SSL pinning patch skipped (no service domain or URI helper)");
            }

            if (config.allowUnsignedImages) {
                anyHook = Hook(Methods::Images::Verify, reinterpret_cast<void*>(ImageVerify), nullptr,
                               "Images.FPKEWHLZXYJ") || anyHook;
            }
            if (config.suppressDuidMismatch) {
                anyHook = Hook(Methods::Session::CheckForDUIDMismatch,
                               reinterpret_cast<void*>(DuidMismatch),
                               reinterpret_cast<void**>(&duidOriginal),
                               "CheatManager.CheckForDUIDMismatch") || anyHook;
            }
            if (!config.voiceKeyXml.empty() && stringNew) {
                anyHook = Hook(Methods::Tachyon::Constructor, reinterpret_cast<void*>(TachyonCtor),
                               reinterpret_cast<void**>(&tachyonCtorOriginal),
                               "TachyonClient..ctor") || anyHook;
            }
            const bool traceQuit = QuitTraceEnabled();
            const bool suppressCheatQuit = SuppressCheatQuitEnabled();
            const bool suppressExitState = SuppressExitStateEnabled();
            if (suppressCheatQuit) {
                Log::Line("[QuitFix] enabled by SCHOOLSOUT_SUPPRESS_CHEAT_QUIT");
            }
            if (suppressExitState) {
                Log::Line("[QuitFix] enabled by SCHOOLSOUT_SUPPRESS_EXIT_STATE");
            }
            if (traceQuit || suppressCheatQuit || suppressExitState) {
                anyHook = Hook(Methods::Quit::CheatManagerFatalQuit,
                               reinterpret_cast<void*>(CheatManagerFatalQuitTrace),
                               reinterpret_cast<void**>(&cheatManagerFatalQuitOriginal),
                               "CheatManager.HRZIGTNFSHP.DCDTOGTESYJ") || anyHook;
            }
            if (traceQuit || suppressExitState) {
                anyHook = Hook(Methods::Quit::ExitStateSetter,
                               reinterpret_cast<void*>(ExitStateTrace),
                               reinterpret_cast<void**>(&exitStateOriginal),
                               "OTBCUXXIPTI.SetExitState") || anyHook;
            }
            if (traceQuit) {
                Log::Line("[QuitTrace] enabled by SCHOOLSOUT_TRACE_QUIT");
                anyHook = Hook(Methods::Unity::Application::QuitWithExitCode,
                               reinterpret_cast<void*>(ApplicationQuitWithExitCodeTrace),
                               reinterpret_cast<void**>(&applicationQuitWithExitCodeOriginal),
                               "Application.Quit(int)") || anyHook;
                anyHook = Hook(Methods::Unity::Application::Quit,
                               reinterpret_cast<void*>(ApplicationQuitTrace),
                               reinterpret_cast<void**>(&applicationQuitOriginal),
                               "Application.Quit()") || anyHook;
                anyHook = Hook(Methods::Unity::Application::InternalQuit,
                               reinterpret_cast<void*>(ApplicationInternalQuitTrace),
                               reinterpret_cast<void**>(&applicationInternalQuitOriginal),
                               "Application.Internal_ApplicationQuit()") || anyHook;
                anyHook = Hook(Methods::Quit::SessionFatalQuit,
                               reinterpret_cast<void*>(SessionFatalQuitTrace),
                               reinterpret_cast<void**>(&sessionFatalQuitOriginal),
                               "SessionManager.FatalApplicationQuit") || anyHook;
                anyHook = Hook(Methods::Quit::SessionTryQuitWithCode,
                               reinterpret_cast<void*>(SessionTryQuitWithCodeTrace),
                               reinterpret_cast<void**>(&sessionTryQuitWithCodeOriginal),
                               "SessionManager.TryApplicationQuit(int)") || anyHook;
                anyHook = Hook(Methods::Quit::SessionTryQuit,
                               reinterpret_cast<void*>(SessionTryQuitTrace),
                               reinterpret_cast<void**>(&sessionTryQuitOriginal),
                               "SessionManager.TryApplicationQuit()") || anyHook;
                anyHook = Hook(Methods::Quit::SessionModelQuit,
                               reinterpret_cast<void*>(SessionModelQuitTrace),
                               reinterpret_cast<void**>(&sessionModelQuitOriginal),
                               "SessionModel.ApplicationQuit") || anyHook;
                anyHook = Hook(Methods::Quit::SessionManagerAccessJoin,
                               reinterpret_cast<void*>(SessionManagerAccessJoinTrace),
                               reinterpret_cast<void**>(&sessionManagerAccessJoinOriginal),
                               "SessionManagerAccess.LHHRAFRXYAO") || anyHook;
            }

            const MH_STATUS applied = MH_ApplyQueued();
            Log::Line("[Hook] all hooks enabled status=%d any=%d", applied, anyHook ? 1 : 0);
            if (applied != MH_OK) {
                MH_Uninitialize();
                return 6;
            }
            return 0;
        }
    }
}
