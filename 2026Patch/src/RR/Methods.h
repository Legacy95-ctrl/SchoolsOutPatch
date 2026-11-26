#pragma once

#include <cstdint>

namespace SchoolsOut
{
    namespace Methods
    {
        namespace GameAssemblyImage
        {
            inline constexpr uintptr_t Size = 0xF505000;
        }

        // All RVAs below were re-derived from C:\Users\PC\Desktop\output for
        // 2026-03-31T03-05-36Z_473be467. Do not reuse them on another build.
        namespace RecNet
        {
            inline constexpr uintptr_t NameServerOverrideGetter = 0x800BDC0;
        }

        namespace HTTP
        {
            inline constexpr uintptr_t SendRequest = 0x7B1E9D0;
            inline constexpr uintptr_t NotifyServerCertificate = 0x7B26FF0;
        }

        namespace SignalR
        {
            // BestHTTP.SignalRCore.Transports.WebSocketTransport.BuildUri(Uri).
            // Unique RVA; unlike HubConnection.set_Uri it is not a shared stub.
            inline constexpr uintptr_t WebSocketBuildUri = 0x7B44DC0;
        }

        namespace Uri
        {
            inline constexpr uintptr_t ToString = 0x966FB00;
            inline constexpr uintptr_t Constructor = 0x9670E30;
        }

        namespace Interop
        {
            inline constexpr uintptr_t PtrToStringAnsi = 0x7561820;
        }

        namespace Images
        {
            // RecNet.Images.FPKEWHLZXYJ(byte[], byte[]) — private RSA verifier.
            inline constexpr uintptr_t Verify = 0x8029550;
        }

        namespace Session
        {
            // CheatManager.CheckForDUIDMismatch(out string, out string).
            inline constexpr uintptr_t CheckForDUIDMismatch = 0x1DE5370;
        }

        namespace Tachyon
        {
            inline constexpr uintptr_t Constructor = 0x86240C0;
        }

        namespace Rsa
        {
            inline constexpr uintptr_t FromXmlString = 0x74FC000;
        }

        namespace Unity
        {
            // UnityEngine.Application.Quit overloads. Used only by the opt-in
            // managed quit-caller trace; no patch decision depends on them.
            namespace Application
            {
                inline constexpr uintptr_t QuitWithExitCode = 0x9D93800;
                inline constexpr uintptr_t Quit = 0x9D93840;
                inline constexpr uintptr_t InternalQuit = 0x9D930D0;
            }
        }

        namespace Quit
        {
            // Opt-in managed quit-chain diagnostics. The anti-cheat callback
            // is the only site in this image that loads 0x1FC85836, the exit
            // code observed in Application.Quit(int).
            inline constexpr uintptr_t CheatManagerFatalQuit = 0x1DF1CC0;
            inline constexpr uintptr_t ExitStateSetter = 0x1DF5310;
            inline constexpr uintptr_t SessionFatalQuit = 0x1E11AB0;
            inline constexpr uintptr_t SessionTryQuitWithCode = 0x1E17CC0;
            inline constexpr uintptr_t SessionTryQuit = 0x1E17E40;
            inline constexpr uintptr_t SessionModelQuit = 0x26445C0;
            inline constexpr uintptr_t SessionManagerAccessJoin = 0x1E0EF80;
        }
    }
}
