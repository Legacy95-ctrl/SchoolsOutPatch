#pragma once

#include <cstddef>
#include <cstdint>

namespace SchoolsOut
{
    namespace Offsets
    {
        namespace String
        {
            inline constexpr uintptr_t Length = 0x10;
            inline constexpr uintptr_t Characters = 0x14;
        }

        namespace HTTPRequest
        {
            inline constexpr uintptr_t Uri = 0x10;
        }

        namespace TlsAuthentication
        {
            inline constexpr uintptr_t TargetUri = 0x20;
        }

        namespace Tachyon
        {
            inline constexpr uintptr_t RsaProvider = 0x48;
        }

        namespace RsaClass
        {
            // The current constructor calls [klass+0x210] and passes the value at
            // [klass+0x218] as the hidden MethodInfo argument. FromXmlString's
            // body uses only rcx (provider) and rdx (XML), so the gate forwards
            // two arguments and the signature check validates +0x210.
            inline constexpr uintptr_t ImportXml = 0x210;
        }

        namespace Referee
        {
            // Unpacked dump value is 0x02. When bit 2 is set, Referee reaches
            // the obfuscated int 0x29 at +0x274BF99 if its IAT probe returns
            // nonzero. Clearing this byte avoids that fail-fast.
            inline constexpr uintptr_t FailFastFlag = 0x5AB2B90;

            // The packed byte decrypts to FailFastFlag. Changing it in memory
            // before the suspended process runs avoids the on-disk modification
            // that Themida rejects as "File corrupted!".
            inline constexpr unsigned char PackedFailFastFlag = 0xFD;
            inline constexpr unsigned char DecryptedFailFastOff = 0xFF;

            // Referee+0x69A4E5 is "je session_fallback" (0F 84 07 03 00 00).
            // The earlier 0x69A487 RVA was the preceding "test cl, cl" and was
            // wrong. The fall-through at 0x69A4EB fully initializes the local
            // object; the fallback calls 0x613130, maps a named section, and
            // leaves the object's vector bounds unset, causing the later fault
            // at 0x69A98D.
            inline constexpr uintptr_t SessionFallbackBranch = 0x69A4E5;
            inline constexpr std::size_t SessionFallbackBranchSize = 6;

            // Forcing the jns at Referee+0x69A53E is deliberately not used.
            // The call at Referee+0x69A52E failed in live tests, so its output
            // pointer stayed zero and the forced success path dereferenced rcx=0
            // at Referee+0x69A592. The object-producing call must succeed instead.

            // Referee+0x69A533 is the instruction immediately after the local
            // preparation call at Referee+0x69A52E. A one-shot process-wide int3
            // here logs the call's return value in eax and the output pointer at
            // [rsp+0x28] without changing either. The original byte and RIP are
            // restored before execution continues.
            inline constexpr uintptr_t SessionLocalCallResult = 0x69A533;

            // Referee+0x21E4A2A is the indirect call to NtMapViewOfSection in
            // the object creator's obfuscated helper. A one-shot int3 here logs
            // the section/process handles, base pointer, and stack arguments
            // without changing them; the original byte and RIP are restored.
            inline constexpr uintptr_t MapViewCall = 0x21E4A2A;

            // Referee+0x21E3A65 is the indirect call to NtAllocateVirtualMemory
            // in the same object creator. It runs before the section is mapped,
            // so a one-shot int3 here logs the process handle, base/size pointers,
            // and allocation flags when the map-view trap does not fire.
            inline constexpr uintptr_t AllocateVirtualMemoryCall = 0x21E3A65;

            // One-shot int3 sites immediately after each API call in the object
            // creator at Referee+0x612A20. Logging eax at these instructions
            // identifies which helper returns STATUS_ACCESS_DENIED even when the
            // call itself began before the traps were armed.
            inline constexpr uintptr_t CreatorCreateSidResult = 0x612B9F;
            inline constexpr uintptr_t CreatorSetAclResult = 0x612C14;
            inline constexpr uintptr_t CreatorAllocateResult = 0x612D5A;
            inline constexpr uintptr_t CreatorInitSdResult = 0x612DA0;
            inline constexpr uintptr_t CreatorSetDaclResult = 0x612DE6;

            // Referee+0x612F4B is the call into the protected-section creation
            // helper. Its r8 still points at the stack OBJECT_ATTRIBUTES whose
            // +0x20 SecurityDescriptor field carries the DACL built above. Live
            // traps showed every earlier helper succeeding while the creator
            // returned C0000022 before NtMapViewOfSection was reached, so this
            // is the access-denied call. The debugger clears only that in-memory
            // pointer before executing the call; no Referee byte is patched on
            // disk and no object is fabricated.
            inline constexpr uintptr_t CreatorCreateSectionCall = 0x612F4B;
            inline constexpr uintptr_t CreatorCreateSectionResult = 0x612F50;

            // Inside the obfuscated NtCreateSection import wrapper at
            // Referee+0x21E3F40, the resolved system call is invoked at
            // Referee+0x21E4053. Its stack slot +0x60 holds the resolved
            // pointer and +0x20/+0x28/+0x30 hold the three stack arguments.
            inline constexpr uintptr_t CreatorSectionApiCall = 0x21E4053;

            // 0x612FE2 is inside the immediate of the mov at 0x612FE0, not an
            // instruction boundary; the real post-map-view instruction is
            // 0x6130E2 ("mov ebx, eax" after the call at 0x6130DD).
            inline constexpr uintptr_t CreatorMapViewResult = 0x6130E2;

            // Referee+0x69A98D is "mov eax, dword ptr [r8]" in the append
            // helper. The diagnostic execute breakpoint logs RCX/RDX/R8 and the
            // session object slot before this read faults with 0xC0000005.
            inline constexpr uintptr_t SessionAppendFault = 0x69A98D;

            // Referee+0x6B1E158 holds a pointer to the owner object whose first
            // qword receives the completed session on the success path. Reading
            // that pointer at a fault distinguishes an uninitialized owner from
            // a published session object.
            inline constexpr uintptr_t SessionObjectSlot = 0x6B1E158;
        }
    }
}
