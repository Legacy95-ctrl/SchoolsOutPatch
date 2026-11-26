#pragma once

#include <Windows.h>

#include <cstdarg>
#include <cstdio>
#include <string>

namespace SchoolsOut
{
    namespace Log
    {
        inline SRWLOCK lock = SRWLOCK_INIT;
        inline bool verbose = false;
        inline std::wstring path;

        inline void Line(const char* format, ...)
        {
            AcquireSRWLockExclusive(&lock);
            FILE* file = nullptr;
            if (_wfopen_s(&file, path.c_str(), L"a")) { ReleaseSRWLockExclusive(&lock); return; }
            char text[1024];
            va_list args;
            va_start(args, format);
            _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
            va_end(args);
            fputs(text, file);
            fputc('\n', file);
            fclose(file);
            ReleaseSRWLockExclusive(&lock);
        }

        inline void Verbose(const char* format, ...)
        {
            if (!verbose) { return; }
            AcquireSRWLockExclusive(&lock);
            FILE* file = nullptr;
            if (_wfopen_s(&file, path.c_str(), L"a")) { ReleaseSRWLockExclusive(&lock); return; }
            char text[1024];
            va_list args;
            va_start(args, format);
            _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
            va_end(args);
            fputs(text, file);
            fputc('\n', file);
            fclose(file);
            ReleaseSRWLockExclusive(&lock);
        }

        inline void Begin(const std::wstring& directory)
        {
            AcquireSRWLockExclusive(&lock);
            path = directory + L"\\2026patch.log";
            FILE* file = nullptr;
            if (!_wfopen_s(&file, path.c_str(), L"w")) {
                fputs("SchoolsOutPatch 2026-03-31T03-05-36Z_473be467\n", file);
                fclose(file);
            }
            ReleaseSRWLockExclusive(&lock);
        }
    }
}
