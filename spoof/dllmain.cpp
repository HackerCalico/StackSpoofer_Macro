#include "pch.h"

__declspec(dllexport) PVOID Log(int run) {
    if (run) {
        volatile char buf[] = "12345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678";
        __asm {
            call rax
            mov rbx, qword ptr[rbx]
            jmp rbx
        }
    }
    return (PVOID)run;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}