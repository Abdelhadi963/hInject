#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "api.h"

// XOR decode function
char decryptedName[64];
const uint8_t key[] = "ippyokai";
const char secret[] = "ippyokai";

void decode(BYTE* buf, DWORD len) {
    int keyLen = sizeof(secret) - 1;
    for (DWORD i = 0; i < len; i++)
        buf[i] ^= secret[i % keyLen];
}

void rc4_init(uint8_t* s, const uint8_t* key, size_t keylen) {
    for (int i = 0; i < 256; i++) s[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) & 0xFF;
        uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

static void rc4(BYTE* key, size_t keyLen, BYTE* data, size_t dataLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    int i = 0; j = 0;
    for (size_t n = 0; n < dataLen; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

int _dll_i(int i) {
    if (i > 2) {
        printf("[-] Error: Invalid DLL index %d\n", i);
        return -1;
	}
    memcpy(decryptedName, dll_list[i].bytes, dll_list[i].length);
    decryptedName[dll_list[i].length] = '\0';
    rc4((BYTE*)key, sizeof(key) - 1, (BYTE*)decryptedName, dll_list[i].length);
    /*printf("[*] Decrypted DLL Name: %s\n", decryptedName);*/
    return 0;
}