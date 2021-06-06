#include <Windows.h>
#include <tlhelp32.h>

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
            case 2: {
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

HANDLE FindAllertableThread(HANDLE hProcess, DWORD dwPid) {
    HANDLE        hSnapshot, hTread, hEvent[2], hReturn = NULL;
    LPVOID        rm, pSetEvent, f[6];
    THREADENTRY32 threadEntry;
    SIZE_T        rd;
    DWORD         i;
    CONTEXT       context;
    ULONG_PTR     p;
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

    // wait a moment for thread to initialize
    Sleep(100);

    // resolve address of SetEvent
    hModule = GetModuleHandle(L"kernel32.dll");
    pSetEvent = GetProcAddress(hModule, "SetEvent");

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


INT main() {
    STARTUPINFOA			startupInfo;
    PROCESS_INFORMATION		processInformation;
    DWORD                   dwPid;
    LONG					lRetVal = ERROR_SUCCESS;
    HANDLE                  hProcess;
    HANDLE                  hTread;

    ZeroMemory(&startupInfo, sizeof startupInfo);
    startupInfo.cb = sizeof startupInfo;
    ZeroMemory(&processInformation, sizeof processInformation);

    if (!CreateProcessA(NULL, "\"calc.exe\"", NULL, NULL, FALSE,
        DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
        return ERROR_CREATE_FAILED;
    }

    dwPid = processInformation.dwProcessId;
    if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) == INVALID_HANDLE_VALUE) {
        lRetVal = ERROR_OPEN_FAILED;
        goto Cleanup;
    }

    hTread = FindAllertableThread(hProcess, dwPid);

Cleanup:
    if (processInformation.hProcess) {
        CloseHandle(processInformation.hProcess);
    }

    if (processInformation.hThread) {
        CloseHandle(processInformation.hThread);
    }

    return lRetVal;
}