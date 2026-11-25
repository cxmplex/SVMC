#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "svm_probe_ioctl.h"
#include "svm_open_shared.h"

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040UL
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif

void *g_NtOpenFile;
extern void SvmUserOpen(void);
extern void SvmUserTrap(void);

typedef NTSTATUS (NTAPI *NT_OPEN_FILE_FN)(PHANDLE, ACCESS_MASK,
                                          POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                          ULONG, ULONG);

typedef struct _OPEN_WORKER {
    HANDLE Ready;
    NT_OPEN_FILE_FN NtOpenFile;
    HANDLE File;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    ULONGLONG StartTick;
    ULONGLONG EndTick;
    UNICODE_STRING AliasName;
    UNICODE_STRING RealName;
    OBJECT_ATTRIBUTES AliasAttributes;
    OBJECT_ATTRIBUTES RealAttributes;
} OPEN_WORKER;

typedef struct _DIAG_WATCH {
    HANDLE Device;
    HANDLE Ready;
    HANDLE Stop;
    DWORD Error;
} DIAG_WATCH;

typedef struct _PROCESS_STOPPER {
    HANDLE Process;
    ULONGLONG ExitTick;
    ULONGLONG SentTick;
    DWORD Error;
    int SawExit;
    int StopOk;
} PROCESS_STOPPER;

typedef struct _MONITOR_WORKER {
    HANDLE Device;
    USHORT Group;
    KAFFINITY Mask; /* zero keeps the legacy CPU-0 affinity path */
    SVM_RUN_INPUT Input;
    SVM_RUN_RESULT Result;
    DWORD Error;
    int Ok;
} MONITOR_WORKER;

typedef struct _MULTI_CHILD {
    PROCESS_INFORMATION Process;
    HANDLE Output;
    DWORD ExitCode;
    char Text[256];
} MULTI_CHILD;

static DWORD WINAPI RunMonitorWorker(PVOID parameter)
{
    MONITOR_WORKER *worker = (MONITOR_WORKER *)parameter;
    DWORD returned = 0;
    GROUP_AFFINITY affinity = {0};
    affinity.Group = worker->Group;
    affinity.Mask = worker->Mask;
    if (!(worker->Mask ?
          SetThreadGroupAffinity(GetCurrentThread(), &affinity, NULL) :
          SetThreadAffinityMask(GetCurrentThread(), 1) != 0)) {
        worker->Error = GetLastError();
        return 1;
    }
    worker->Ok = DeviceIoControl(worker->Device, SVM_PROBE_IOCTL_RUN,
                                 &worker->Input, sizeof(worker->Input),
                                 &worker->Result, sizeof(worker->Result),
                                 &returned, NULL) != 0;
    if (!worker->Ok) worker->Error = GetLastError();
    return worker->Ok ? 0 : 1;
}

static DWORD WINAPI StopAfterProcess(PVOID parameter)
{
    PROCESS_STOPPER *stopper = (PROCESS_STOPPER *)parameter;
    HANDLE device;
    DWORD returned = 0;
    unsigned i;
    SetThreadAffinityMask(GetCurrentThread(), 2);
    if (WaitForSingleObject(stopper->Process, 4500) == WAIT_OBJECT_0) {
        stopper->SawExit = 1;
        stopper->ExitTick = GetTickCount64();
    }
    device = CreateFileW(L"\\\\.\\SvmcProbe", GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        stopper->Error = GetLastError();
        return 1;
    }
    for (i = 0; i < 1000; ++i) {
        SVM_DIAG diag = {0};
        if (DeviceIoControl(device, SVM_PROBE_IOCTL_DIAG, NULL, 0,
                            &diag, sizeof(diag), &returned, NULL) &&
            diag.Mode == 5 && diag.State >= 2 && diag.State <= 4) {
            stopper->SentTick = GetTickCount64();
            stopper->StopOk = DeviceIoControl(device, SVM_PROBE_IOCTL_STOP,
                                              NULL, 0, NULL, 0,
                                              &returned, NULL) != 0;
            if (!stopper->StopOk) stopper->Error = GetLastError();
            break;
        }
        Sleep(1);
    }
    if (i == 1000) stopper->Error = WAIT_TIMEOUT;
    CloseHandle(device);
    return stopper->StopOk ? 0 : 1;
}

static DWORD WINAPI DiagWatchWorker(PVOID parameter)
{
    DIAG_WATCH *watch = (DIAG_WATCH *)parameter;
    HANDLE file;
    SVM_DIAG previous = {0};
    SetThreadAffinityMask(GetCurrentThread(), 2);
    file = CreateFileW(L"C:\\SvmLab\\diag-watch.log", GENERIC_WRITE,
                       FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    watch->Error = file == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    SetEvent(watch->Ready);
    if (file == INVALID_HANDLE_VALUE) return 1;
    do {
        SVM_DIAG diag = {0};
        DWORD returned = 0;
        if (DeviceIoControl(watch->Device, SVM_PROBE_IOCTL_DIAG, NULL, 0,
                            &diag, sizeof(diag), &returned, NULL) &&
            (diag.State != previous.State || diag.ExitCount != previous.ExitCount ||
             diag.FaultCount != previous.FaultCount ||
             diag.LstarFallback != previous.LstarFallback)) {
            char line[320];
            DWORD written = 0;
            int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                "tick=%llu state=%llu exits=%llu code=0x%llX rip=0x%llX nrip=0x%llX info1=0x%llX info2=0x%llX faults=%llu fallback=%llu cpl=%llu first_rip=0x%llX first_addr=0x%llX first_err=0x%llX first_rsp=0x%llX first_cr3=0x%llX\r\n",
                (unsigned long long)GetTickCount64(),
                (unsigned long long)diag.State,
                (unsigned long long)diag.ExitCount,
                (unsigned long long)diag.ExitCode,
                (unsigned long long)diag.Rip,
                (unsigned long long)diag.Nrip,
                (unsigned long long)diag.ExitInfo1,
                (unsigned long long)diag.ExitInfo2,
                (unsigned long long)diag.FaultCount,
                (unsigned long long)diag.LstarFallback,
                (unsigned long long)diag.Cpl,
                (unsigned long long)diag.FirstFaultRip,
                (unsigned long long)diag.FirstFaultAddress,
                (unsigned long long)diag.FirstFaultError,
                (unsigned long long)diag.FirstFaultRsp,
                (unsigned long long)diag.FirstFaultCr3);
            if (n > 0) {
                WriteFile(file, line, (DWORD)n, &written, NULL);
                FlushFileBuffers(file);
            }
            previous = diag;
        }
    } while (WaitForSingleObject(watch->Stop, 1) == WAIT_TIMEOUT);
    CloseHandle(file);
    return 0;
}

static DWORD WINAPI OpenWorker(PVOID parameter)
{
    OPEN_WORKER *worker = (OPEN_WORKER *)parameter;
    SetThreadAffinityMask(GetCurrentThread(), 1);
    SetEvent(worker->Ready);
    Sleep(30);
    worker->StartTick = GetTickCount64();
    worker->Status = worker->NtOpenFile(&worker->File,
                                       FILE_READ_DATA | SYNCHRONIZE,
                                       &worker->AliasAttributes,
                                       &worker->IoStatus,
                                       FILE_SHARE_READ,
                                       FILE_NON_DIRECTORY_FILE |
                                       FILE_SYNCHRONOUS_IO_NONALERT);
    worker->EndTick = GetTickCount64();
    return 0;
}

static int RunMultiWindow(HANDLE control)
{
    SVM_MULTI_INFO info = {0};
    MONITOR_WORKER *workers = NULL;
    HANDLE *threads = NULL;
    DWORD returned = 0;
    ULONG count, index = 0, group, number, i;
    USHORT groups;
    int begun = 0, stopped = 0, good = 0, ready = 0;

    if (!DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_INFO, NULL, 0,
                         &info, sizeof(info), &returned, NULL))
        return 1;
    count = info.CpuCount;
    groups = GetActiveProcessorGroupCount();
    if (count < 2 || count > 64 || info.Armed || groups == 0) {
        fprintf(stderr, "unsupported multi layout cpus=%lu groups=%u\n", count, groups);
        return 1;
    }
    workers = calloc(count, sizeof(*workers));
    threads = calloc(count, sizeof(*threads));
    if (!workers || !threads) goto cleanup;
    if (!DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_BEGIN,
                         NULL, 0, NULL, 0, &returned, NULL)) goto cleanup;
    begun = 1;
    for (group = 0; group < groups; ++group) {
        ULONG group_count = GetActiveProcessorCount((WORD)group);
        for (number = 0; number < group_count; ++number) {
            MONITOR_WORKER *worker;
            if (index >= count || number >= sizeof(KAFFINITY) * 8) goto cleanup;
            worker = &workers[index];
            worker->Device = CreateFileW(L"\\\\.\\SvmcProbe", GENERIC_READ,
                                         FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                         0, NULL);
            if (worker->Device == INVALID_HANDLE_VALUE) goto cleanup;
            worker->Group = (USHORT)group;
            worker->Mask = ((KAFFINITY)1) << number;
            worker->Input.Mode = 5;
            worker->Input.Reserved = SVM_RUN_FLAG_LSTAR |
                SVM_RUN_FLAG_NO_PF_INTERCEPT | SVM_RUN_FLAG_ALLOW_STOP |
                SVM_RUN_FLAG_MULTI;
            worker->Input.DesiredStatus = 2000;
            threads[index] = CreateThread(NULL, 0, RunMonitorWorker,
                                          worker, 0, NULL);
            if (!threads[index]) goto cleanup;
            index++;
        }
    }
    if (index != count) goto cleanup;
    for (i = 0; i < 1000; ++i) {
        ULONG cpu;
        ready = DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_INFO, NULL, 0,
                                &info, sizeof(info), &returned, NULL) &&
                info.ActiveCount == count;
        for (cpu = 0; ready && cpu < count; ++cpu) {
            SVM_CPU_DIAG query = {0};
            query.CpuIndex = cpu;
            ready = DeviceIoControl(control, SVM_PROBE_IOCTL_DIAG_CPU,
                                    &query, sizeof(query), &query, sizeof(query),
                                    &returned, NULL) &&
                    query.Diag.Mode == 5 &&
                    query.Diag.State >= 2 && query.Diag.State <= 4;
        }
        if (ready) break;
        Sleep(1);
    }
    if (!ready) {
        fprintf(stderr, "multi workers did not all enter\n");
        goto cleanup;
    }
    Sleep(150);
    stopped = DeviceIoControl(control, SVM_PROBE_IOCTL_STOP,
                              NULL, 0, NULL, 0, &returned, NULL) != 0;
    if (!stopped) goto cleanup;
    good = 1;
    for (i = 0; i < count; ++i) {
        if (WaitForSingleObject(threads[i], 3000) != WAIT_OBJECT_0 ||
            !workers[i].Ok || workers[i].Result.ExitCode != 0x43 ||
            workers[i].Result.CpuIndex != i ||
            workers[i].Result.WindowStoppedBySignal != 1 ||
            workers[i].Result.WindowUnexpected != 0) good = 0;
        printf("multi_cpu index=%lu ok=%d error=%lu exit=0x%llX syscalls=%lu hypercalls=%lu stop=%lu observed_cpu=%lu\n",
               i, workers[i].Ok, workers[i].Error,
               workers[i].Result.ExitCode, workers[i].Result.WindowSyscalls,
               workers[i].Result.WindowHypercalls,
               workers[i].Result.WindowStoppedBySignal,
               workers[i].Result.CpuIndex);
    }
cleanup:
    if (begun && !stopped)
        DeviceIoControl(control, SVM_PROBE_IOCTL_STOP,
                        NULL, 0, NULL, 0, &returned, NULL);
    if (threads) for (i = 0; i < count; ++i)
        if (threads[i]) WaitForSingleObject(threads[i], INFINITE);
    if (begun) {
        int ended = DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_END,
                                    NULL, 0, NULL, 0, &returned, NULL) != 0;
        SVM_MULTI_INFO after = {0};
        int queried = DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_INFO,
                                      NULL, 0, &after, sizeof(after),
                                      &returned, NULL) != 0;
        printf("multi_end active=%lu armed=%lu stop=%lu\n",
               after.ActiveCount, after.Armed, after.StopSignaled);
        if (!ended || !queried || after.ActiveCount || after.Armed) good = 0;
    }
    if (workers) for (i = 0; i < count; ++i)
        if (workers[i].Device && workers[i].Device != INVALID_HANDLE_VALUE)
            CloseHandle(workers[i].Device);
    free(threads);
    free(workers);
    return good ? 0 : 2;
}

static int RunMultiStatus(HANDLE control)
{
    unsigned char *stub = (unsigned char *)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    SVM_MULTI_INFO info = {0};
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    MONITOR_WORKER *workers = NULL;
    MULTI_CHILD *children = NULL;
    HANDLE *threads = NULL, *process_handles = NULL;
    DWORD returned = 0;
    ULONG count, index = 0, thread_count = 0, group, number, i, service = 0;
    USHORT groups;
    int begun = 0, stopped = 0, ready = 0, good = 0;
    const wchar_t command_template[] =
        L"\"C:\\SvmLab\\svmc_ntopen_probe.exe\" C:\\SvmLab\\real.txt";

    if (!stub || memcmp(stub, "\x4C\x8B\xD1\xB8", 4) != 0 ||
        stub[18] != 0x0F || stub[19] != 0x05) return 1;
    memcpy(&service, stub + 4, sizeof(service));
    if (!DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_INFO, NULL, 0,
                         &info, sizeof(info), &returned, NULL)) return 1;
    count = info.CpuCount;
    groups = GetActiveProcessorGroupCount();
    if (count < 2 || count > 16 || groups == 0 || info.Armed) return 1;
    workers = calloc(count, sizeof(*workers));
    children = calloc(count, sizeof(*children));
    threads = calloc(count, sizeof(*threads));
    process_handles = calloc(count, sizeof(*process_handles));
    if (!workers || !children || !threads || !process_handles) goto cleanup;
    for (i = 0; i < count; ++i) {
        workers[i].Device = INVALID_HANDLE_VALUE;
        children[i].Output = INVALID_HANDLE_VALUE;
    }

    for (group = 0; group < groups; ++group) {
        ULONG group_count = GetActiveProcessorCount((WORD)group);
        for (number = 0; number < group_count; ++number) {
            GROUP_AFFINITY affinity = {0};
            STARTUPINFOW startup = {0};
            SVM_PROCESS_CR3 process_cr3 = {0};
            wchar_t output_path[128];
            wchar_t command[_countof(command_template)];
            MONITOR_WORKER *worker;
            MULTI_CHILD *child;
            if (index >= count || number >= sizeof(KAFFINITY) * 8) goto cleanup;
            worker = &workers[index];
            child = &children[index];
            affinity.Group = (USHORT)group;
            affinity.Mask = ((KAFFINITY)1) << number;
            swprintf_s(output_path, _countof(output_path),
                       L"C:\\SvmLab\\svmc-multi-%lu.txt", index);
            child->Output = CreateFileW(output_path, GENERIC_READ | GENERIC_WRITE,
                                        FILE_SHARE_READ, &security, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (child->Output == INVALID_HANDLE_VALUE) goto cleanup;
            startup.cb = sizeof(startup);
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup.hStdOutput = child->Output;
            startup.hStdError = child->Output;
            wcscpy_s(command, _countof(command), command_template);
            if (!CreateProcessW(L"C:\\SvmLab\\svmc_ntopen_probe.exe", command,
                                NULL, NULL, TRUE,
                                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                NULL, NULL, &startup, &child->Process)) goto cleanup;
            SetHandleInformation(child->Output, HANDLE_FLAG_INHERIT, 0);
            if (!SetThreadGroupAffinity(child->Process.hThread, &affinity, NULL))
                goto cleanup;
            process_handles[index] = child->Process.hProcess;
            process_cr3.ProcessId = child->Process.dwProcessId;
            if (!DeviceIoControl(control, SVM_PROBE_IOCTL_PROCESS_CR3,
                                 &process_cr3, sizeof(process_cr3),
                                 &process_cr3, sizeof(process_cr3),
                                 &returned, NULL)) goto cleanup;
            worker->Device = CreateFileW(L"\\\\.\\SvmcProbe", GENERIC_READ,
                                         FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                         0, NULL);
            if (worker->Device == INVALID_HANDLE_VALUE) goto cleanup;
            worker->Group = (USHORT)group;
            worker->Mask = affinity.Mask;
            worker->Input.Mode = 5;
            worker->Input.Reserved = SVM_RUN_FLAG_LSTAR |
                SVM_RUN_FLAG_NO_PF_INTERCEPT | SVM_RUN_FLAG_ALLOW_STOP |
                SVM_RUN_FLAG_MULTI | SVM_RUN_FLAG_OVERRIDE_OPEN_STATUS |
                SVM_RUN_FLAG_MATCH_ACCESS;
            worker->Input.DesiredStatus = 5000;
            worker->Input.ExpectedService = service;
            worker->Input.Reserved2 = 2;
            worker->Input.OverrideStatus = 0xC0000022u;
            worker->Input.ExpectedAccess = FILE_READ_DATA | SYNCHRONIZE;
            worker->Input.TargetProcessId = child->Process.dwProcessId;
            worker->Input.ExpectedCr3 = process_cr3.AttachedCr3;
            index++;
        }
    }
    if (index != count ||
        !DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_BEGIN,
                         NULL, 0, NULL, 0, &returned, NULL)) goto cleanup;
    begun = 1;
    for (i = 0; i < count; ++i) {
        threads[i] = CreateThread(NULL, 0, RunMonitorWorker,
                                  &workers[i], 0, NULL);
        if (!threads[i]) goto cleanup;
        thread_count++;
    }
    for (i = 0; i < 1000; ++i) {
        ULONG cpu;
        ready = DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_INFO, NULL, 0,
                                &info, sizeof(info), &returned, NULL) &&
                info.ActiveCount == count;
        for (cpu = 0; ready && cpu < count; ++cpu) {
            SVM_CPU_DIAG query = {0};
            query.CpuIndex = cpu;
            ready = DeviceIoControl(control, SVM_PROBE_IOCTL_DIAG_CPU,
                                    &query, sizeof(query), &query, sizeof(query),
                                    &returned, NULL) &&
                    query.Diag.Mode == 5 &&
                    query.Diag.State >= 2 && query.Diag.State <= 4;
        }
        if (ready) break;
        Sleep(1);
    }
    if (!ready) goto cleanup;
    for (i = 0; i < count; ++i)
        if (ResumeThread(children[i].Process.hThread) == (DWORD)-1) goto cleanup;
    if (WaitForMultipleObjects(count, process_handles, TRUE, 4000) != WAIT_OBJECT_0)
        goto cleanup;
    stopped = DeviceIoControl(control, SVM_PROBE_IOCTL_STOP,
                              NULL, 0, NULL, 0, &returned, NULL) != 0;
    if (!stopped ||
        WaitForMultipleObjects(count, threads, TRUE, 5000) != WAIT_OBJECT_0)
        goto cleanup;
    good = 1;
    for (i = 0; i < count; ++i) {
        DWORD read_count = 0;
        MULTI_CHILD *child = &children[i];
        MONITOR_WORKER *worker = &workers[i];
        GetExitCodeProcess(child->Process.hProcess, &child->ExitCode);
        FlushFileBuffers(child->Output);
        SetFilePointer(child->Output, 0, NULL, FILE_BEGIN);
        ReadFile(child->Output, child->Text, sizeof(child->Text) - 1,
                 &read_count, NULL);
        if (!worker->Ok || worker->Result.ExitCode != 0x43 ||
            worker->Result.CpuIndex != i ||
            worker->Result.WindowStatusOverrides != 1 ||
            worker->Result.AppliedStatus != 0xC0000022u ||
            worker->Result.WindowStoppedBySignal != 1 ||
            worker->Result.WindowUnexpected != 0 || child->ExitCode != 1 ||
            !strstr(child->Text, "status=0xC0000022")) good = 0;
        printf("multi_status cpu=%lu pid=%lu child_exit=%lu monitor_ok=%d overrides=%lu match_index=%lu applied=0x%08lX cr3_hits=%lu syscalls=%lu stop=%lu output=%s\n",
               i, child->Process.dwProcessId, child->ExitCode,
               worker->Ok, worker->Result.WindowStatusOverrides,
               worker->Result.OverrideMatchIndex,
               worker->Result.AppliedStatus, worker->Result.ProcessCr3Hits,
               worker->Result.WindowSyscalls,
               worker->Result.WindowStoppedBySignal, child->Text);
        {
            ULONG event;
            for (event = 0; event < worker->Result.OpenTraceCount; ++event)
                printf("multi_entry cpu=%lu index=%lu access=0x%llX cr3=0x%llX\n",
                       i, event + 1,
                       worker->Result.OpenTrace[event].DesiredAccess,
                       worker->Result.OpenTrace[event].Cr3);
        }
    }
cleanup:
    if (begun && !stopped)
        DeviceIoControl(control, SVM_PROBE_IOCTL_STOP,
                        NULL, 0, NULL, 0, &returned, NULL);
    if (children) for (i = 0; i < count; ++i)
        if (children[i].Process.hProcess &&
            WaitForSingleObject(children[i].Process.hProcess, 0) != WAIT_OBJECT_0)
            TerminateProcess(children[i].Process.hProcess, 3);
    /* Keep the worker storage alive until every RUN IOCTL returns. Each
     * guest window has its own five-second deadline after a stop request.
     */
    for (i = 0; i < thread_count; ++i)
        WaitForSingleObject(threads[i], INFINITE);
    if (begun) {
        int ended = DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_END,
                                    NULL, 0, NULL, 0, &returned, NULL) != 0;
        SVM_MULTI_INFO after = {0};
        int queried = DeviceIoControl(control, SVM_PROBE_IOCTL_MULTI_INFO,
                                      NULL, 0, &after, sizeof(after),
                                      &returned, NULL) != 0;
        printf("multi_end active=%lu armed=%lu stop=%lu\n",
               after.ActiveCount, after.Armed, after.StopSignaled);
        if (!ended || !queried || after.ActiveCount || after.Armed) good = 0;
    }
    if (threads) for (i = 0; i < count; ++i)
        if (threads[i]) CloseHandle(threads[i]);
    if (workers) for (i = 0; i < count; ++i)
        if (workers[i].Device && workers[i].Device != INVALID_HANDLE_VALUE)
            CloseHandle(workers[i].Device);
    if (children) for (i = 0; i < count; ++i) {
        if (children[i].Process.hThread) CloseHandle(children[i].Process.hThread);
        if (children[i].Process.hProcess) CloseHandle(children[i].Process.hProcess);
        if (children[i].Output && children[i].Output != INVALID_HANDLE_VALUE)
            CloseHandle(children[i].Output);
    }
    free(process_handles);
    free(threads);
    free(children);
    free(workers);
    return good ? 0 : 2;
}

static int RunProcessOpen(HANDLE device, int diagnostic, int until_exit)
{
    wchar_t map_name[128], ready_name[128], go_name[128], done_name[128];
    wchar_t command_line[640];
    HANDLE mapping = NULL, ready = NULL, go = NULL, done = NULL;
    SVM_OPEN_SHARED *shared = NULL;
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    PROCESS_STOPPER stopper = {0};
    HANDLE stopper_thread = NULL;
    SVM_RUN_INPUT input = {0};
    SVM_RUN_RESULT run = {0};
    SVM_PROCESS_CR3 process_cr3 = {0};
    ULONGLONG start = 0, end = 0, tick = GetTickCount64();
    DWORD returned = 0, child_exit = 0xFFFFFFFF;
    int good = 0;

    swprintf_s(map_name, _countof(map_name), L"Local\\SvmOpen_%lu_%llu_Map",
               GetCurrentProcessId(), (unsigned long long)tick);
    swprintf_s(ready_name, _countof(ready_name), L"Local\\SvmOpen_%lu_%llu_Ready",
               GetCurrentProcessId(), (unsigned long long)tick);
    swprintf_s(go_name, _countof(go_name), L"Local\\SvmOpen_%lu_%llu_Go",
               GetCurrentProcessId(), (unsigned long long)tick);
    swprintf_s(done_name, _countof(done_name), L"Local\\SvmOpen_%lu_%llu_Done",
               GetCurrentProcessId(), (unsigned long long)tick);
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                 0, sizeof(SVM_OPEN_SHARED), map_name);
    ready = CreateEventW(NULL, TRUE, FALSE, ready_name);
    go = CreateEventW(NULL, TRUE, FALSE, go_name);
    done = CreateEventW(NULL, TRUE, FALSE, done_name);
    if (!mapping || !ready || !go || !done) {
        fprintf(stderr, "process IPC setup error=%lu\n", GetLastError());
        goto cleanup;
    }
    shared = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared));
    if (!shared) {
        fprintf(stderr, "process map error=%lu\n", GetLastError());
        goto cleanup;
    }
    ZeroMemory(shared, sizeof(*shared));
    shared->MonitoredStatus = (LONG)0xC0000001L;
    startup.cb = sizeof(startup);
    swprintf_s(command_line, _countof(command_line),
               L"\"C:\\SvmLab\\svmc_open_worker.exe\" \"%s\" \"%s\" \"%s\" \"%s\" %lu",
               map_name, ready_name, go_name, done_name,
               until_exit ? 1200UL : 0UL);
    if (!CreateProcessW(L"C:\\SvmLab\\svmc_open_worker.exe", command_line,
                        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                        &startup, &process) ||
        WaitForSingleObject(ready, 5000) != WAIT_OBJECT_0 ||
        InterlockedCompareExchange(&shared->Ready, 0, 0) != 1 ||
        shared->SetupError != 0) {
        fprintf(stderr, "worker process setup failed error=%lu child_error=%lu\n",
                GetLastError(), shared->SetupError);
        goto cleanup;
    }
    process_cr3.ProcessId = process.dwProcessId;
    if (!DeviceIoControl(device, SVM_PROBE_IOCTL_PROCESS_CR3,
                         &process_cr3, sizeof(process_cr3),
                         &process_cr3, sizeof(process_cr3),
                         &returned, NULL)) {
        fprintf(stderr, "process CR3 query failed error=%lu\n", GetLastError());
        goto cleanup;
    }
    input.Mode = 5;
    input.Reserved = SVM_RUN_FLAG_LSTAR |
        (diagnostic ? SVM_RUN_FLAG_STOP_ON_FIRST_PF :
                      SVM_RUN_FLAG_NO_PF_INTERCEPT);
    if (until_exit) input.Reserved |= SVM_RUN_FLAG_ALLOW_STOP;
    input.DesiredStatus = until_exit ? 5000 : 1000;
    input.OutHandlePointer = shared->OutHandlePointer;
    input.ObjectAttributesPointer = shared->ObjectAttributesPointer;
    input.ReplacementObjectAttributesPointer =
        shared->ReplacementObjectAttributesPointer;
    input.IoStatusPointer = shared->IoStatusPointer;
    input.ExpectedService = shared->ExpectedService;
    input.ExpectedReturnRip = shared->ExpectedReturnRip;
    input.TargetProcessId = process.dwProcessId;
    input.ExpectedCr3 = process_cr3.AttachedCr3;
    if (!SetThreadAffinityMask(GetCurrentThread(), 1)) {
        fprintf(stderr, "monitor affinity failed\n");
        goto cleanup;
    }
    if (until_exit) {
        stopper.Process = process.hProcess;
        stopper_thread = CreateThread(NULL, 0, StopAfterProcess,
                                      &stopper, 0, NULL);
        if (!stopper_thread) {
            fprintf(stderr, "stopper thread error=%lu\n", GetLastError());
            goto cleanup;
        }
    }
    SetEvent(go);
    start = GetTickCount64();
    if (!DeviceIoControl(device, SVM_PROBE_IOCTL_RUN, &input, sizeof(input),
                         &run, sizeof(run), &returned, NULL)) {
        fprintf(stderr, "monitor run error=%lu\n", GetLastError());
        goto cleanup;
    }
    end = GetTickCount64();
    if (stopper_thread && WaitForSingleObject(stopper_thread, 2000) != WAIT_OBJECT_0) {
        fprintf(stderr, "stopper did not finish\n");
        goto cleanup;
    }
    if (WaitForSingleObject(done, 2000) != WAIT_OBJECT_0 ||
        WaitForSingleObject(process.hProcess, 2000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &child_exit)) {
        fprintf(stderr, "worker process completion failed\n");
        goto cleanup;
    }
    good = (!until_exit ||
            (stopper.SawExit && stopper.StopOk &&
             run.WindowStoppedBySignal == 1 &&
             stopper.ExitTick >= start && stopper.ExitTick <= end &&
             end - start < 5000)) &&
           child_exit == 0 && shared->DirectBefore == (LONG)0xC0000034L &&
           shared->MonitoredStatus == 0 &&
           shared->DirectAfter == (LONG)0xC0000034L &&
           shared->StartTick >= start && shared->EndTick <= end &&
           run.ExitCode == 0x43 && run.WindowRewrites == 1 &&
           run.ProcessCr3Hits >= 1 &&
           run.WindowSyscalls > 0 && run.WindowUnexpected == 0 &&
           (strcmp(shared->Payload, "SVM-LAB-REAL\r\n") == 0 ||
            strcmp(shared->Payload, "SVM-LAB-REAL\n") == 0 ||
            strcmp(shared->Payload, "SVM-LAB-REAL") == 0);
    printf("process_open pid=%lu child_exit=%lu direct_before=0x%08lX monitored=0x%08lX direct_after=0x%08lX syscalls=%lu rewrites=%lu hypercalls=%lu attached_cr3=0x%llX rewrite_cr3=0x%llX cr3_hits=%lu path_probes=%lu path_matches=%lu path_errors=%lu window_ms=%llu child_start=%llu child_end=%llu stop_signal=%lu stop_ok=%d process_exit_ms=%llu payload=%s\n",
           process.dwProcessId, child_exit,
           (unsigned long)shared->DirectBefore,
           (unsigned long)shared->MonitoredStatus,
           (unsigned long)shared->DirectAfter,
           (unsigned long)run.WindowSyscalls,
           (unsigned long)run.WindowRewrites,
           (unsigned long)run.WindowHypercalls,
           (unsigned long long)process_cr3.AttachedCr3,
           (unsigned long long)run.RewriteCr3,
           (unsigned long)run.ProcessCr3Hits,
           (unsigned long)run.PathProbeHits,
           (unsigned long)run.PathMatches,
           (unsigned long)run.PathProbeErrors,
           (unsigned long long)(end - start),
           (unsigned long long)(shared->StartTick - start),
           (unsigned long long)(shared->EndTick - start),
           (unsigned long)run.WindowStoppedBySignal,
           stopper.StopOk,
           stopper.SawExit ? (unsigned long long)(stopper.ExitTick - start) : 0,
           shared->Payload);
cleanup:
    if (process.hProcess &&
        WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0)
        TerminateProcess(process.hProcess, 3);
    if (stopper_thread) {
        WaitForSingleObject(stopper_thread, 5000);
        CloseHandle(stopper_thread);
    }
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (shared) UnmapViewOfFile(shared);
    if (mapping) CloseHandle(mapping);
    if (ready) CloseHandle(ready);
    if (go) CloseHandle(go);
    if (done) CloseHandle(done);
    return good ? 0 : 2;
}

/* action: 0 = observe, 1 = null the third argument, 2 = return a status. */
static int RunUnmodifiedOpen(HANDLE device, ULONG target_index, int action)
{
    int capture_only = action == 0;
    int status_override = action == 2;
    unsigned char *stub = (unsigned char *)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    SVM_PROCESS_CR3 process_cr3 = {0};
    MONITOR_WORKER monitor = {0};
    PROCESS_STOPPER stopper = {0};
    HANDLE output = INVALID_HANDLE_VALUE, diag_device = INVALID_HANDLE_VALUE;
    HANDLE monitor_thread = NULL, stopper_thread = NULL;
    DWORD returned = 0, child_exit = 0xFFFFFFFF, read_count = 0;
    ULONG service = 0;
    SVM_DIAG diag = {0};
    char child_output[512] = {0};
    int active = 0, good = 0;
    unsigned i;
    wchar_t command[] = L"\"C:\\SvmLab\\svmc_ntopen_probe.exe\" C:\\SvmLab\\real.txt";

    if (!stub || memcmp(stub, "\x4C\x8B\xD1\xB8", 4) != 0 ||
        stub[18] != 0x0F || stub[19] != 0x05) {
        fprintf(stderr, "unsupported NtOpenFile stub\n");
        return 1;
    }
    memcpy(&service, stub + 4, sizeof(service));
    output = CreateFileW(L"C:\\SvmLab\\svmc-unmodified-open.txt",
                         GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                         &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) goto cleanup;
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = output;
    startup.hStdError = output;
    if (!CreateProcessW(L"C:\\SvmLab\\svmc_ntopen_probe.exe", command,
                        NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) goto cleanup;
    if (!SetThreadAffinityMask(process.hThread, 1)) goto cleanup;
    process_cr3.ProcessId = process.dwProcessId;
    if (!DeviceIoControl(device, SVM_PROBE_IOCTL_PROCESS_CR3,
                         &process_cr3, sizeof(process_cr3),
                         &process_cr3, sizeof(process_cr3),
                         &returned, NULL)) goto cleanup;

    monitor.Device = device;
    monitor.Input.Mode = 5;
    monitor.Input.Reserved = SVM_RUN_FLAG_LSTAR |
        SVM_RUN_FLAG_NO_PF_INTERCEPT | SVM_RUN_FLAG_ALLOW_STOP |
        (capture_only ? 0 : status_override ?
         SVM_RUN_FLAG_OVERRIDE_OPEN_STATUS :
         SVM_RUN_FLAG_NULL_OBJECT_ATTRIBUTES);
    monitor.Input.DesiredStatus = 5000;
    monitor.Input.ExpectedService = service;
    monitor.Input.Reserved2 = target_index;
    monitor.Input.OverrideStatus = 0xC0000022u; /* STATUS_ACCESS_DENIED */
    monitor.Input.TargetProcessId = process.dwProcessId;
    monitor.Input.ExpectedCr3 = process_cr3.AttachedCr3;
    diag_device = CreateFileW(L"\\\\.\\SvmcProbe", GENERIC_READ,
                              FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (diag_device == INVALID_HANDLE_VALUE) goto cleanup;
    if (!SetThreadAffinityMask(GetCurrentThread(), 2)) goto cleanup;
    monitor_thread = CreateThread(NULL, 0, RunMonitorWorker, &monitor, 0, NULL);
    if (!monitor_thread) goto cleanup;
    for (i = 0; i < 1000; ++i) {
        if (DeviceIoControl(diag_device, SVM_PROBE_IOCTL_DIAG, NULL, 0,
                            &diag, sizeof(diag), &returned, NULL) &&
            diag.Mode == 5 && (diag.State == 3 || diag.State == 4)) {
            active = 1;
            break;
        }
        Sleep(1);
    }
    if (!active) goto cleanup;
    stopper.Process = process.hProcess;
    stopper_thread = CreateThread(NULL, 0, StopAfterProcess, &stopper, 0, NULL);
    if (!stopper_thread || ResumeThread(process.hThread) == (DWORD)-1) goto cleanup;
    if (WaitForSingleObject(process.hProcess, 6000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &child_exit) ||
        WaitForSingleObject(stopper_thread, 2000) != WAIT_OBJECT_0 ||
        WaitForSingleObject(monitor_thread, 2000) != WAIT_OBJECT_0)
        goto cleanup;
    FlushFileBuffers(output);
    SetFilePointer(output, 0, NULL, FILE_BEGIN);
    ReadFile(output, child_output, sizeof(child_output) - 1, &read_count, NULL);
    good = monitor.Ok && monitor.Result.ExitCode == 0x43 &&
           monitor.Result.WindowRewrites == (ULONG)(action == 1 ? 1 : 0) &&
           monitor.Result.WindowStatusOverrides ==
               (ULONG)(status_override ? 1 : 0) &&
           (!status_override || monitor.Result.AppliedStatus == 0xC0000022u) &&
           monitor.Result.ProcessCr3Hits >= 1 &&
           monitor.Result.OpenTraceCount >= 1 &&
           monitor.Result.OpenTraceDropped == 0 &&
           monitor.Result.WindowUnexpected == 0 &&
           stopper.StopOk && stopper.SawExit &&
           child_exit == (DWORD)(capture_only ? 0 : 1) &&
           strstr(child_output, "status=0x") != NULL &&
           (capture_only ?
            strstr(child_output, "status=0x00000000") != NULL :
            status_override ?
            strstr(child_output, "status=0xC0000022") != NULL :
            strstr(child_output, "status=0x00000000") == NULL);
    printf("unmodified_open pid=%lu child_exit=%lu service=0x%lX attached_cr3=0x%llX rewrite_cr3=0x%llX cr3_hits=%lu rewrites=%lu status_overrides=%lu applied_status=0x%08lX syscalls=%lu stop_ok=%d monitor_error=%lu output=%s\n",
           process.dwProcessId, child_exit, service,
           (unsigned long long)process_cr3.AttachedCr3,
           (unsigned long long)monitor.Result.RewriteCr3,
           monitor.Result.ProcessCr3Hits, monitor.Result.WindowRewrites,
           monitor.Result.WindowStatusOverrides,
           monitor.Result.AppliedStatus,
           monitor.Result.WindowSyscalls, stopper.StopOk, monitor.Error,
           child_output);
    if (capture_only) {
        printf("ntdll_NtOpenFile_stub=");
        for (i = 0; i < 21; ++i) printf("%02X", stub[i]);
        printf(" service=0x%lX trace_count=%lu trace_dropped=%lu\n",
               service, monitor.Result.OpenTraceCount,
               monitor.Result.OpenTraceDropped);
        for (i = 0; i < monitor.Result.OpenTraceCount; ++i) {
            const SVM_OPEN_TRACE *trace = &monitor.Result.OpenTrace[i];
            printf("ntopen_entry index=%u tsc=0x%llX cr3=0x%llX return_rip=0x%llX out_handle=0x%llX access=0x%llX object_attributes=0x%llX io_status=0x%llX\n",
                   i + 1, trace->Tsc, trace->Cr3, trace->ReturnRip,
                   trace->OutHandlePointer, trace->DesiredAccess,
                   trace->ObjectAttributesPointer, trace->IoStatusPointer);
        }
    }
cleanup:
    if (!good) fprintf(stderr, "unmodified open error=%lu active=%d monitor_error=%lu\n",
                       GetLastError(), active, monitor.Error);
    if (process.hProcess && WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0)
        TerminateProcess(process.hProcess, 3);
    if (stopper_thread) { WaitForSingleObject(stopper_thread, 5000); CloseHandle(stopper_thread); }
    if (monitor_thread) { WaitForSingleObject(monitor_thread, 6000); CloseHandle(monitor_thread); }
    if (diag_device != INVALID_HANDLE_VALUE) CloseHandle(diag_device);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    return good ? 0 : 2;
}

int main(int argc, char **argv)
{
    SVM_PROBE_CAPS caps = {0};
    DWORD returned = 0;
    HANDLE device = CreateFileW(L"\\\\.\\SvmcProbe", GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "open error=%lu\n", GetLastError());
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "multi_window") == 0) {
        int result = RunMultiWindow(device);
        CloseHandle(device);
        return result;
    }
    if (argc > 1 && strcmp(argv[1], "multi_status") == 0) {
        int result = RunMultiStatus(device);
        CloseHandle(device);
        return result;
    }
    if (argc > 1 && (strcmp(argv[1], "multi_info") == 0 ||
                     strcmp(argv[1], "multi_session_smoke") == 0)) {
        SVM_MULTI_INFO info = {0};
        int smoke = strcmp(argv[1], "multi_session_smoke") == 0;
        int good;
        if (smoke && !DeviceIoControl(device, SVM_PROBE_IOCTL_MULTI_BEGIN,
                                      NULL, 0, NULL, 0, &returned, NULL)) {
            fprintf(stderr, "multi begin error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        good = DeviceIoControl(device, SVM_PROBE_IOCTL_MULTI_INFO,
                               NULL, 0, &info, sizeof(info), &returned, NULL) != 0;
        printf("multi_info cpus=%lu active=%lu armed=%lu stop=%lu lstar=0x%llX\n",
               info.CpuCount, info.ActiveCount, info.Armed,
               info.StopSignaled, info.OriginalLstar);
        if (smoke) {
            int ended = DeviceIoControl(device, SVM_PROBE_IOCTL_MULTI_END,
                                        NULL, 0, NULL, 0, &returned, NULL) != 0;
            good = good && info.CpuCount >= 2 && info.ActiveCount == 0 &&
                   info.Armed == 1 && ended;
        }
        CloseHandle(device);
        return good ? 0 : 2;
    }
    if (argc > 1 && strcmp(argv[1], "diag_cpu") == 0) {
        SVM_CPU_DIAG query = {0};
        query.CpuIndex = argc > 2 ? strtoul(argv[2], NULL, 0) : 0;
        if (!DeviceIoControl(device, SVM_PROBE_IOCTL_DIAG_CPU,
                             &query, sizeof(query), &query, sizeof(query),
                             &returned, NULL)) {
            fprintf(stderr, "diag_cpu error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        printf("diag_cpu index=%lu state=%llu mode=%llu exits=%llu lstar=0x%llX\n",
               query.CpuIndex, query.Diag.State, query.Diag.Mode,
               query.Diag.ExitCount, query.Diag.OriginalLstar);
        CloseHandle(device);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "diag") == 0) {
        SVM_DIAG diag = {0};
        if (!SetThreadAffinityMask(GetCurrentThread(), 2) ||
            !DeviceIoControl(device, SVM_PROBE_IOCTL_DIAG, NULL, 0,
                             &diag, sizeof(diag), &returned, NULL)) {
            fprintf(stderr, "diag error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        printf("state=%llu mode=%llu lstar=0x%llX exits=%llu code=0x%llX rip=0x%llX nrip=0x%llX rcx=0x%llX r11=0x%llX cpu=%llu info1=0x%llX info2=0x%llX faults=%llu fallback=%llu cpl=%llu\n",
               (unsigned long long)diag.State,
               (unsigned long long)diag.Mode,
               (unsigned long long)diag.OriginalLstar,
               (unsigned long long)diag.ExitCount,
               (unsigned long long)diag.ExitCode,
               (unsigned long long)diag.Rip,
               (unsigned long long)diag.Nrip,
               (unsigned long long)diag.GuestRcx,
               (unsigned long long)diag.GuestR11,
               (unsigned long long)diag.Cpu,
               (unsigned long long)diag.ExitInfo1,
               (unsigned long long)diag.ExitInfo2,
               (unsigned long long)diag.FaultCount,
               (unsigned long long)diag.LstarFallback,
               (unsigned long long)diag.Cpl);
        printf("first_fault_rip=0x%llX first_fault_addr=0x%llX first_fault_rsp=0x%llX guest_stack=0x%llX..0x%llX\n",
               (unsigned long long)diag.FirstFaultRip,
               (unsigned long long)diag.FirstFaultAddress,
               (unsigned long long)diag.FirstFaultRsp,
               (unsigned long long)diag.GuestStackBottom,
               (unsigned long long)diag.GuestStackTop);
        CloseHandle(device);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "inspect") == 0) {
        unsigned char *stub = (unsigned char *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                               "NtOpenFile");
        unsigned i;
        if (!stub) { CloseHandle(device); return 1; }
        printf("NtOpenFile=%p bytes=", (void *)stub);
        for (i = 0; i < 32; ++i) printf("%02X", stub[i]);
        printf("\n");
        CloseHandle(device);
        return 0;
    }
    if (argc > 1 && (strcmp(argv[1], "process_open") == 0 ||
                     strcmp(argv[1], "process_open_diag") == 0 ||
                     strcmp(argv[1], "process_open_until_exit") == 0)) {
        int result = RunProcessOpen(device,
            strcmp(argv[1], "process_open_diag") == 0,
            strcmp(argv[1], "process_open_until_exit") == 0);
        CloseHandle(device);
        return result;
    }
    if (argc > 1 && (strcmp(argv[1], "unmodified_open") == 0 ||
                     strcmp(argv[1], "ntopen_capture") == 0 ||
                     strcmp(argv[1], "ntopen_status") == 0)) {
        int capture_only = strcmp(argv[1], "ntopen_capture") == 0;
        ULONG target_index = argc > 2 ? strtoul(argv[2], NULL, 0) : 1;
        int result;
        if (!capture_only && (target_index < 1 || target_index > 32)) {
            CloseHandle(device);
            return 1;
        }
        result = RunUnmodifiedOpen(device, target_index,
                                  capture_only ? 0 :
                                  strcmp(argv[1], "ntopen_status") == 0 ? 2 : 1);
        CloseHandle(device);
        return result;
    }
    if (argc > 1 && (strcmp(argv[1], "monitored_open") == 0 ||
                     strcmp(argv[1], "monitored_open_plain") == 0 ||
                     strcmp(argv[1], "monitored_open_observe") == 0)) {
        if (argc < 3 || strcmp(argv[2], "--unsafe-scheduler-test") != 0) {
            fprintf(stderr, "disabled: separate-thread window has crashed the lab guest; pass --unsafe-scheduler-test only for crash analysis\n");
            CloseHandle(device);
            return 3;
        }
        int observe = strcmp(argv[1], "monitored_open_plain") != 0;
        int rewrite = strcmp(argv[1], "monitored_open") == 0;
        const wchar_t alias[] = L"\\??\\C:\\SvmLab\\alias.txt";
        const wchar_t real[] = L"\\??\\C:\\SvmLab\\real.txt";
        unsigned char *stub = (unsigned char *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                               "NtOpenFile");
        OPEN_WORKER worker = {0};
        DIAG_WATCH watch = {0};
        SVM_RUN_INPUT input = {0};
        SVM_RUN_RESULT run = {0};
        HANDLE thread = NULL;
        HANDLE watch_thread = NULL;
        ULONG service;
        ULONGLONG start, end;
        char bytes[128] = {0};
        DWORD read_count = 0;
        int good = 0;
        if (!stub || memcmp(stub, "\x4C\x8B\xD1\xB8", 4) != 0 ||
            stub[18] != 0x0F || stub[19] != 0x05) {
            fprintf(stderr, "unsupported NtOpenFile stub\n");
            CloseHandle(device);
            return 1;
        }
        memcpy(&service, stub + 4, sizeof(service));
        worker.NtOpenFile = (NT_OPEN_FILE_FN)stub;
        worker.AliasName.Buffer = (PWSTR)alias;
        worker.AliasName.Length = (USHORT)(wcslen(alias) * sizeof(wchar_t));
        worker.AliasName.MaximumLength = worker.AliasName.Length + sizeof(wchar_t);
        worker.RealName.Buffer = (PWSTR)real;
        worker.RealName.Length = (USHORT)(wcslen(real) * sizeof(wchar_t));
        worker.RealName.MaximumLength = worker.RealName.Length + sizeof(wchar_t);
        worker.AliasAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        worker.AliasAttributes.ObjectName = &worker.AliasName;
        worker.AliasAttributes.Attributes = OBJ_CASE_INSENSITIVE;
        worker.RealAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        worker.RealAttributes.ObjectName = &worker.RealName;
        worker.RealAttributes.Attributes = OBJ_CASE_INSENSITIVE;
        worker.Status = STATUS_UNSUCCESSFUL;
        watch.Device = device;
        watch.Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
        watch.Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!watch.Ready || !watch.Stop) {
            fprintf(stderr, "watch events failed\n");
            CloseHandle(device);
            return 1;
        }
        watch_thread = CreateThread(NULL, 0, DiagWatchWorker, &watch, 0, NULL);
        if (!watch_thread || WaitForSingleObject(watch.Ready, 2000) != WAIT_OBJECT_0 ||
            watch.Error != 0) {
            fprintf(stderr, "diagnostic watcher failed error=%lu\n", watch.Error);
            if (watch_thread) CloseHandle(watch_thread);
            CloseHandle(watch.Ready);
            CloseHandle(watch.Stop);
            CloseHandle(device);
            return 1;
        }
        worker.Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!worker.Ready) { CloseHandle(device); return 1; }
        thread = CreateThread(NULL, 0, OpenWorker, &worker, 0, NULL);
        if (!thread || WaitForSingleObject(worker.Ready, 2000) != WAIT_OBJECT_0) {
            fprintf(stderr, "worker start failed\n");
            if (thread) CloseHandle(thread);
            CloseHandle(worker.Ready);
            CloseHandle(device);
            return 1;
        }
        input.Mode = 5;
        input.Reserved = observe ? SVM_RUN_FLAG_LSTAR : 0;
        if (argc > 3 && strcmp(argv[3], "--first-pf-stop") == 0)
            input.Reserved |= SVM_RUN_FLAG_STOP_ON_FIRST_PF;
        input.DesiredStatus = argc > 4 ? (ULONG)strtoul(argv[4], NULL, 10) : 100;
        if (input.DesiredStatus < 1 || input.DesiredStatus > 1000) {
            fprintf(stderr, "window duration must be 1..1000 ms\n");
            SetEvent(watch.Stop);
            WaitForSingleObject(watch_thread, 2000);
            CloseHandle(watch_thread);
            CloseHandle(watch.Ready);
            CloseHandle(watch.Stop);
            CloseHandle(thread);
            CloseHandle(worker.Ready);
            CloseHandle(device);
            return 1;
        }
        input.OutHandlePointer = (ULONGLONG)(ULONG_PTR)&worker.File;
        input.ObjectAttributesPointer = (ULONGLONG)(ULONG_PTR)&worker.AliasAttributes;
        input.ReplacementObjectAttributesPointer = rewrite ?
            (ULONGLONG)(ULONG_PTR)&worker.RealAttributes : 0;
        input.IoStatusPointer = (ULONGLONG)(ULONG_PTR)&worker.IoStatus;
        input.ExpectedService = service;
        input.ExpectedReturnRip = (ULONGLONG)(ULONG_PTR)(stub + 20);
        if (!SetThreadAffinityMask(GetCurrentThread(), 1)) {
            fprintf(stderr, "monitor affinity failed\n");
            CloseHandle(thread);
            CloseHandle(worker.Ready);
            CloseHandle(device);
            return 1;
        }
        start = GetTickCount64();
        if (!DeviceIoControl(device, SVM_PROBE_IOCTL_RUN, &input, sizeof(input),
                             &run, sizeof(run), &returned, NULL)) {
            fprintf(stderr, "monitor run error=%lu\n", GetLastError());
            CloseHandle(thread);
            CloseHandle(worker.Ready);
            CloseHandle(device);
            return 1;
        }
        end = GetTickCount64();
        if (WaitForSingleObject(thread, 2000) == WAIT_OBJECT_0) {
            if (rewrite && worker.File && worker.Status == 0 &&
                ReadFile(worker.File, bytes, sizeof(bytes) - 1, &read_count, NULL)) {
                bytes[read_count] = 0;
                good = strcmp(bytes, "SVM-LAB-REAL\r\n") == 0 ||
                       strcmp(bytes, "SVM-LAB-REAL\n") == 0 ||
                       strcmp(bytes, "SVM-LAB-REAL") == 0;
            } else if (!rewrite) {
                good = worker.Status == STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }
        SetEvent(watch.Stop);
        WaitForSingleObject(watch_thread, 2000);
        printf("%s service=0x%lX status=0x%08lX syscalls=%lu rewrites=%lu hypercalls=%lu unexpected=%lu monitor_ms=%llu worker_start=%llu worker_end=%llu payload=%s\n",
               argv[1],
               (unsigned long)service, (unsigned long)worker.Status,
               (unsigned long)run.WindowSyscalls,
               (unsigned long)run.WindowRewrites,
               (unsigned long)run.WindowHypercalls,
               (unsigned long)run.WindowUnexpected,
               (unsigned long long)(end - start),
               (unsigned long long)(worker.StartTick - start),
               (unsigned long long)(worker.EndTick - start), bytes);
        if (worker.File) CloseHandle(worker.File);
        CloseHandle(thread);
        CloseHandle(worker.Ready);
        CloseHandle(watch_thread);
        CloseHandle(watch.Ready);
        CloseHandle(watch.Stop);
        CloseHandle(device);
        return good && (!observe || run.WindowSyscalls > 0) &&
               run.WindowRewrites == (ULONG)rewrite &&
               worker.StartTick >= start && worker.StartTick <= end &&
               run.ExitCode == 0x43 ? 0 : 2;
    }
    if (argc > 1 && strcmp(argv[1], "ntopen") == 0) {
        unsigned char *stub = (unsigned char *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                               "NtOpenFile");
        unsigned char *code = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
        unsigned char *stack = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
        const wchar_t native[] = L"\\??\\C:\\SvmLab\\alias.txt";
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attributes;
        IO_STATUS_BLOCK io_status = {0};
        HANDLE file = NULL;
        SVM_RUN_INPUT input = {0};
        SVM_RUN_RESULT run = {0};
        CONTEXT context = {0};
        ULONGLONG *guest_stack;
        ULONG service;
        char bytes[128] = {0};
        DWORD read_count = 0;
        int good;
        if (!stub || !code || !stack ||
            memcmp(stub, "\x4C\x8B\xD1\xB8", 4) != 0 ||
            stub[18] != 0x0F || stub[19] != 0x05 ||
            (*(volatile unsigned char *)(ULONG_PTR)0x7FFE0308 & 1) != 0) {
            fprintf(stderr, "unsupported NtOpenFile stub or allocation error\n");
            CloseHandle(device);
            return 1;
        }
        memcpy(&service, stub + 4, sizeof(service));
        g_NtOpenFile = stub;
        code[0] = 0xCC;
        guest_stack = (ULONGLONG *)(stack + 4096 - 0x88);
        guest_stack[0] = (ULONGLONG)(ULONG_PTR)code;
        guest_stack[5] = FILE_SHARE_READ;
        guest_stack[6] = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
        if (!VirtualLock(code, 4096) || !VirtualLock(stack, 4096) ||
            !VirtualLock(stub, 32) || !VirtualLock((void *)SvmUserOpen, 64) ||
            !VirtualLock(&g_NtOpenFile, sizeof(g_NtOpenFile))) {
            fprintf(stderr, "lock error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        name.Buffer = (PWSTR)native;
        name.Length = (USHORT)(wcslen(native) * sizeof(wchar_t));
        name.MaximumLength = name.Length + sizeof(wchar_t);
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = NULL;
        attributes.ObjectName = &name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE;
        attributes.SecurityDescriptor = NULL;
        attributes.SecurityQualityOfService = NULL;
        RtlCaptureContext(&context);
        input.Mode = 3;
        input.EntryRip = (ULONGLONG)(ULONG_PTR)SvmUserOpen;
        input.StackPointer = (ULONGLONG)(ULONG_PTR)guest_stack;
        input.Cs = context.SegCs;
        input.Ss = context.SegSs;
        input.OutHandlePointer = (ULONGLONG)(ULONG_PTR)&file;
        input.ObjectAttributesPointer = (ULONGLONG)(ULONG_PTR)&attributes;
        input.IoStatusPointer = (ULONGLONG)(ULONG_PTR)&io_status;
        input.ExpectedService = service;
        input.ExpectedReturnRip = (ULONGLONG)(ULONG_PTR)(stub + 20);
        if (!SetThreadAffinityMask(GetCurrentThread(), 1) ||
            !DeviceIoControl(device, SVM_PROBE_IOCTL_RUN, &input, sizeof(input),
                             &run, sizeof(run), &returned, NULL)) {
            fprintf(stderr, "ntopen entry error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        printf("ntopen service=0x%lX observed=0x%lX first=0x%llX second=0x%llX status=0x%llX host=0x%lX handle=0x%llX return=0x%llX trap=0x%llX expected_trap=0x%llX cpu=%lu->%lu\n",
               (unsigned long)service, (unsigned long)run.ObservedService,
               (unsigned long long)run.ExitCode,
               (unsigned long long)run.SecondExitCode,
               (unsigned long long)run.ReturnedRax,
               (unsigned long)run.HostStatus,
               (unsigned long long)run.OpenedHandle,
               (unsigned long long)run.GuestRcx,
               (unsigned long long)run.SecondGuestRip,
               (unsigned long long)(ULONG_PTR)SvmUserTrap,
               (unsigned long)run.ProcessorBefore,
               (unsigned long)run.ProcessorAfter);
        good = run.ExitCode == 0x81 && run.SecondExitCode == 0x43 &&
               run.ReturnedRax == 0 && run.HostStatus == 0 &&
               run.ObservedService == service &&
               run.GuestRcx == (ULONGLONG)(ULONG_PTR)(stub + 20) &&
               run.SecondGuestRip == (ULONGLONG)(ULONG_PTR)SvmUserTrap &&
               file != NULL &&
               (ULONGLONG)(ULONG_PTR)file == run.OpenedHandle;
        if (good && ReadFile(file, bytes, sizeof(bytes) - 1, &read_count, NULL)) {
            bytes[read_count] = 0;
            printf("read=%lu payload=%s\n", (unsigned long)read_count, bytes);
            good = strcmp(bytes, "SVM-LAB-REAL\r\n") == 0 ||
                   strcmp(bytes, "SVM-LAB-REAL\n") == 0 ||
                   strcmp(bytes, "SVM-LAB-REAL") == 0;
        } else if (good) {
            good = 0;
        }
        if (file) CloseHandle(file);
        VirtualUnlock(stub, 32);
        VirtualUnlock((void *)SvmUserOpen, 64);
        VirtualUnlock(&g_NtOpenFile, sizeof(g_NtOpenFile));
        VirtualFree(code, 0, MEM_RELEASE);
        VirtualFree(stack, 0, MEM_RELEASE);
        CloseHandle(device);
        return good ? 0 : 2;
    }
    if (argc > 1 && strcmp(argv[1], "smoke") == 0) {
        SVM_RUN_RESULT run = {0};
        SVM_RUN_INPUT input = {0};
        ULONG desired = argc > 2 ? strtoul(argv[2], NULL, 0) : 0xC0000034u;
        input.DesiredStatus = desired;
        if (!SetThreadAffinityMask(GetCurrentThread(), 1)) {
            fprintf(stderr, "affinity error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        if (!DeviceIoControl(device, SVM_PROBE_IOCTL_RUN, &input, sizeof(input),
                             &run, sizeof(run), &returned, NULL)) {
            fprintf(stderr, "run error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        printf("exit=0x%llX info1=0x%llX info2=0x%llX rip=0x%llX entry=0x%llX resume=0x%llX second=0x%llX returned=0x%llX desired=0x%lX cs_attr=0x%lX cpu=%lu->%lu\n",
               (unsigned long long)run.ExitCode,
               (unsigned long long)run.ExitInfo1,
               (unsigned long long)run.ExitInfo2,
               (unsigned long long)run.GuestRip,
               (unsigned long long)run.EntryRip,
               (unsigned long long)run.ResumeRip,
               (unsigned long long)run.SecondExitCode,
               (unsigned long long)run.ReturnedRax,
               (unsigned long)run.DesiredStatus,
               (unsigned long)run.CsAttributes,
               (unsigned long)run.ProcessorBefore,
               (unsigned long)run.ProcessorAfter);
        CloseHandle(device);
        return run.ExitCode == 0x81 && run.SecondExitCode == 0x81 &&
               run.ReturnedRax == desired &&
               run.ProcessorBefore == run.ProcessorAfter ? 0 : 2;
    }
    if (argc > 1 && (strcmp(argv[1], "delay") == 0 ||
                     strcmp(argv[1], "window") == 0 ||
                     strcmp(argv[1], "window_plain") == 0)) {
        int window = strcmp(argv[1], "window") == 0;
        int plain = strcmp(argv[1], "window_plain") == 0;
        SVM_RUN_INPUT input = {0};
        SVM_RUN_RESULT run = {0};
        LARGE_INTEGER start, end, frequency;
        input.Mode = window || plain ? 5 : 4;
        input.Reserved = window ? SVM_RUN_FLAG_LSTAR : 0;
        if (window || plain)
            input.DesiredStatus = argc > 2 ? strtoul(argv[2], NULL, 0) : 100;
        if (!SetThreadAffinityMask(GetCurrentThread(), 1)) {
            fprintf(stderr, "affinity error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        if (!DeviceIoControl(device, SVM_PROBE_IOCTL_RUN, &input, sizeof(input),
                             &run, sizeof(run), &returned, NULL)) {
            fprintf(stderr, "%s error=%lu\n", window ? "window" :
                    plain ? "window_plain" : "delay", GetLastError());
            CloseHandle(device);
            return 1;
        }
        QueryPerformanceCounter(&end);
        printf("%s requested_ms=%lu exit=0x%llX rip=0x%llX entry=0x%llX elapsed_us=%llu syscalls=%lu hypercalls=%lu unexpected=%lu cpu=%lu->%lu\n",
               window ? "window" : plain ? "window_plain" : "delay",
               (unsigned long)(window || plain ? input.DesiredStatus : 10),
               (unsigned long long)run.ExitCode,
               (unsigned long long)run.GuestRip,
               (unsigned long long)run.EntryRip,
               (unsigned long long)((end.QuadPart - start.QuadPart) * 1000000ULL /
                                    frequency.QuadPart),
               (unsigned long)run.WindowSyscalls,
               (unsigned long)run.WindowHypercalls,
               (unsigned long)run.WindowUnexpected,
               (unsigned long)run.ProcessorBefore,
               (unsigned long)run.ProcessorAfter);
        CloseHandle(device);
        return run.ExitCode == 0x43 && run.WindowUnexpected == 0 &&
               run.ProcessorBefore == run.ProcessorAfter ? 0 : 2;
    }
    if (argc > 1 && (strcmp(argv[1], "user") == 0 || strcmp(argv[1], "syscall") == 0)) {
        int syscall_mode = strcmp(argv[1], "syscall") == 0;
        CONTEXT context = {0};
        SVM_RUN_INPUT input = {0};
        SVM_RUN_RESULT run = {0};
        unsigned char *code = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
        unsigned char *stack = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
        if (!code || !stack) {
            fprintf(stderr, "allocation error=%lu\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        if (syscall_mode) {
            code[0] = 0x0F;
            code[1] = 0x05;
            code[2] = 0xCC;
        } else {
            code[0] = 0xCC;
        }
        stack[0] = 0;
        if (!VirtualLock(code, 4096) || !VirtualLock(stack, 4096)) {
            fprintf(stderr, "lock error=%lu\n", GetLastError());
            VirtualFree(code, 0, MEM_RELEASE);
            VirtualFree(stack, 0, MEM_RELEASE);
            CloseHandle(device);
            return 1;
        }
        RtlCaptureContext(&context);
        input.Mode = syscall_mode ? 2 : 1;
        input.DesiredStatus = 0xC0000034u;
        input.EntryRip = (ULONGLONG)(ULONG_PTR)code;
        input.StackPointer = (ULONGLONG)(ULONG_PTR)(stack + 4096 - 0x20);
        input.Cs = context.SegCs;
        input.Ss = context.SegSs;
        if (!SetThreadAffinityMask(GetCurrentThread(), 1) ||
            !DeviceIoControl(device, SVM_PROBE_IOCTL_RUN, &input, sizeof(input),
                             &run, sizeof(run), &returned, NULL)) {
            fprintf(stderr, "user entry error=%lu\n", GetLastError());
            VirtualFree(code, 0, MEM_RELEASE);
            VirtualFree(stack, 0, MEM_RELEASE);
            CloseHandle(device);
            return 1;
        }
        printf("%s exit=0x%llX second=0x%llX returned=0x%llX rip=0x%llX entry=0x%llX trap=0x%llX rcx=0x%llX r11=0x%llX cs_attr=0x%lX selectors=%X/%X cpu=%lu->%lu\n",
               syscall_mode ? "syscall" : "user",
               (unsigned long long)run.ExitCode,
               (unsigned long long)run.SecondExitCode,
               (unsigned long long)run.ReturnedRax,
               (unsigned long long)run.GuestRip,
               (unsigned long long)run.EntryRip,
               (unsigned long long)run.TrapRip,
               (unsigned long long)run.GuestRcx,
               (unsigned long long)run.GuestR11,
               (unsigned long)run.CsAttributes,
               (unsigned)input.Cs, (unsigned)input.Ss,
               (unsigned long)run.ProcessorBefore,
               (unsigned long)run.ProcessorAfter);
        VirtualFree(code, 0, MEM_RELEASE);
        VirtualFree(stack, 0, MEM_RELEASE);
        CloseHandle(device);
        return run.ExitCode == (syscall_mode ? 0x81u : 0x43u) &&
               (!syscall_mode || (run.SecondExitCode == 0x43 &&
                                  run.ReturnedRax == input.DesiredStatus)) &&
               (!syscall_mode || run.GuestRip == run.TrapRip) &&
               run.ProcessorBefore == run.ProcessorAfter ? 0 : 2;
    }
    if (!DeviceIoControl(device, SVM_PROBE_IOCTL_QUERY, NULL, 0,
                         &caps, sizeof(caps), &returned, NULL)) {
        fprintf(stderr, "query error=%lu\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    printf("size=%lu svm=%u leaf_ecx=0x%08lX leaf_edx=0x%08lX svm_features=0x%08lX hypervisor=%s vm_cr=0x%016llX efer=0x%016llX\n",
           (unsigned long)returned,
           (unsigned)((caps.SvmLeafEcx >> 2) & 1),
           (unsigned long)caps.SvmLeafEcx,
           (unsigned long)caps.SvmLeafEdx,
           (unsigned long)caps.SvmFeaturesEdx,
           caps.HypervisorVendor,
           (unsigned long long)caps.VmCr,
           (unsigned long long)caps.Efer);
    CloseHandle(device);
    return 0;
}
