#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include "svm_open_shared.h"

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040UL
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#endif
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)

typedef NTSTATUS (NTAPI *NT_OPEN_FILE_FN)(PHANDLE, ACCESS_MASK,
                                          POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                          ULONG, ULONG);

static NTSTATUS OpenOne(NT_OPEN_FILE_FN fn, POBJECT_ATTRIBUTES attributes,
                        PHANDLE handle, PIO_STATUS_BLOCK io_status)
{
    return fn(handle, FILE_READ_DATA | SYNCHRONIZE, attributes, io_status,
              FILE_SHARE_READ,
              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t alias[] = L"\\??\\C:\\SvmLab\\alias.txt";
    const wchar_t real[] = L"\\??\\C:\\SvmLab\\real.txt";
    HANDLE mapping = NULL, ready = NULL, go = NULL, done = NULL;
    SVM_OPEN_SHARED *shared = NULL;
    unsigned char *stub;
    NT_OPEN_FILE_FN fn = NULL;
    UNICODE_STRING alias_name = {0}, real_name = {0};
    OBJECT_ATTRIBUTES alias_attrs = {0}, real_attrs = {0};
    IO_STATUS_BLOCK io_status = {0}, direct_io = {0};
    HANDLE file = NULL, direct_file = NULL;
    DWORD read_count = 0;
    DWORD hold_ms = 0;
    int good = 0;

    if (argc != 6 || !SetThreadAffinityMask(GetCurrentThread(), 1)) return 2;
    hold_ms = (DWORD)wcstoul(argv[5], NULL, 10);
    if (hold_ms > 3000) return 2;
    mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, argv[1]);
    ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]);
    go = OpenEventW(SYNCHRONIZE, FALSE, argv[3]);
    done = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[4]);
    if (!mapping || !ready || !go || !done) goto cleanup;
    shared = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared));
    if (!shared) goto cleanup;
    stub = (unsigned char *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                           "NtOpenFile");
    if (!stub || memcmp(stub, "\x4C\x8B\xD1\xB8", 4) != 0 ||
        stub[18] != 0x0F || stub[19] != 0x05) {
        shared->SetupError = ERROR_NOT_SUPPORTED;
        goto signal_ready;
    }
    fn = (NT_OPEN_FILE_FN)stub;
    alias_name.Buffer = (PWSTR)alias;
    alias_name.Length = (USHORT)(wcslen(alias) * sizeof(wchar_t));
    alias_name.MaximumLength = alias_name.Length + sizeof(wchar_t);
    real_name.Buffer = (PWSTR)real;
    real_name.Length = (USHORT)(wcslen(real) * sizeof(wchar_t));
    real_name.MaximumLength = real_name.Length + sizeof(wchar_t);
    alias_attrs.Length = sizeof(alias_attrs);
    alias_attrs.ObjectName = &alias_name;
    alias_attrs.Attributes = OBJ_CASE_INSENSITIVE;
    real_attrs.Length = sizeof(real_attrs);
    real_attrs.ObjectName = &real_name;
    real_attrs.Attributes = OBJ_CASE_INSENSITIVE;
    shared->DirectBefore = OpenOne(fn, &alias_attrs, &direct_file, &direct_io);
    if (direct_file) { CloseHandle(direct_file); direct_file = NULL; }
    if (shared->DirectBefore != STATUS_OBJECT_NAME_NOT_FOUND) {
        shared->SetupError = ERROR_INVALID_DATA;
        goto signal_ready;
    }
    shared->OutHandlePointer = (ULONGLONG)(ULONG_PTR)&file;
    shared->ObjectAttributesPointer = (ULONGLONG)(ULONG_PTR)&alias_attrs;
    shared->ReplacementObjectAttributesPointer =
        (ULONGLONG)(ULONG_PTR)&real_attrs;
    shared->IoStatusPointer = (ULONGLONG)(ULONG_PTR)&io_status;
    shared->ExpectedReturnRip = (ULONGLONG)(ULONG_PTR)(stub + 20);
    memcpy(&shared->ExpectedService, stub + 4, sizeof(DWORD));
signal_ready:
    MemoryBarrier();
    InterlockedExchange(&shared->Ready, 1);
    SetEvent(ready);
    if (shared->SetupError || WaitForSingleObject(go, 5000) != WAIT_OBJECT_0)
        goto signal_done;
    Sleep(30);
    shared->StartTick = GetTickCount64();
    shared->MonitoredStatus = OpenOne(fn, &alias_attrs, &file, &io_status);
    shared->EndTick = GetTickCount64();
    if (shared->MonitoredStatus == 0 && file &&
        ReadFile(file, shared->Payload, sizeof(shared->Payload) - 1,
                 &read_count, NULL)) {
        shared->ReadCount = read_count;
        shared->Payload[read_count] = 0;
    }
    if (file) { CloseHandle(file); file = NULL; }
    shared->DirectAfter = OpenOne(fn, &alias_attrs, &direct_file, &direct_io);
    if (direct_file) { CloseHandle(direct_file); direct_file = NULL; }
    if (hold_ms) Sleep(hold_ms);
    good = shared->DirectAfter == STATUS_OBJECT_NAME_NOT_FOUND &&
           shared->MonitoredStatus == 0 &&
           (strcmp(shared->Payload, "SVM-LAB-REAL\r\n") == 0 ||
            strcmp(shared->Payload, "SVM-LAB-REAL\n") == 0 ||
            strcmp(shared->Payload, "SVM-LAB-REAL") == 0);
signal_done:
    MemoryBarrier();
    SetEvent(done);
cleanup:
    if (direct_file) CloseHandle(direct_file);
    if (file) CloseHandle(file);
    if (shared) UnmapViewOfFile(shared);
    if (mapping) CloseHandle(mapping);
    if (ready) CloseHandle(ready);
    if (go) CloseHandle(go);
    if (done) CloseHandle(done);
    return good ? 0 : 2;
}
