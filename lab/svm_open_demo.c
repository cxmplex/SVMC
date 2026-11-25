#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "svm_probe_ioctl.h"

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040UL
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#endif
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)

void *g_NtOpenFile;
extern void SvmUserOpen(void);
extern void SvmUserTrap(void);

typedef NTSTATUS (NTAPI *NT_OPEN_FILE_FN)(PHANDLE, ACCESS_MASK,
                                          POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                          ULONG, ULONG);

static NTSTATUS DirectOpen(NT_OPEN_FILE_FN nt_open_file,
                           POBJECT_ATTRIBUTES attributes)
{
    HANDLE file = NULL;
    IO_STATUS_BLOCK io_status = {0};
    NTSTATUS status = nt_open_file(&file, FILE_READ_DATA | SYNCHRONIZE,
                                   attributes, &io_status, FILE_SHARE_READ,
                                   FILE_NON_DIRECTORY_FILE |
                                   FILE_SYNCHRONOUS_IO_NONALERT);
    if (status >= 0 && file) CloseHandle(file);
    return status;
}

int main(void)
{
    const wchar_t native[] = L"\\??\\C:\\SvmLab\\alias.txt";
    unsigned char *stub = (unsigned char *)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    unsigned char *code = NULL;
    unsigned char *stack = NULL;
    HANDLE device = INVALID_HANDLE_VALUE;
    HANDLE file = NULL;
    UNICODE_STRING name = {0};
    OBJECT_ATTRIBUTES attributes = {0};
    IO_STATUS_BLOCK io_status = {0};
    CONTEXT context = {0};
    SVM_RUN_INPUT input = {0};
    SVM_RUN_RESULT run = {0};
    ULONGLONG *guest_stack;
    NTSTATUS before, after;
    ULONG service;
    DWORD returned = 0, read_count = 0;
    char bytes[128] = {0};
    DWORD old_protect;
    int good = 0;

    if (!stub || memcmp(stub, "\x4C\x8B\xD1\xB8", 4) != 0 ||
        stub[18] != 0x0F || stub[19] != 0x05 ||
        (*(volatile unsigned char *)(ULONG_PTR)0x7FFE0308 & 1) != 0) {
        fprintf(stderr, "unsupported NtOpenFile stub\n");
        return 1;
    }
    memcpy(&service, stub + 4, sizeof(service));
    g_NtOpenFile = stub;
    name.Buffer = (PWSTR)native;
    name.Length = (USHORT)(wcslen(native) * sizeof(wchar_t));
    name.MaximumLength = name.Length + sizeof(wchar_t);
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    before = DirectOpen((NT_OPEN_FILE_FN)stub, &attributes);
    if (before != STATUS_OBJECT_NAME_NOT_FOUND) {
        fprintf(stderr, "baseline status=0x%08lX\n", (unsigned long)before);
        return 2;
    }

    device = CreateFileW(L"\\\\.\\SvmcProbe", GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, 0, NULL);
    code = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    stack = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (device == INVALID_HANDLE_VALUE || !code || !stack) {
        fprintf(stderr, "setup error=%lu\n", GetLastError());
        goto done;
    }
    code[0] = 0xCC;
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &old_protect)) {
        fprintf(stderr, "protect error=%lu\n", GetLastError());
        goto done;
    }
    guest_stack = (ULONGLONG *)(stack + 4096 - 0x88);
    guest_stack[0] = (ULONGLONG)(ULONG_PTR)code;
    guest_stack[5] = FILE_SHARE_READ;
    guest_stack[6] = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
    if (!VirtualLock(code, 4096) || !VirtualLock(stack, 4096) ||
        !VirtualLock(stub, 32) || !VirtualLock((void *)SvmUserOpen, 64) ||
        !VirtualLock(&g_NtOpenFile, sizeof(g_NtOpenFile))) {
        fprintf(stderr, "lock error=%lu\n", GetLastError());
        goto done;
    }
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
        fprintf(stderr, "monitor error=%lu\n", GetLastError());
        goto done;
    }
    if (run.ExitCode != 0x81 || run.SecondExitCode != 0x43 ||
        run.ReturnedRax != 0 || run.HostStatus != 0 ||
        run.ObservedService != service ||
        run.GuestRcx != (ULONGLONG)(ULONG_PTR)(stub + 20) ||
        run.SecondGuestRip != (ULONGLONG)(ULONG_PTR)SvmUserTrap ||
        run.ProcessorBefore != run.ProcessorAfter ||
        !file || (ULONGLONG)(ULONG_PTR)file != run.OpenedHandle ||
        !ReadFile(file, bytes, sizeof(bytes) - 1, &read_count, NULL)) {
        fprintf(stderr, "monitor validation failed\n");
        goto done;
    }
    bytes[read_count] = 0;
    after = DirectOpen((NT_OPEN_FILE_FN)stub, &attributes);
    good = (strcmp(bytes, "SVM-LAB-REAL\r\n") == 0 ||
            strcmp(bytes, "SVM-LAB-REAL\n") == 0 ||
            strcmp(bytes, "SVM-LAB-REAL") == 0) &&
           after == STATUS_OBJECT_NAME_NOT_FOUND;
    printf("app=svm_open_demo.exe service=0x%lX direct_before=0x%08lX monitored=0x%llX direct_after=0x%08lX payload=%s\n",
           (unsigned long)service, (unsigned long)before,
           (unsigned long long)run.ReturnedRax,
           (unsigned long)after, bytes);
done:
    if (file) CloseHandle(file);
    if (device != INVALID_HANDLE_VALUE) CloseHandle(device);
    if (code) VirtualFree(code, 0, MEM_RELEASE);
    if (stack) VirtualFree(stack, 0, MEM_RELEASE);
    return good ? 0 : 2;
}
