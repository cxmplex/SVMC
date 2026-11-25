#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <wchar.h>

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040UL
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#endif

typedef NTSTATUS (NTAPI *NtOpenFileFn)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

int wmain(int argc, wchar_t **argv)
{
    wchar_t native[MAX_PATH + 8];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io_status = {0};
    NtOpenFileFn nt_open_file;
    HANDLE file = INVALID_HANDLE_VALUE;
    char bytes[128] = {0};
    DWORD read_count = 0;
    NTSTATUS status;

    if (argc != 2 || wcslen(argv[1]) > MAX_PATH - 8) {
        fwprintf(stderr, L"usage: ntopen_probe.exe C:\\path\\file.txt\n");
        return 2;
    }
    if (swprintf_s(native, sizeof(native) / sizeof(native[0]), L"\\??\\%ls", argv[1]) < 0) {
        fwprintf(stderr, L"path conversion failed\n");
        return 2;
    }
    name.Buffer = native;
    name.Length = (USHORT)(wcslen(native) * sizeof(wchar_t));
    name.MaximumLength = name.Length + sizeof(wchar_t);
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = NULL;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = NULL;
    attributes.SecurityQualityOfService = NULL;

    nt_open_file = (NtOpenFileFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile");
    if (!nt_open_file) {
        fwprintf(stderr, L"NtOpenFile export not found\n");
        return 2;
    }
    status = nt_open_file(&file, FILE_READ_DATA | SYNCHRONIZE, &attributes,
                          &io_status, FILE_SHARE_READ,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    wprintf(L"path=%ls\nstatus=0x%08lX\n", argv[1], (unsigned long)status);
    if (status < 0) return 1;
    if (ReadFile(file, bytes, sizeof(bytes) - 1, &read_count, NULL)) {
        bytes[read_count] = 0;
        wprintf(L"read=%lu bytes payload=%hs\n", (unsigned long)read_count, bytes);
    } else {
        wprintf(L"ReadFile error=%lu\n", (unsigned long)GetLastError());
    }
    CloseHandle(file);
    return 0;
}
