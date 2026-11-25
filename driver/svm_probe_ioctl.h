/* Shared driver/controller ABI. Keep both sides in sync when this changes.
 * IOCTL_RUN uses METHOD_BUFFERED: its input and result share SystemBuffer.
 * The VMCB offset map is in ../docs/VMCB_OFFSETS.md.
 */
#pragma once

#define SVM_PROBE_IOCTL_QUERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_RUN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_DIAG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_STOP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_PROCESS_CR3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_MULTI_BEGIN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_MULTI_END CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_MULTI_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_PROBE_IOCTL_DIAG_CPU CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS)
#define SVM_RUN_FLAG_LSTAR 1u
#define SVM_RUN_FLAG_STOP_ON_FIRST_PF 2u
#define SVM_RUN_FLAG_NO_PF_INTERCEPT 4u
#define SVM_RUN_FLAG_ALLOW_STOP 8u
#define SVM_RUN_FLAG_NULL_OBJECT_ATTRIBUTES 16u
#define SVM_RUN_FLAG_OVERRIDE_OPEN_STATUS 32u /* one matching call returns via SYSRETQ */
#define SVM_RUN_FLAG_MULTI 64u /* RUN participates in a pre-armed all-CPU session */
#define SVM_RUN_FLAG_MATCH_ACCESS 128u /* select by NtOpenFile DesiredAccess */

typedef struct _SVM_DIAG {
    ULONGLONG State;
    ULONGLONG Mode;
    ULONGLONG OriginalLstar;
    ULONGLONG ExitCount;
    ULONGLONG ExitCode;
    ULONGLONG Rip;
    ULONGLONG Nrip;
    ULONGLONG GuestRcx;
    ULONGLONG GuestR11;
    ULONGLONG Cpu;
    ULONGLONG ExitInfo1;
    ULONGLONG ExitInfo2;
    ULONGLONG FaultCount;
    ULONGLONG LstarFallback;
    ULONGLONG Cpl;
    ULONGLONG FirstFaultRip;
    ULONGLONG FirstFaultAddress;
    ULONGLONG FirstFaultError;
    ULONGLONG FirstFaultRsp;
    ULONGLONG FirstFaultCr3;
    ULONGLONG GuestStackBottom;
    ULONGLONG GuestStackTop;
} SVM_DIAG;

typedef struct _SVM_CPU_DIAG {
    ULONG CpuIndex; /* system-wide logical processor index */
    ULONG Reserved;
    SVM_DIAG Diag;
} SVM_CPU_DIAG;

typedef struct _SVM_MULTI_INFO {
    ULONG CpuCount;
    ULONG ActiveCount;
    ULONG Armed;
    ULONG StopSignaled;
    ULONGLONG OriginalLstar;
} SVM_MULTI_INFO;

typedef struct _SVM_RUN_INPUT {
    ULONG Mode;
    ULONG DesiredStatus;
    ULONGLONG EntryRip;
    ULONGLONG StackPointer;
    USHORT Cs;
    USHORT Ss;
    ULONG Reserved;
    ULONGLONG OutHandlePointer;
    ULONGLONG ObjectAttributesPointer;
    ULONGLONG IoStatusPointer;
    ULONG ExpectedService;
    ULONG Reserved2; /* selected matching NtOpenFile call index, 1-based */
    ULONGLONG ExpectedReturnRip;
    ULONGLONG ReplacementObjectAttributesPointer;
    ULONGLONG TargetProcessId;
    ULONGLONG ExpectedCr3;
    ULONG OverrideStatus; /* NTSTATUS placed in guest RAX for direct return */
    ULONG Reserved3;
    ULONG ExpectedAccess;
    ULONG Reserved4;
} SVM_RUN_INPUT;

typedef struct _SVM_PROCESS_CR3 {
    ULONGLONG ProcessId;
    ULONGLONG AttachedCr3;
} SVM_PROCESS_CR3;

typedef struct _SVM_GPRS {
    ULONGLONG Rcx;
    ULONGLONG Rdx;
    ULONGLONG R8;
    ULONGLONG R9;
    ULONGLONG R10;
    ULONGLONG R11;
    ULONGLONG Rbx;
    ULONGLONG Rbp;
    ULONGLONG Rsi;
    ULONGLONG Rdi;
    ULONGLONG R12;
    ULONGLONG R13;
    ULONGLONG R14;
    ULONGLONG R15;
} SVM_GPRS;

#define SVM_OPEN_TRACE_MAX 16u
typedef struct _SVM_OPEN_TRACE {
    ULONGLONG Tsc;
    ULONGLONG Cr3;
    ULONGLONG ReturnRip;
    ULONGLONG OutHandlePointer;
    ULONGLONG DesiredAccess;
    ULONGLONG ObjectAttributesPointer;
    ULONGLONG IoStatusPointer;
} SVM_OPEN_TRACE;

typedef struct _SVM_PROBE_CAPS {
    ULONG Size;
    ULONG MaxExtendedLeaf;
    ULONG SvmLeafEcx;
    ULONG SvmLeafEdx;
    ULONG SvmFeaturesEdx;
    ULONG HypervisorMaxLeaf;
    CHAR HypervisorVendor[13];
    ULONGLONG VmCr;
    ULONGLONG Efer;
} SVM_PROBE_CAPS;

typedef struct _SVM_RUN_RESULT {
    ULONGLONG ExitCode;
    ULONGLONG ExitInfo1;
    ULONGLONG ExitInfo2;
    ULONGLONG GuestRip;
    ULONGLONG EntryRip;
    ULONGLONG ResumeRip;
    ULONGLONG SecondExitCode;
    ULONGLONG SecondGuestRip;
    ULONGLONG ReturnedRax;
    ULONGLONG TrapRip;
    ULONGLONG GuestRcx;
    ULONGLONG GuestR11;
    ULONGLONG OpenedHandle;
    ULONG ObservedService;
    ULONG HostStatus;
    ULONG WindowSyscalls;
    ULONG WindowUnexpected;
    ULONG WindowRewrites;
    ULONG WindowHypercalls;
    ULONG WindowStoppedBySignal;
    ULONGLONG RewriteCr3;
    ULONG ProcessCr3Hits;
    ULONG PathProbeHits;
    ULONG PathMatches;
    ULONG PathProbeErrors;
    ULONG CsAttributes;
    ULONG DesiredStatus;
    ULONG ProcessorBefore;
    ULONG ProcessorAfter;
    ULONG CpuIndex; /* system-wide logical processor index */
    ULONG OpenTraceCount;
    ULONG OpenTraceDropped;
    ULONG WindowStatusOverrides;
    ULONG AppliedStatus;
    ULONG OverrideMatchIndex;
    SVM_OPEN_TRACE OpenTrace[SVM_OPEN_TRACE_MAX];
} SVM_RUN_RESULT;
