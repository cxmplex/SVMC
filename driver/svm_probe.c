/*
 * SvmcProbe: WDM control plane for the disposable SvmLab guest.
 * IOCTLs are defined in svm_probe_ioctl.h. RUN enters SVM on the calling CPU;
 * QUERY/DIAG/STOP/PROCESS_CR3 are used by the separate lab controller.
 * See ../README.md and ../docs/VMCB_OFFSETS.md.
 */
#include <ntifs.h>
#include <intrin.h>
#include "svm_probe_ioctl.h"

extern NTSTATUS SvmRunOne(const SVM_RUN_INPUT *input, SVM_RUN_RESULT *out);
extern VOID SvmGetDiag(SVM_DIAG *out);
extern NTSTATUS SvmRequestStop(VOID);
extern NTSTATUS SvmInitializeGlobals(VOID);
extern VOID SvmCleanupGlobals(VOID);
extern NTSTATUS SvmBeginMulti(VOID);
extern NTSTATUS SvmEndMulti(VOID);
extern VOID SvmGetMultiInfo(SVM_MULTI_INFO *out);
extern NTSTATUS SvmGetDiagCpu(SVM_CPU_DIAG *out);

static UNICODE_STRING g_link = RTL_CONSTANT_STRING(L"\\DosDevices\\SvmcProbe");

static NTSTATUS FinishIrp(PIRP irp, NTSTATUS status, ULONG_PTR information)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS OpenClose(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    return FinishIrp(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS QueryProcessCr3(SVM_PROCESS_CR3 *query)
{
    PEPROCESS process = NULL;
    KAPC_STATE apc_state;
    NTSTATUS status;
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL || !query->ProcessId)
        return STATUS_INVALID_PARAMETER;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)query->ProcessId,
                                        &process);
    if (!NT_SUCCESS(status)) return status;
    /* This runs at PASSIVE_LEVEL before VMRUN, not in a VM-exit handler.
     * The returned CR3 is a lab selector; PID reuse and KVA shadow mean it
     * must be checked again against the VMCB state at each intercepted call.
     */
    KeStackAttachProcess((PRKPROCESS)process, &apc_state);
    query->AttachedCr3 = __readcr3();
    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

static NTSTATUS DeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack;
    SVM_PROBE_CAPS *caps;
    int r[4];
    UNREFERENCED_PARAMETER(device);
    stack = IoGetCurrentIrpStackLocation(irp);
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_MULTI_BEGIN)
        return FinishIrp(irp, SvmBeginMulti(), 0);
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_MULTI_END)
        return FinishIrp(irp, SvmEndMulti(), 0);
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_MULTI_INFO) {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SVM_MULTI_INFO))
            return FinishIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        SvmGetMultiInfo((SVM_MULTI_INFO *)irp->AssociatedIrp.SystemBuffer);
        return FinishIrp(irp, STATUS_SUCCESS, sizeof(SVM_MULTI_INFO));
    }
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_DIAG_CPU) {
        SVM_CPU_DIAG *query;
        NTSTATUS query_status;
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SVM_CPU_DIAG))
            return FinishIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        query = (SVM_CPU_DIAG *)irp->AssociatedIrp.SystemBuffer;
        query_status = SvmGetDiagCpu(query);
        return FinishIrp(irp, query_status,
                         NT_SUCCESS(query_status) ? sizeof(*query) : 0);
    }
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_STOP)
        return FinishIrp(irp, SvmRequestStop(), 0);
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_PROCESS_CR3) {
        SVM_PROCESS_CR3 *query;
        NTSTATUS query_status;
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(SVM_PROCESS_CR3) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SVM_PROCESS_CR3))
            return FinishIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        query = (SVM_PROCESS_CR3 *)irp->AssociatedIrp.SystemBuffer;
        query_status = QueryProcessCr3(query);
        return FinishIrp(irp, query_status,
                         NT_SUCCESS(query_status) ? sizeof(*query) : 0);
    }
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_DIAG) {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SVM_DIAG))
            return FinishIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        SvmGetDiag((SVM_DIAG *)irp->AssociatedIrp.SystemBuffer);
        return FinishIrp(irp, STATUS_SUCCESS, sizeof(SVM_DIAG));
    }
    if (stack->Parameters.DeviceIoControl.IoControlCode == SVM_PROBE_IOCTL_RUN) {
        NTSTATUS run_status;
        SVM_RUN_INPUT input;
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(input))
            return FinishIrp(irp, STATUS_INVALID_PARAMETER, 0);
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SVM_RUN_RESULT))
            return FinishIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        RtlCopyMemory(&input, irp->AssociatedIrp.SystemBuffer, sizeof(input));
        run_status = SvmRunOne(&input, (SVM_RUN_RESULT *)irp->AssociatedIrp.SystemBuffer);
        return FinishIrp(irp, run_status, NT_SUCCESS(run_status) ? sizeof(SVM_RUN_RESULT) : 0);
    }
    if (stack->Parameters.DeviceIoControl.IoControlCode != SVM_PROBE_IOCTL_QUERY)
        return FinishIrp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SVM_PROBE_CAPS))
        return FinishIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
    caps = (SVM_PROBE_CAPS *)irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(caps, sizeof(*caps));
    caps->Size = sizeof(*caps);
    __cpuid(r, 0x80000000);
    caps->MaxExtendedLeaf = (ULONG)r[0];
    if (caps->MaxExtendedLeaf >= 0x80000001) {
        __cpuid(r, 0x80000001);
        caps->SvmLeafEcx = (ULONG)r[2];
        caps->SvmLeafEdx = (ULONG)r[3];
    }
    if (caps->MaxExtendedLeaf >= 0x8000000A) {
        __cpuid(r, 0x8000000A);
        caps->SvmFeaturesEdx = (ULONG)r[3];
    }
    __cpuid(r, 0x40000000);
    caps->HypervisorMaxLeaf = (ULONG)r[0];
    RtlCopyMemory(caps->HypervisorVendor + 0, &r[1], 4);
    RtlCopyMemory(caps->HypervisorVendor + 4, &r[2], 4);
    RtlCopyMemory(caps->HypervisorVendor + 8, &r[3], 4);
    caps->HypervisorVendor[12] = '\0';
    if (caps->SvmLeafEcx & (1u << 2)) {
        caps->VmCr = __readmsr(0xC0010114);
        caps->Efer = __readmsr(0xC0000080);
    }
    return FinishIrp(irp, STATUS_SUCCESS, sizeof(*caps));
}

static VOID Unload(PDRIVER_OBJECT driver)
{
    IoDeleteSymbolicLink(&g_link);
    if (driver->DeviceObject) IoDeleteDevice(driver->DeviceObject);
    SvmCleanupGlobals();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\SvmcProbe");
    PDEVICE_OBJECT device = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry_path);
    status = SvmInitializeGlobals();
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateDevice(driver, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        SvmCleanupGlobals();
        return status;
    }
    driver->MajorFunction[IRP_MJ_CREATE] = OpenClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = OpenClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driver->DriverUnload = Unload;
    device->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&g_link, &name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        SvmCleanupGlobals();
        return status;
    }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
