# SVMC: multicore AMD SVM syscall interception

SVMC extends the [SV](https://github.com/cxmplex/SV) from one logical processor to simultaneous monitors on the active logical processors of a disposable Windows Hyper-V guest. Each monitor has its own VMCB, host state, stacks, register state, and diagnostic slot. A shared session coordinates start, stop, and the original `IA32_LSTAR` value.

**A CPU in the controller output means a logical processor.** It may be a hardware thread of a physical core, or a virtual processor assigned to this VM. The tested `SvmLab` guest exposes four virtual logical processors, indexed 0 through 3.

The `multi_status` experiment starts four unchanged `svmc_ntopen_probe.exe` processes, one pinned to each guest vCPU, and four SVM monitor workers. It matches the guest's `NtOpenFile` service number, each target process's CR3, and `DesiredAccess = FILE_READ_DATA | SYNCHRONIZE`. For one matching call per process, the monitor sets guest `RAX` to `0xC0000022` (`STATUS_ACCESS_DENIED`) and returns through the existing `SYSRETQ` shim.

## Layout

| Path | Purpose |
| --- | --- |
| `driver/svm_probe.c` | `SvmcProbe` device, IOCTL dispatch, and pre-run process CR3 query. |
| `driver/svm_run.c` | Per-CPU state, session protocol, VMCB setup, and VM-exit policy. |
| `driver/svm_enter.asm` | VMRUN entry/exit, register and FPU handling, LSTAR trap, and SYSRETQ return. |
| `driver/svm_probe_ioctl.h` | Shared controller/driver ABI and bounded capture records. |
| `lab/svmctl.c` | Single-CPU controls, multicore orchestration, and result checks. |
| `lab/ntopen_probe.c` | Unchanged file-open application used for the status test. |
| `docs/VMCB_OFFSETS.md`, `docs/REFERENCES.md` | AMD VMCB map and primary references. |

## Build and run in the disposable VM

`build.cmd` uses Visual Studio x64 tools and Windows SDK/WDK 10.0.28000.0. It writes unsigned artifacts to ignored `out/`. Sign `out/svm_probe.sys` with a test certificate trusted by the guest. The repository contains no signing key. The guest must have nested AMD SVM and a driver test-signing environment configured.

Copy the signed driver and programs from `out/` to `C:\SvmLab` in the test guest. Install the driver as the demand-start `SvmcProbe` service. Keep VM credentials and deployment automation outside this source repository.

From an elevated shell **inside that guest**, after deployment:

```text
C:\SvmLab\svmcctl.exe multi_info
C:\SvmLab\svmcctl.exe multi_window
C:\SvmLab\svmcctl.exe multi_status
```
