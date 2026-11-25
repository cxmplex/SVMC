# VMCB byte offsets used by `svm_run.c`

The VMCB is a 4 KiB page. Offsets below are measured from its base. State-save fields are shown as `0x400 + relative offset`, matching the code. These are AMD SVM architectural fields, **not** Windows structure offsets. The primary reference is AMD64 Architecture Programmer's Manual Volume 2, revision 3.44, Chapter 15, VMCB layout and SVM instructions: https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2 .

| Offset | Field | Use here |
| --- | --- | --- |
| `0x08` | Exception intercept bitmap | Intercept `#BP` (bit 3); optional diagnostic `#PF` (bit 14). |
| `0x0C`, `0x10` | Instruction intercept controls | Configure the prototype's VMMCALL and other test exits. |
| `0x40` | I/O permission-map physical base | Points to the three-page IOPM allocation. |
| `0x48` | MSR permission-map physical base | Points to the two-page MSRPM allocation. |
| `0x58` | Guest ASID | Uses ASID 1. |
| `0x5C` | TLB control | Value 3 in the current setup. |
| `0x70` | EXITCODE | `0x43` identifies intercepted `#BP`; `0x81` VMMCALL. |
| `0x78`, `0x80` | EXITINFO1/EXITINFO2 | Exception data and diagnostic fault address. |
| `0xA8` | EVENTINJ | Used only in diagnostic fault reinjection. |
| `0xC8` | NRIP | Next guest instruction after the intercepted `INT3`. |
| `0x400 + 0x00..0x30` | ES, CS, SS, DS segments | Built from the host GDT snapshot or selected user selectors. |
| `0x400 + 0x60`, `+0x80` | GDTR, IDTR | Copied from host snapshot. |
| `0x400 + 0xD0` | EFER | Enables guest SVME. |
| `0x400 + 0x148`, `+0x150`, `+0x158` | CR4, CR3, CR0 | CR3 is the per-process selector at the intercepted call. |
| `0x400 + 0x160`, `+0x168` | DR7, DR6 | Restores debug-register state. |
| `0x400 + 0x170`, `+0x178` | RFLAGS, RIP | `RIP` is set to the LSTAR shim's next instruction or the direct-return shim. |
| `0x400 + 0x1D8`, `+0x1F8` | RSP, RAX | Dedicated guest stack; RAX contains service number at entry and override status on direct return. |
| `0x400 + 0x208` | LSTAR | Redirected to `SvmSyscallForward` for the active window. |
| `0x400 + 0x240` | CR2 | Used only for diagnostic page-fault reinjection. |

The code uses `RtlCopyMemory` for VMCB scalar accesses to avoid unaligned typed loads. The mode-5 fast path uses `NO_PF_INTERCEPT`; user memory is never dereferenced from its VM-exit handler.
