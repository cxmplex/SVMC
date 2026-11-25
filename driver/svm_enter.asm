; AMD SVM entry/exit shims for SvmLab. The C side owns VMCB construction.
; SvmEnterLoaded switches to a dedicated nonpaged host stack, saves host
; nonvolatile/FPU state, loads guest registers, and executes VMRUN. No Windows
; services are called while the host is handling a VM exit with GIF cleared.
; See ../README.md for the register and return paths.
option casemap:none
.code

SvmSnapshot PROC
    mov ax, cs
    mov word ptr [rcx], ax
    mov ax, ss
    mov word ptr [rcx+2], ax
    mov ax, ds
    mov word ptr [rcx+4], ax
    mov ax, es
    mov word ptr [rcx+6], ax
    sgdt fword ptr [rcx+8]
    sidt fword ptr [rcx+18]
    mov rax, dr6
    mov qword ptr [rcx+28], rax
    mov rax, dr7
    mov qword ptr [rcx+36], rax
    mov qword ptr [rcx+44], rsp
    pushfq
    pop rax
    mov qword ptr [rcx+52], rax
    ret
SvmSnapshot ENDP

SvmEnter PROC
    push r11
    mov r11, dr7
    push r11
    mov rax, rcx
    clgi
    vmrun rax
    pop r11
    mov dr7, r11
    stgi
    pop r11
    ret
SvmEnter ENDP

SvmSaveHost PROC
    mov rax, rcx
    vmsave rax
    ret
SvmSaveHost ENDP

SvmEnterLoaded PROC
    mov r10, qword ptr [rsp+28h]
    mov rax, rsp
    mov rsp, r9
    and rsp, -16
    sub rsp, 80h
    mov qword ptr [rsp+00h], rax
    mov qword ptr [rsp+08h], rbx
    mov qword ptr [rsp+10h], rbp
    mov qword ptr [rsp+18h], rsi
    mov qword ptr [rsp+20h], rdi
    mov qword ptr [rsp+28h], r12
    mov qword ptr [rsp+30h], r13
    mov qword ptr [rsp+38h], r14
    mov qword ptr [rsp+40h], r15
    mov qword ptr [rsp+48h], r11
    mov qword ptr [rsp+50h], rcx
    mov qword ptr [rsp+58h], rdx
    mov qword ptr [rsp+60h], r8
    mov qword ptr [rsp+70h], r10
    mov r11, qword ptr [rax+30h]
    mov qword ptr [rsp+78h], r11
    mov r11, dr7
    mov qword ptr [rsp+68h], r11
    mov rax, qword ptr [rsp+70h]
    test rax, rax
    jz fx_restore_done
    fxsave64 [rax]
    cmp dword ptr [rax+400h], 0
    jne fx_ready
    mov rsi, rax
    lea rdi, [rax+200h]
    mov ecx, 64
    rep movsq
    mov dword ptr [rax+400h], 1
fx_ready:
    fxrstor64 [rax+200h]
fx_restore_done:
    mov rax, qword ptr [rsp+50h]
    vmload rax
    mov rax, qword ptr [rsp+60h]
    mov rcx, qword ptr [rax+00h]
    mov rdx, qword ptr [rax+08h]
    mov r8, qword ptr [rax+10h]
    mov r9, qword ptr [rax+18h]
    mov r10, qword ptr [rax+20h]
    mov r11, qword ptr [rax+28h]
    mov rbx, qword ptr [rax+30h]
    mov rbp, qword ptr [rax+38h]
    mov rsi, qword ptr [rax+40h]
    mov rdi, qword ptr [rax+48h]
    mov r12, qword ptr [rax+50h]
    mov r13, qword ptr [rax+58h]
    mov r14, qword ptr [rax+60h]
    mov r15, qword ptr [rax+68h]
    mov rax, qword ptr [rsp+50h]
    clgi
    vmrun rax
    mov rax, qword ptr [rsp+70h]
    test rax, rax
    jz fx_save_done
    fxsave64 [rax+200h]
    fxrstor64 [rax]
fx_save_done:
    mov rax, qword ptr [rsp+60h]
    mov qword ptr [rax+00h], rcx
    mov qword ptr [rax+08h], rdx
    mov qword ptr [rax+10h], r8
    mov qword ptr [rax+18h], r9
    mov qword ptr [rax+20h], r10
    mov qword ptr [rax+28h], r11
    mov qword ptr [rax+30h], rbx
    mov qword ptr [rax+38h], rbp
    mov qword ptr [rax+40h], rsi
    mov qword ptr [rax+48h], rdi
    mov qword ptr [rax+50h], r12
    mov qword ptr [rax+58h], r13
    mov qword ptr [rax+60h], r14
    mov qword ptr [rax+68h], r15
    mov rax, qword ptr [rsp+50h]
    vmsave rax
    mov rax, qword ptr [rsp+58h]
    vmload rax
    mov r11, qword ptr [rsp+68h]
    mov dr7, r11
    mov rbx, qword ptr [rsp+08h]
    mov rbp, qword ptr [rsp+10h]
    mov rsi, qword ptr [rsp+18h]
    mov rdi, qword ptr [rsp+20h]
    mov r12, qword ptr [rsp+28h]
    mov r13, qword ptr [rsp+30h]
    mov r14, qword ptr [rsp+38h]
    mov r15, qword ptr [rsp+40h]
    mov r11, qword ptr [rsp+48h]
    mov r10, qword ptr [rsp+78h]
    mov rsp, qword ptr [rsp+00h]
    test r10, r10
    jnz svm_return_no_stgi
    stgi
svm_return_no_stgi:
    ret
SvmEnterLoaded ENDP

SvmEnableGlobalInterrupts PROC
    stgi
    ret
SvmEnableGlobalInterrupts ENDP

SvmForwardHypercall PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    fxsave64 [rsi]
    fxrstor64 [rsi+200h]
    mov rcx, qword ptr [rbx+00h]
    mov rdx, qword ptr [rbx+08h]
    mov r8, qword ptr [rbx+10h]
    call rdi
    mov qword ptr [rbx+00h], rcx
    mov qword ptr [rbx+08h], rdx
    mov qword ptr [rbx+10h], r8
    fxsave64 [rsi+200h]
    fxrstor64 [rsi]
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
SvmForwardHypercall ENDP

SvmGuestStub PROC
    vmmcall
    vmmcall
    ud2
SvmGuestStub ENDP

SvmSyscallStub PROC
    vmmcall
    db 48h, 0Fh, 07h
    ud2
SvmSyscallStub ENDP

EXTERN g_OriginalLstar:QWORD
EXTERN g_SvmStopFlag:DWORD
PUBLIC SvmGuestKernelWindowTrap
PUBLIC SvmSyscallForwardTrap
PUBLIC SvmSyscallReturn
SvmGuestKernelDelay PROC
    rdtsc
    shl rdx, 20h
    or rax, rdx
    add rbx, rax
delay_spin:
    rdtsc
    shl rdx, 20h
    or rax, rdx
    cmp rax, rbx
    jb delay_spin
    int 3
    ud2
SvmGuestKernelDelay ENDP

SvmGuestKernelWindow PROC
    rdtsc
    shl rdx, 20h
    or rax, rdx
    add rbx, rax
window_spin:
    cmp dword ptr [g_SvmStopFlag], 0
    jne window_done
    rdtsc
    shl rdx, 20h
    or rax, rdx
    cmp rax, rbx
    jb window_spin
window_done:
SvmGuestKernelWindowTrap LABEL BYTE
    int 3
    ud2
SvmGuestKernelWindow ENDP

SvmSyscallForward PROC
SvmSyscallForwardTrap LABEL BYTE
    int 3                   ; intercepted #BP: EXITCODE 0x43, NRIP at VMCB +0xC8
    jmp qword ptr [g_OriginalLstar]
SvmSyscallForward ENDP

; At the LSTAR VM exit, SYSCALL has already saved the user return RIP in RCX
; and RFLAGS in R11. This path returns directly to user mode without running
; the original Windows system-call handler. RAX is set in the guest VMCB.
SvmSyscallReturn PROC
    db 48h, 0Fh, 07h       ; SYSRETQ
    ud2
SvmSyscallReturn ENDP

END
