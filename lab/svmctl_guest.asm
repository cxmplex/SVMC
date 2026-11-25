option casemap:none
EXTERN g_NtOpenFile:QWORD
PUBLIC SvmUserTrap
.code

SvmUserOpen PROC
    sub rsp, 38h
    mov dword ptr [rsp+20h], 1
    mov dword ptr [rsp+28h], 60h
    mov rax, qword ptr [g_NtOpenFile]
    call rax
    add rsp, 38h
SvmUserTrap LABEL BYTE
    int 3
    ret
SvmUserOpen ENDP

END
