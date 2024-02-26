.code

extern syscallID : DWORD
extern syscallAddr : QWORD

public indirect_sys

indirect_sys PROC
    mov r10, rcx
    mov eax, syscallID
    jmp QWORD PTR [syscallAddr]
    syscall
    ret
indirect_sys ENDP

END