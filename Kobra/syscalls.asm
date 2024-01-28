.code

extern syscallID : DWORD
extern syscallAddr : QWORD

public indirect_sys

indirect_sys PROC
    mov r10, rcx
    mov eax, syscallID
    jmp QWORD PTR [syscallAddr]
indirect_sys ENDP

END