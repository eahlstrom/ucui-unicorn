BITS 32

section .text

_start:

begin:
  jmp addr_of_str
got_addr_of_str:
  mov eax, 4  ; sys_write
  mov ebx, 1  ; stdout
  pop ecx     ; *str
  mov edx, 28 ; length
  int 0x80

  mov eax, 1      ; system call (sys_exit)
  mov ebx, 9      ; exit code
  int 0x80        ; call kernel

addr_of_str:
  call got_addr_of_str
  db 'this string is in the code', 0xa

