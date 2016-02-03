BITS 32

section .text

_start:

begin:
  mov eax, -3
  mov edi, esp
  mov ecx, 10
  rep stosb
  nop

  jmp addr_of_str
got_addr_of_str:
  pop esi     ; *str
  mov edi, 0x00400060
  mov ecx, 27
  rep movsb 


  mov eax, 1      ; system call (sys_exit)
  mov ebx, 9      ; exit code
  int 0x80        ; call kernel

addr_of_str:
  call got_addr_of_str
  db 'this string is in the code', 0xa

