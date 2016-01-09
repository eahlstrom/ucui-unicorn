BITS 32

section .text

_start:
  int 0x80
  sub ecx, 0x25
  jmp ecx
