; vim: ft=nasm :

BITS 64

global _start
section .text
      
_start:

_write:
  mov rax, 1        ; SYS_WRITE
  mov rdi, 1        ; 1 - STDOUT
  jmp _str
_got_str:
  pop rsi
  mov rdx, 31       ; length
  syscall           ; make the call

_exit:
  xor rax, rax
  mov al,60         ; SYS_EXIT
  xor rdi,rdi       ; exit code 0
  syscall           ; make the call

_str:
  call _got_str
  db 'This string are in the code...', 0x0a
