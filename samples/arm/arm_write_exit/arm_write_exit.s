.text
.globl _start

_start:
  @ generate a string
  mov r2, #0
  mov r0, #'a'
  loop:
    strb r0, [sp, r2]
    add r0, #1
    add r2, #1
    cmp r2, #10
    bne loop
  mov r0, #'\n'
  strb r0, [sp, r2]
  add r2, #1

  @ write
  mov r7, #4  @ write syscall
  mov r0, #1  @ stdout
  mov r1, sp  @ *string
              @ r2 - length
  svc #0
  

  # exit(2)
  mov r7, #1  @ exit syscall
  mov r0, #2  @ exit argument
  svc #0
