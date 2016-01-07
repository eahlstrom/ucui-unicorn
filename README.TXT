ucui is a simple cpu emulator to help with learning assembly and shellcodes. It has partial support for linux syscall decoding.

Start with:
  $ ucui shellcode_file
  $ ucui -a ARM arm_shellcode_file
  $ ucui -m 64 x86_64_shellcode_file

Navigation:
  Up/Down     - Scroll assembly window.
  <F8>/Enter  - Step
  <F9>        - Run to breakpoint (set with -b) or to the end.
  D           - Re-disassemble code. when you have a polymorpic code this is handy.
