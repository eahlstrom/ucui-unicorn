ucui is a simple cpu emulator to help with learning assembly and shellcodes. It has partial support for linux syscall decoding.

Start with:
  $ ucui shellcode_file
  $ ucui -a ARM arm_shellcode_file
  $ ucui -m 64 x86_64_shellcode_file

Commands:
  D           - Re-disassemble code. when you have a polymorpic code this is handy.
                Test with: ucui -b 0x00400048 -R samples/x86/shellcodes/execve_rot7.sc
