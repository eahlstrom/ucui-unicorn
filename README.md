# ucui-unicorn

ucui is a simple cpu emulator to help with learning assembly and shellcodes.
It has partial support for linux syscall decoding.

![Sample screenshot](https://github.com/eahlstrom/ucui-unicorn/images/ucui_screenshot1.png)

Start with:
  $ ucui shellcode_file
  $ ucui -a ARM arm_shellcode_file
  $ ucui -m 64 x86_64_shellcode_file

Or checkout the examples within samples/

Commands:
  ?   - Show help in the ui.
  D   - Re-disassemble code. when you have a polymorpic code this is handy.
        Test with: ucui -b 0x00400048 -R samples/x86/shellcodes/execve_rot7.sc
