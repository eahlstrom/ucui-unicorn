all: write_exit ucui 

write_exit: FORCE
	nasm write_exit.asm

elf: FORCE
	nasm -f elf32 -o write_exit.o write_exit.asm
	ld -o write_exit.elf write_exit.o

ucui:
	../../../build/ucui $(O) -a x86 -m 32 write_exit

clean:
	rm -f write_exit *.o

FORCE:
