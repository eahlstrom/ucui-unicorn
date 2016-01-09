all: run

run: FORCE
	../../../build/ucui $(O) -M ./memory_map -r ./registers

b:
	nasm -o write_exit.mem x.asm

FORCE:
