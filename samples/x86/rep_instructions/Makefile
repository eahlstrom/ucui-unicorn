N = rep_ins

all: $(N) ucui 

$(N): $(N).asm
	nasm $(N).asm

elf: FORCE
	nasm -f elf32 -o $(N).o $(N).asm
	ld -o $(N).elf $(N).o

ucui:
	../../../build/ucui $(O) -a x86 -m 32 $(N)

clean:
	rm -f $(N) *.o

dis: FORCE
	cat rep_ins | ndisasm -b 32 -

FORCE:
