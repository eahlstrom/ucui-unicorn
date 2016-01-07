CC=gcc
CFLAGS=-c -Wall -ggdb
LDFLAGS=-lcapstone -lncurses -lunicorn
SOURCES=main.c capstone.c readfile.c utils.c hexdump.c unicorn_x86.c unicorn_x64.c unicorn_arm.c syscall.c syscall_linux.c
INC=-I../include
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=../build/ucui

all: $(SOURCES) $(EXECUTABLE)
    
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(INC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(EXECUTABLE)
