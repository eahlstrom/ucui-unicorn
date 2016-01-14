BINNAME=ucui
CC=gcc
CFLAGS=-c -Wall -ggdb -DBINNAME='"$(BINNAME)"'
LDFLAGS=-lcapstone -lncurses -lunicorn -lreadline
SOURCES=main.c capstone.c readfile.c utils.c hexdump.c unicorn_x86.c unicorn_x64.c unicorn_arm.c \
				syscall.c syscall_linux.c init_from_file.c memory_map.c command_parser.c commands.c readline.c
INC=-I../include
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=../build/$(BINNAME)

all: $(SOURCES) $(EXECUTABLE)
    
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(INC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(EXECUTABLE)
