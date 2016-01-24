
all: ucui

ucui:
	cd src; make

capstone: submodules FORCE
	cd capstone; ./make.sh

capstone_install:
	cd capstone; make install

unicorn: submodules FORCE
	cd unicorn; ./make.sh

unicorn_install:
	cd unicorn; make install

install:
	cp build/ucui /usr/local/bin

clean: FORCE
	cd src; make clean

uninstall:
	rm -f /usr/local/bin/ucui

submodules:
	git submodule init
	git submodule update

FORCE:
