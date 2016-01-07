
all: ucui

ucui:
	cd src; make

capstone: FORCE
	cd capstone; ./make.sh

capstone_install:
	cd capstone; make install

unicorn: FORCE
	cd unicorn; ./make.sh

unicorn_install:
	cd unicorn; make install

install:
	cp build/ucui /usr/local/bin

uninstall:
	rm /usr/local/bin/ucui

FORCE:
