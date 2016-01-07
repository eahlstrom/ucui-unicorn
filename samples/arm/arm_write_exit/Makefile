all: arm_write_exit ucui 

arm_write_exit: FORCE
	./build_arm.rb arm_write_exit

ucui:
	ucui -a ARM -m 32 arm_write_exit.sc

clean:
	rm -f arm_write_exit arm_write_exit.sc

FORCE:
