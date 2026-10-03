# CVE-2023-0179: stack_overflow
all:
	gcc -o sample sample.c -no-pie -fno-stack-protector -z execstack
clean:
	rm -f sample
