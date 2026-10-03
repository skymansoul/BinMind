CFLAGS=-O0 -fno-stack-protector -no-pie
all: vuln.exe
vuln.exe: vuln.c
	gcc $(CFLAGS) -o $@ $<
clean:
	rm -f vuln.exe
