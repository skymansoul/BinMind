# cve_2020_10713_grub 编译入口.
# Windows (mingw) 产出 vuln.exe (PE), Linux 产出 vuln (ELF).
CC ?= gcc
CFLAGS ?= -O0 -Wall

EXE = vuln$(if $(filter Windows_NT,$(OS)),.exe,)

all: $(EXE)

$(EXE): vuln.c
	$(CC) $(CFLAGS) vuln.c -o $@

O2: vuln.c
	$(CC) -O2 -Wall vuln.c -o vuln_O2$(if $(filter Windows_NT,$(OS)),.exe,)

clean:
	-rm -f vuln vuln.exe vuln_O2 vuln_O2.exe

.PHONY: all O2 clean
