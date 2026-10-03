CC := gcc
CFLAGS := -m64 -O0 -g -fno-stack-protector -z execstack -no-pie -Wno-implicit-function-declaration
TARGET := vuln
OUTDIR ?= .

all: plain

plain: vuln.c
	$(CC) $(CFLAGS) -o $(OUTDIR)/$(TARGET) vuln.c

packed: plain
	upx -q -o $(OUTDIR)/$(TARGET)_packed $(OUTDIR)/$(TARGET)

clean:
	rm -f $(OUTDIR)/$(TARGET) $(OUTDIR)/$(TARGET)_packed
