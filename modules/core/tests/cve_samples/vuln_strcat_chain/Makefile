# vuln_strcat_chain — STRCAT-CHAIN
CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -fno-stack-protector
TARGET = vuln_strcat_chain.exe

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
