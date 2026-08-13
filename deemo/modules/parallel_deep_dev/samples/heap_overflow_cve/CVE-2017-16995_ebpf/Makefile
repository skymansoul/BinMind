CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
TARGET = vuln.exe

all: $(TARGET)

$(TARGET): vuln.c
	$ $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
