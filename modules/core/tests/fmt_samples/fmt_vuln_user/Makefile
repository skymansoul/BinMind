CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall
TARGET = fmt_vuln_user.exe
all: $(TARGET)
$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $(TARGET) vuln.c
clean:
	rm -f $(TARGET)
