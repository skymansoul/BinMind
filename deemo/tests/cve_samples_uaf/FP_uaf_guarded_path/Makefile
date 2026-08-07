# FP_uaf_guarded_path — 路径条件保护 (False Positive)

CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(TARGET).exe
