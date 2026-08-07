# TP_uaf_alias_use — 别名UAF (True Positive)

CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(TARGET).exe
