# TP_uaf_callback_use — 回调UAF (True Positive)

CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = vuln

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(TARGET).exe
