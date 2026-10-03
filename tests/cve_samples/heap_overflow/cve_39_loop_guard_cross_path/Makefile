CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=loop_guard_cross_path

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe

