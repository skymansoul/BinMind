CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=cross_path_guard_safe

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe

