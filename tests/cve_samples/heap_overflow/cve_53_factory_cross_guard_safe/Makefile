CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=factory_cross_guard_safe

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
