CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=compound_offset_overflow

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
