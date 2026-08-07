CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=complex_stride_overflow

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
