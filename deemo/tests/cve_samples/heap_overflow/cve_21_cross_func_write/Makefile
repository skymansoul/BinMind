CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=cross_func_write

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
