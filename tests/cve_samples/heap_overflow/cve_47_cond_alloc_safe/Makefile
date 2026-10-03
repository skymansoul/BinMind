CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=cond_alloc_safe

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
