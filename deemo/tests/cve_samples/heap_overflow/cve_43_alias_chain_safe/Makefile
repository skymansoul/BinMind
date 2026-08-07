CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=alias_chain_safe

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
