CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=alignment_slack

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET).exe
