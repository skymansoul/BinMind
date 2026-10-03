CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET=same_offset_accumulate
all: $(TARGET).exe
$(TARGET).exe: $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET).exe
