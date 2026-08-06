CC ?= gcc
CFLAGS ?= -g -O0
TARGET = vuln

all: $(TARGET).elf

$(TARGET).elf: vuln.c
	$(CC) $(CFLAGS) -o $@ $<

stripped: $(TARGET).elf
	strip -o $(TARGET)_stripped.elf $(TARGET).elf

clean:
	rm -f *.elf
