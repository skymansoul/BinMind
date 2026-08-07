CC=gcc; CFLAGS=-O0 -g -fno-stack-protector -no-pie
TARGET=safe_heap.elf
all: $(TARGET)
$(TARGET): vuln.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f $(TARGET)
