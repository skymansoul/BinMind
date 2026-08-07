CC=gcc; CFLAGS=-O0 -g -fno-stack-protector -no-pie
TARGET=safe_equal_size.elf
all: $(TARGET)
$(TARGET): vuln.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f $(TARGET)
