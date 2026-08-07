CC=gcc; CFLAGS=-O0 -g -fno-stack-protector -no-pie
TARGET=fp_alloc_constraint.elf
all: $(TARGET)
$(TARGET): vuln.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f $(TARGET)
