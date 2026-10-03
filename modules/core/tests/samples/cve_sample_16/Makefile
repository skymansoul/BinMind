CC=gcc; CFLAGS=-O0 -g -fno-stack-protector -no-pie
TARGET=vuln_strcat_chain.elf
all: $(TARGET)
$(TARGET): vuln.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f $(TARGET)
