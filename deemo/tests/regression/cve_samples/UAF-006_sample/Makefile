CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: $(TARGET)
$(TARGET): UAF-006_sample.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f $(TARGET) *.o
