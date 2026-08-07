CC=gcc
CFLAGS=-g -O0 -fno-stack-protector -z execstack
TARGET=vuln
SRC=vuln.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) vuln.exe
