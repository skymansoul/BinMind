CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = fp_test
SRC = fp_test.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
