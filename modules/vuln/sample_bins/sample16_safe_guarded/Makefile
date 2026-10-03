CC = gcc
CFLAGS = -Wall -O0 -g -fno-stack-protector
TARGET = safe_guarded
SRC = safe_guarded.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
