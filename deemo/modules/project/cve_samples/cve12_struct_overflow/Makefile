CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = cve12_struct_overflow

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
