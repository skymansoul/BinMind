CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = cve18_input_controlled

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
