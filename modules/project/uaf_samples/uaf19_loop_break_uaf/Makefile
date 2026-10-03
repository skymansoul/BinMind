CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = uaf19_loop_break_uaf

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
