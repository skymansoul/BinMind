CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = sample

all: $(TARGET)

$(TARGET): sample.c
	$(CC) $(CFLAGS) -o $(TARGET) sample.c

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
