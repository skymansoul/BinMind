CC      = gcc
CFLAGS  = -O2 -fno-stack-protector -fno-pie
TARGET  = vuln.exe
OBJ     = vuln.o

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	del /q $(TARGET) $(OBJ) 2>nul || rm -f $(TARGET) $(OBJ)

.PHONY: clean
