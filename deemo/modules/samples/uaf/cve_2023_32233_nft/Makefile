CC      = gcc
CFLAGS  = -O0 -fno-stack-protector -fno-pie
TARGET  = vuln.exe

$(TARGET): vuln.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	del /q $(TARGET) 2>nul || rm -f $(TARGET)
