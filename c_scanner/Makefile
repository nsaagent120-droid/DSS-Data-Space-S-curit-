CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = port_scanner
SRCS = port_scanner.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
