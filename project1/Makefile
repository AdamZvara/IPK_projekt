CC = gcc
CFLAGS = -std=gnu11 -g -Wall -Wextra -pedantic

TARGET = hinfosvc

$(TARGET): $(TARGET).c
		$(CC) $(CFLAGS) $^ -o $@

clean:
		rm -rf $(TARGET)

test: $(TARGET)
		./test.sh

.phony: clean test