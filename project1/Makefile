CC = gcc
CFLAGS = -std=c99 -g -Wall -Wextra -pedantic

TARGET = hinfosvc

$(TARGET): $(TARGET).c
		$(CC) $(CFLAGS) $^ -o $@

clean:
		rm -rf $(TARGET)

test: $(TARGET)
		./test.sh

.phony: clean test