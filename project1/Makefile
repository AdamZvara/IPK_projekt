CC = g++
CPPFLAGS = -std=c++11 -g -Wall -Wextra -pedantic

TARGET = hinfosvc

$(TARGET): $(TARGET).cpp
		$(CC) $(CPPFLAGS) $^ -o $@

clean:
		rm -rf $(TARGET)

test: $(TARGET)
		./test.sh

.phony: clean test