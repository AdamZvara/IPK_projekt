CC = gcc
CFLAGS = -g -std=c17 -Wall -Wextra

project = main

.PHONY: clean

$(project): $(project).c arg_parse.o network.o
	$(CC) $(CFLAGS) $(project).c network.c arg_parse.c -o $@

clean:
	rm -rf $(project) *.o