CC = gcc
CFLAGS = -g -std=c17 -Wall -Wextra

project = main
network = network

src = $(project).c $(network).c

.PHONY: clean

$(project): $(project).c arg_parse.h network.h
	$(CC) $(CFLAGS) $(src) -o $@

clean:
	rm -rf $(project)