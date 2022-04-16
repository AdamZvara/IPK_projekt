CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra

project = ipk-l4-scan

.PHONY: clean

$(project): $(project).c parse_args.o network.o
	$(CC) $(CFLAGS) $^ -o $@
	rm -rf *.o
	
clean:
	rm -rf $(project) *.o