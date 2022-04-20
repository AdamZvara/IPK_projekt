CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra
LFLAGS = -lpcap -lpthread

project = ipk-l4-scan

.PHONY: clean

$(project): $(project).c parse_args.o scanner.o
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS) 
	
clean:
	rm -rf $(project) *.o