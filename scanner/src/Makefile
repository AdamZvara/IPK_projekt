CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra
LFLAGS = -lpcap

project = ipk-l4-scan

.PHONY: clean

$(project): $(project).c parse_args.o tcp_scan.o common.o
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS) 
	
clean:
	rm -rf $(project) *.o