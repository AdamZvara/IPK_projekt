CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra
LFLAGS = -lpcap

project = ipk-l4-scan

.PHONY: clean

$(project): $(project).c parse_args.o common.o tcp_scan.o udp_scan.o  
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS) 
	
clean:
	rm -rf $(project) *.o