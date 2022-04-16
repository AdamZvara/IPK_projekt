from socket import *
import sys

# create socket and bind it to port (first argument from command line)
sd = socket(AF_INET, SOCK_DGRAM)
sd.bind(('', int(sys.argv[1])))

while True:
    message, address = sd.recvfrom(1)