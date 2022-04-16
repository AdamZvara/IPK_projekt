#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <ifaddrs.h>

#include "network.h"

void print_interfaces()
{
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if (if_nidxs != NULL) {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            printf("%s\n", intf->if_name);
        }
        if_freenameindex(if_nidxs);
    }
}

int scan(char *domain, int timeout, int port)
{
    struct sockaddr_in address;
    //struct timeval tv;
    //fd_set write_fds;
	//socklen_t so_error_len;
    int sd;
    //, so_error = 1, yes = 1;

    //int write_permission;

    struct hostent *server;
    server = gethostbyname(domain);

    address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr *)(server->h_addr_list[0]))));	/* inet_addr() converts string of host IP to int */
	address.sin_port = htons(port);	/* htons() returns int with data set as big endian. Most computers follow little endian and network devices only know big endian. */

    // Microseconds to timeout
    //tv.tv_usec = timeout;

    //Create a socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        fprintf(stderr, "Socket creating error\n");

    const struct ifreq ifr = {};

    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("setsockopt");
        return EXIT_FAILURE;
    }

    // if (connect(sd, (const struct sockaddr *) &address, sizeof(address))) {
    //     fprintf(stderr, "connection error");
    // }

    struct sockaddr_in addr;
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    socklen_t addr_len;

    addr_len = sizeof (addr);
    getsockname(sd, (struct sockaddr*)&addr, &addr_len);
    getifaddrs(&ifaddr);

    // look which interface contains the wanted IP.
    // When found, ifa->ifa_name contains the name of the interface (eth0, eth1, ppp0...)
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr)
        {
            if (AF_INET == ifa->ifa_addr->sa_family)
            {
                struct sockaddr_in* inaddr = (struct sockaddr_in*)ifa->ifa_addr;

                if (inaddr->sin_addr.s_addr == addr.sin_addr.s_addr)
                {
                    if (ifa->ifa_name)
                    {
                        printf("%s", ifa->ifa_name);
                    }
                }
            }
        }
    }
    freeifaddrs(ifaddr);

}