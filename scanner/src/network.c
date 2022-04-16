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

int valid_address(char *address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, address, &(sa.sin_addr));
    if (result == 0) {
        result = inet_pton(AF_INET6, address, &(sa.sin_addr));
    }
    return result != 0;
}

const char *resolve_hostname(char *domain)
{
    struct hostent *host;
    if ((host = gethostbyname(domain)) == NULL)
        error_internal();

    return inet_ntoa(*((struct in_addr*)host->h_addr));
}

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

// int scan(char *domain, char *interface, int timeout, int port)
// {
//     struct sockaddr_in address;
//     //struct timeval tv;
//     int sd;

//     struct hostent *server;
//     server = gethostbyname(domain);

//     address.sin_family = AF_INET;
// 	address.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr *)(server->h_addr_list[0]))));	/* inet_addr() converts string of host IP to int */
// 	address.sin_port = htons(port);	/* htons() returns int with data set as big endian. Most computers follow little endian and network devices only know big endian. */

//     // Microseconds to timeout
//     //tv.tv_usec = timeout;

//     //Create a socket
//     if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
//         fprintf(stderr, "Socket creating error\n");

//     const struct ifreq ifr = {};
//     strcpy((char *)ifr.ifr_name, interface);

//     if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
//         perror("setsockopt");
//         return EXIT_FAILURE;
//     }

//     if (connect(sd, (const struct sockaddr *) &address, sizeof(address))) {
//         fprintf(stderr, "connection error");
//     }
// }