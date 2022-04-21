/**
 * @brief   Implementation of common functions used by whole program
 * @author  xzvara01(@vutbr.cz)
 * @file    common.c
 * @date    20.04.2022
 */

#include <sys/ioctl.h>          // ioctl

#include "common.h"

bool valid_address(char *address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, address, &(sa.sin_addr));
    if (result == 0) {
        result = inet_pton(AF_INET6, address, &(sa.sin_addr));
    }
    return result != 0;
}

char *domain_to_IP(char *domain)
{
    struct hostent *host;
    if ((host = gethostbyname(domain)) == NULL)
        error_internal();    

    return inet_ntoa(*((struct in_addr*)host->h_addr));
}


void print_interfaces()
{
    struct if_nameindex *name_index, *intf;

    name_index = if_nameindex();
    if (name_index != NULL) {
        for (intf = name_index; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            printf("%s\n", intf->if_name);
        }
        if_freenameindex(name_index);
    }
}

uint32_t get_interface_ip(int socket, char *interface)
{
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(socket, SIOCGIFADDR, &ifr);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

char *set_filter_string(struct arguments uargs, int port, int socket_fd, char *protocol)
{
    static char filter_string[FILTER_STR_LEN];
    memset(filter_string, 0, FILTER_STR_LEN);

    strcat(filter_string, protocol);
    if (!strcmp(protocol, "tcp")) {
    strcat(filter_string, " and src port ");
    char port_str[10] = "";
        snprintf(port_str, 10, "%d", port);
        strcat(filter_string, port_str);
        strcat(filter_string, " and dst port ");
        snprintf(port_str, 10, "%d", SENDER_PORT);
        strcat(filter_string, port_str);
    }
    strcat(filter_string, " and src host ");
    strcat(filter_string, uargs.domain);
    strcat(filter_string, " and dst host ");
    int32_t IP_int = get_interface_ip(socket_fd, uargs.interface);
    char IP_str[INET6_ADDRSTRLEN];
    strcat(filter_string, inet_ntop(AF_INET, &IP_int, IP_str, INET6_ADDRSTRLEN));

    return filter_string;
}

void breakloop(int signum)
{
    (void) signum;
    pcap_breakloop(handle);
}