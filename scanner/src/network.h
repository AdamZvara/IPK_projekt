#ifndef _NETWORK_H
#define _NETWORK_H 1

#include <stdbool.h>
#include <netinet/tcp.h>    // TCP header
#include <netinet/in.h>     // sockaddr_in, in_addr
#include "parse_args.h"

#define DNS_SERVER "8.8.4.4"
#define DNS_SERVER_PORT 53
#define MAX_IP_SIZE 128
#define DATAGRAM_BUF_SIZE 4096
#define BUF_SIZE 65536

typedef enum port_status {OPENED = 1, FILTERED, CLOSED} p_status;

/* NEW CODE */
struct pseudo_header {
    unsigned int source_addr;
    unsigned int dest_addr;
    unsigned char plc;
    unsigned char prt;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

struct target_header {
    struct in_addr target_ip;
    unsigned int target_port;
};

struct datagram_header {
    char datagram[DATAGRAM_BUF_SIZE];
    struct iphdr *ip_head;
    struct tcphdr *tcp_head;
};

/**
 * @brief Check if given address is in valid IP format
 *
 * @return True if address is in correct format, otherwise False
 */
bool valid_address(char *address);

/**
 * @brief Convert domain name to IP address (IPv4)
 *
 * @return Pointer to converted IP address if successful, otherwise NULL
 */
const char *resolve_hostname(char *domain);

/**
 * @brief Print all existing network interfaces
 */
void print_interfaces();

/**
 * @brief Try to scan single TCP port on given IP address
 *
 * @return Value from enum port_status which represents state of scanned port
 */
int tcp_ipv4_scan(char *domain, char *interface, int timeout, int port);

#endif