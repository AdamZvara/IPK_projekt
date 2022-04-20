#ifndef _COMMON_H
#define _COMMON_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>         // sockaddr_in, in_addr
#include <netdb.h>              // gethostbyname
#include <net/if.h>             // if_nameindex

#define SENDER_PORT 46300
#define ERR 1
#define error_internal() {fprintf(stderr, "Internal error occured\n"); exit(ERR);}

extern pcap_t *handle;		// global pcap handle from main file

/**
 * @enum port_status
 * 
 * @brief Values indicating state of scanned port
 */
typedef enum port_status {NONE, OPENED, FILTERED, CLOSED} p_status;

/**
 * @brief Check if given address is in valid IP(v4/v6) format
 *
 * @return True if address is in correct format, otherwise False
 */
bool valid_address(char *address);

/**
 * @brief Convert domain name to IP address (IPv4)
 *
 * @return Pointer to converted IP address if successful, otherwise NULL
 */
char *domain_to_IP(char *domain);

/**
 * @brief Print all existing network interfaces
 */
void print_interfaces();

#endif