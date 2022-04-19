#ifndef _SCANNER_H
#define _SCANNER_H 1

#include <stdbool.h>
#include "parse_args.h"

#define DNS_SERVER "8.8.4.4"
#define DNS_SERVER_PORT 53
#define MAX_IP_SIZE 128
#define HEADER_SIZE 4096
#define SENDER_PORT 46300
#define IP_LENGTH 40

/**
 * @struct Pseudo TCP header used for checksum
 * source: https://www.binarytides.com/raw-sockets-c-code-linux/
 * author: Silver Moon
 */
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

typedef enum port_status {OPENED = 1, FILTERED, CLOSED} p_status;

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
char *resolve_domain(char *domain);

/**
 * @brief Print all existing network interfaces
 */
void print_interfaces();

/**
 * @brief Try to scan single TCP port on given IP address
 *
 * @return Value from enum port_status which represents state of scanned port
 */
enum port_status tcp_ipv4_scan(char *domain, char *interface, int timeout, int port);

#endif