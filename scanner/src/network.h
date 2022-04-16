#ifndef _NETWORK_H
#define _NETWORK_H 1

#include <stdbool.h>
#include "parse_args.h"

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
 * @brief Try to scan single port on given domain name
 *
 * @return
 */
//int scan(char *domain, char *interface, int timeout, int port);

#endif