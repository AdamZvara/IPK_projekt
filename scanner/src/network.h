#ifndef _NETWORK_H
#define _NETWORK_H 1

#include "arg_parse.h"

/**
 * @brief Print all existing network interfaces
 */
void print_interfaces();

/**
 * @brief Try to scan single port on given domain name
 *
 * @return
 */
int scan(char *domain, int timeout, int port);

#endif