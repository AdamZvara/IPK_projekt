/**
 * @brief   Header file for common functions used by whole program
 * @author  xzvara01(@vutbr.cz)
 * @file    common.h
 * @date    20.04.2022
 */

#ifndef _COMMON_H
#define _COMMON_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>         // sockaddr_in, in_addr
#include <netdb.h>              // gethostbyname
#include <net/if.h>             // if_nameindex

#include "parse_args.h"

#define SENDER_PORT 46300

#define FILTER_STR_LEN 1024
#define ETHER_HEADER_LEN 14

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

/**
 * @brief Get IP address of used interface for pseudo header
 *
 * @return 32bit IP address of interface
 *
 * source: https://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php
 * author: Akimichi Ogawa
 */
uint32_t get_interface_ip(int socket, char *interface);

/**
 * @brief Create string to filter out unwanted traffic
 * @details Example output string: tcp and src port 1234 and dst port 1234 and src host 127.0.0.1 and dst host 127.0.0.1
 * 
 * @param[in] uargs Program arguments
 * @param[in] port  Destination port number 
 * @param[in] socket_fd Socket descriptor
 * @param[in] protocol  Type of protocol
 * 
 * @return Pointer to static char array representing filter string
 */
char *set_filter_string(struct arguments uargs, int port, int socket_fd, char *protocol);

/**
 * @brief Event handler for SIGALRM used for stopping pcap_next
 * 
 * @param[in] signum Signal number
 */
void breakloop(int signum);

#endif