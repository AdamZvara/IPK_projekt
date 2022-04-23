/**
 * @brief 	Header file for UDP scanning functions
 * @author  xzvara01(@vutbr.cz)
 * @file    udp_scan.h
 * @date    20.04.2022
 */

#ifndef _UDP_SCAN_H
#define _UDP_SCAN_H 1

#include "common.h"
#include "parse_args.h"

p_status udp_ipv4_scan(struct arguments uargs, int port);

p_status udp_ipv6_scan(struct arguments uargs, int port);

#endif