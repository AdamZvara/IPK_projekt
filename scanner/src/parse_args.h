/**
 * @file    parse_args.h
 * @author  Adam Zvara, xzvara01@vutbr.cz
 * @brief   Header file for parsing command line options
 */

#ifndef _ARG_PARSE_H
#define _ARG_PARSE_H 1

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TIMEOUT_DEFAULT  5000
#define error_internal() {fprintf(stderr, "Internal error occured\n"); exit(E_INTERNAL);}
#define help() {fprintf(stderr, "%s", help_string); exit(0);}

enum error {E_INTERNAL = -10, E_UNKNOWN_OPT, E_OPT_MISSING_ARG, E_MISSING_DOMAIN, E_MISSING_INTERFACE, E_MISSING_PORTS, E_PORT_NUMBER};


/** @enum Define format of scanned ports used program options */
enum port_format
{
    CONT, /*!< continuous format: range (eg. 20-30) */
    DISC  /*!< discrete format: concrete values (eg. 20,30) */
};

/** @struct Define boundaries of continuous port type or concrete port values for discrete port type */
struct port
{
    int start;
    int end;
    int array_length;
    int *array;
};

/** @brief Store program options */
struct arguments
{
    char interface[256];
    char domain[256];
    enum port_format tcp_type;
    struct port tcp;
    enum port_format udp_type;
    struct port udp;
    int timeout;
};

/**
 * @brief Parsing function
 * @details Function uses argp parsing combined with my own domain_parse function, which
 *  handles special program option - domain/IP_address
 * @param[in] argc Number of arguments
 * @param[in] argv Program arguments
 * @return Static structure 'arguments' containing parsed options
 */
struct arguments *args_parse(int argc, char *argv[]);

/**
 * @brief Print argument structure
 * @param[in] user_args Argument structure
 */
void args_print(struct arguments user_args);

#endif