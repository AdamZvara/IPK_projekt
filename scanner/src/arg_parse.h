/**
 * @file    arg_parse.h
 * @author  Adam Zvara, xzvara01@vutbr.cz
 * @brief   Header file for parsing command line options
 */

#ifndef _ARG_PARSE_H
#define _ARG_PARSE_H 1

#include <argp.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>
#include <stdio.h>

#define E_MISSING_DOMAIN -1
#define E_INTERFACE -2
#define error_internal() {fprintf(stderr, "Internal error occured\n"); exit(-3);}
#define TIMEOUT_DEFAULT  5000

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
    int *array;
    int array_length;
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


/* Parse argument in format: 'start-end' into structure port (start, end) */
void set_port_range(struct port *port, char *argument);

/* Convert port number and insert it into array */
void port_array_insert(int* array, int position, char *number);

/* Parse argument in format: 'port1,port2,port3...' into structure port (array, array_length)*/
void set_port_array(struct port *port, char *argument);

/**
 * @brief Function called when port option was found
 * @details Supported port options are in range format (24-30) or discrete values (24,50)
 *  which are stored separately. For range format, start and end port numbers are stored in port structure.
 *  For discrete values, each value is stored in array in port structure
 * @param[out] t        Pointer to port format in arguments
 * @param[out] port     Pointer to port structure in arguments
 * @param[in]  argument Currently parsed option
 */
void set_port(enum port_format *t, struct port *port, char *argument);

// Function to determine actions when certain option is found
error_t parse_opt (int key, char *arg, struct argp_state *state);

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