/**
 * @file    arg_parse.h
 * @author  Adam Zvara, xzvara01@vutbr.cz
 * @brief   Header file for parsing command line options
 */

#include <argp.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>
#include <stdio.h>

#define E_MISSING_DOMAIN -1
#define error_internal() {fprintf(stderr, "Internal error occured\n"); exit(-2);}
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

// All possbile ARGP options
struct argp_option options[] = {
    {"interface", 'i', "INTERFACE", 0, "Interface used for scanning", 0},
    {"pu",        'u', "UDP_PORTS", 0, "UDP port range", 0},
    {"pt",        't', "TCP_PORTS", 0, "TCP port range", 0},
    {"wait",      'w', "TIMEOUT",   0, "Maximum waiting time for server response", 0},
    { 0 }
};

// Program description
char doc[] =
    "UDP and TCP port scanner";

// Special command line arguments
char args_doc[] =
    "[domain-name|ip-address]";

// Fill other options so compiler does not produce warning
struct argp_child children[] = {};
char *help_filter(int key, const char *text, void *input){(void)key; (void)input; return (char *)text;}
char argp_domain[] = "";

/* Parse argument in format: 'start-end' into structure port (start, end) */
void set_port_range(struct port *port, char *argument)
{
    char start[6] = {};
    char end[6] = {};
    int i;
    int port_number;

    // starting port number
    for (i = 0; argument[i] != '-'; i++) {
        start[i] = argument[i];
    }
    if ((port_number = atoi(start)) <= 0) {
        fprintf(stderr, "Starting range number could not be converted. Using default value (1)\n");
        port->start = 1;
    } else {
        port->start = port_number;
    }

    // ending port number
    for (int c = 0; argument[i] != '\0'; c++) {
        ++i;
        end[c] = argument[i];
    }
    if ((port_number = atoi(end)) <= 0) {
        fprintf(stderr, "Ending range number could not be converted. Using default value (65535)\n");
        port->end = 65535;
    } else {
        port->end = port_number;
    }
}

/* Convert port number and insert it into array */
void port_array_insert(int* array, int position, char *number)
{
    int port_number;
    if ((port_number = atoi(number)) > 0) {
        array[position] = port_number;
    } else {
        fprintf(stderr, "Port number could not be converted\n");
    }
}

/* Parse argument in format: 'port1,port2,port3...' into structure port (array, array_length)*/
void set_port_array(struct port *port, char *argument)
{
    // count commas in argument and allocate space for array
    int alloc_size = 0;
    for (int i = 0; argument[i] != '\0'; i++) {
        if (argument[i] == ',')
            alloc_size++;
    }
    alloc_size++;
    port->array = malloc(alloc_size * sizeof(int));
    if (port->array == NULL) {
        error_internal();
    }
    port->array_length = alloc_size;

    // convert numbers and store them in allocated array
    int number_position = 0;
    int array_position = 0;
    char number[6] = {};
    for (int i = 0; argument[i] != '\0'; i++) {
        if (argument[i] != ',') {
            number[number_position++] = argument[i];
        }
        else {
            port_array_insert(port->array, array_position++, number);
            memset(number, 0, 6);
            number_position = 0;
        }
    }
    port_array_insert(port->array, array_position, number); // insert last number
}

/**
 * @brief Function called when port option was found
 * @details Supported port options are in range format (24-30) or discrete values (24,50)
 *  which are stored separately. For range format, start and end port numbers are stored in port structure.
 *  For discrete values, each value is stored in array in port structure
 * @param[out] t        Pointer to port format in arguments
 * @param[out] port     Pointer to port structure in arguments
 * @param[in]  argument Currently parsed option
 */
void set_port(enum port_format *t, struct port *port, char *argument)
{
    if (strchr(argument, '-')) {
        *t = CONT; // range format
        set_port_range(port, argument);
    } else {
        *t = DISC; // list format
        set_port_array(port, argument);
    }
}

/**
 * @brief Get domain-name/IP-address from program arguments
 * @details This function is called before argp_parse and changes argv and argc.
 *  It assumes the last option given to program is domain-name or IP-address, parses it
 *  into arguments structure and removes it from argv (decrements argc). If there are no
 *  options to be parsed, function exits the program with E_MISSING_DOMAIN.
 * @param[in,out] argc  Number of arguments
 * @param[in,out] argv  Program arguments
 * @param[out]    args  Pointer to arguments structure to store domain into
 */
void domain_parse(int *argc, char *argv[], struct arguments *args)
{
    if (*argc < 2) {
        fprintf(stderr, "No domain name or IP address specified\n");
        exit(E_MISSING_DOMAIN);
    }

    // set args->domain to extracted domain (only 255 characters)
    /* memset(args->domain, 0, 256); // not mandatory since static variables are initialized with 0 */
    strncpy(args->domain, argv[*argc-1], 255);

    // delete last argument from argv and decrement argc
    memset(&(argv[*argc-1]), 0, sizeof(void *));
    (*argc)--;
}

// Function to determine actions when certain option is found
error_t parse_opt (int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    int time;

    switch (key)
    {
        case 'i':
            strncpy(arguments->interface, arg, 256);
            break;
        case 'u':
            set_port(&arguments->udp_type, &arguments->udp, arg);
            break;
        case 't':
            set_port(&arguments->tcp_type, &arguments->tcp, arg);
            break;
        case 'w':
            if ((time = atoi(arg)) > 0)
                arguments->timeout = time;
            else
                fprintf(stderr, "Timeout value could not be converted. Using default value ...\n");
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// ARGP final structure
struct argp argp = {options, parse_opt, args_doc, doc, children, help_filter, argp_domain};

/**
 * @brief Parsing function
 * @details Function uses argp parsing combined with my own domain_parse function, which
 *  handles special program option - domain/IP_address
 * @param[in] argc Number of arguments
 * @param[in] argv Program arguments
 * @return Static structure 'arguments' containing parsed options
 */
struct arguments *args_parse(int argc, char *argv[]) {
    static struct arguments args;
    args.timeout = TIMEOUT_DEFAULT;
    domain_parse(&argc, argv, &args);
    argp_parse(&argp, argc, argv, 0, 0, &args);
    return &args;
}

/**
 * @brief Print argument structure
 * @param[in] user_args Argument structure
 */
void args_print(struct arguments user_args)
{
    printf("domain: %s\n", user_args.domain);
    printf("interface: %s\n", user_args.interface);
    printf("TCP ports:\n");
    if (user_args.tcp_type == CONT) {
        printf("\tstart: %d\n", user_args.tcp.start);
        printf("\tend: %d\n", user_args.tcp.end);
    } else {
        printf("\tPort array: ");
        for (int i = 0; i < user_args.tcp.array_length; i++) {
            printf("%d, ", user_args.tcp.array[i]);
        }
        printf("\n");
    }
    printf("UDP ports:\n");
    if (user_args.udp_type == CONT) {
        printf("\tstart: %d\n", user_args.udp.start);
        printf("\tend: %d\n", user_args.udp.end);
    } else {
        printf("\tPort array: ");
        for (int i = 0; i < user_args.udp.array_length; i++) {
            printf("%d, ", user_args.udp.array[i]);
        }
        printf("\n");
    }
    printf("timeout: %d\n", user_args.timeout);
}