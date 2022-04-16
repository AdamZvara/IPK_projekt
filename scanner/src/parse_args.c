/**
 * @file    parse_args.c
 * @author  Adam Zvara, xzvara01@vutbr.cz
 * @brief   Implementation of functions used for parsing arguments
 */

#include <getopt.h>
#include "network.h"
#include "parse_args.h"


static char help_string[] =
"USAGE: ./ipk-l4-scan interface ports domain {timeout}\n\
Scan domain for openned ports\n\n\
interface\n\t-i | --interface[=interface]\tSelect interface from which packets will be sent\n\
\t\t\t\t\tThis option without argument prints all availiable interfaces\n\
ports\n\t-u | --pu=port_range Range of UDP ports to be scanned\n\
\t-t | --pt=port_range Range of TCP ports to be scanned\n\
domain\n\t domain name or IP address to be scanned\n\
timeout\n\t -w | --wait=miliseconds Time used to wait for response from server\n";


/* Convert port number from string to integer and check boundaries */
int convert_port_number(char *port_number)
{
    int retval;
    if ((retval = atoi(port_number)) <= 0) {
        fprintf(stderr, "Starting range number could not be converted\n");
        exit(E_PORT_NUMBER);
    } 

    if (retval > 65535 || retval < 1) {
        fprintf(stderr, "Port range number has to be in interval <1,65535>\n");
        exit(E_PORT_NUMBER);
    }

    return retval;
}

void set_port_range(struct port *port, char *argument)
{
    char start[6] = {};
    char end[6] = {};
    int i;

    // starting port number
    for (i = 0; argument[i] != '-'; i++) {
        start[i] = argument[i];
    }
    port->start = convert_port_number(start);

    // ending port number
    for (int c = 0; argument[i] != '\0'; c++) {
        ++i;
        end[c] = argument[i];
    }
    port->end = convert_port_number(end);

    if (port->start > port->end) {
        fprintf(stderr, "Starting port number must be lower than ending port number\n");
        exit(E_PORT_NUMBER);
    }
}

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
    int arr_position = 0;
    char number[6] = {};
    for (int i = 0; argument[i] != '\0'; i++) {
        if (argument[i] != ',') {
            number[number_position++] = argument[i];
        }
        else {
            port->array[arr_position++] = convert_port_number(number);
            memset(number, 0, 6);
            number_position = 0;
        }
    }
    port->array[arr_position] = convert_port_number(number); // insert last number
}

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

struct arguments *args_parse(int argc, char *argv[]) {
    static struct arguments args;
    args.timeout = TIMEOUT_DEFAULT;

    if (argc == 1) {
        help();
    }
    
    int c, option_index, timeout;
    struct option long_options[] = {
        {"pu",        required_argument, 0, 'u'},
        {"pt",        required_argument, 0, 't'},
        {"wait",      required_argument, 0, 'w'},
        {"help",            no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, ":i:u:t:w:h", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                help();

            case 'i':
                strncpy(args.interface, optarg, 255);
                break;

            case 'u':
                set_port(&args.udp_type, &args.udp, optarg);
                break;
            
            case 't':
                set_port(&args.tcp_type, &args.tcp, optarg);
                break;

            case 'w':
                if ((timeout = atoi(optarg)) > 0)
                    args.timeout = timeout;
                else    
                    fprintf(stderr, "Timeout value could not be converted. Using default value ...\n");
                break;
            
            case ':':
                if (optopt == 'i') {
                    printf("Availiable interfaces:\n");
                    print_interfaces();
                    exit(0);
                } else {
                    fprintf(stderr, "Option (%c) is missing an argument\n", optopt);
                    exit(E_OPT_MISSING_ARG);
                }
                break;

            default:
                fprintf(stderr, "Unknown option used\n");
                exit(E_UNKNOWN_OPT);
                break;
        }
    }

    // parse domain/ip address
    if ((argc - optind) == 1) {
        strcpy(args.domain, argv[optind]);
    } else {
        fprintf(stderr, "Missing domain arugment\n");
        exit(E_MISSING_DOMAIN);
    }

    // check if interface has been provided
    if (!strcmp(args.interface, "")) {
        fprintf(stderr, "Provide name of the interface\n");
        exit(E_MISSING_INTERFACE);
    }

    // check if at least one port number has been defined
    if (args.tcp_type == 0 && args.udp_type == 0) {
        fprintf(stderr, "Provide ports to be scanned\n");
        exit(E_MISSING_PORTS);
    }

    // if user inserted domain name, convert it to IP address
    if (!valid_address(args.domain)) {
        strcpy(args.domain, resolve_hostname(args.domain));
    }
  
    return &args;
}

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