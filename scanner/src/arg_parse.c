#include "arg_parse.h"

// All possbile ARGP options
struct argp_option options[] = {
    {"interface", 'i', "interface",    0, "Interface used for scanning", 0},
    {"pu",        'u', "(range|list)", 0, "UDP port range", 0},
    {"pt",        't', "(range|list)", 0, "TCP port range", 0},
    {"wait",      'w', "miliseconds",  0, "Maximum waiting time for server response", 0},
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

void port_array_insert(int* array, int position, char *number)
{
    int port_number;
    if ((port_number = atoi(number)) > 0) {
        array[position] = port_number;
    } else {
        fprintf(stderr, "Port number could not be converted\n");
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

        case ARGP_KEY_ARG:
            if (state->arg_num >= 2)
                argp_usage(state);
            strncpy(arguments->domain, arg, 255);
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// ARGP final structure
struct argp argp = {options, parse_opt, args_doc, doc, children, help_filter, argp_domain};

struct arguments *args_parse(int argc, char *argv[]) {
    static struct arguments args;
    args.timeout = TIMEOUT_DEFAULT;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    if (!strcmp(args.domain, "")) {
        fprintf(stderr, "Missing domain\n");
        exit(E_MISSING_DOMAIN);
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