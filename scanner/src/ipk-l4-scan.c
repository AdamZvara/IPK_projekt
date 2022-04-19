#include <stdio.h>
#include <argp.h>
#include "parse_args.h"
#include "scanner.h"

void print_result(int portnum, enum port_status status, char *protocol)
{
    printf("%d/%s\t", portnum, protocol);
    switch (status) {
        case OPENED:
            printf("opened\n");
            break;

        case CLOSED:
            printf("closed\n");
            break;

        case FILTERED:
            printf("filtered\n");
            break;
    }
}

int main(int argc, char const *argv[])
{
    struct arguments *user_args;
    user_args = parse_args(argc, (char **)argv);

    /* print user arguments */
    // print_args(*user_args);

    printf("Interesting ports on %s:\n", user_args->domain);
    printf("PORT\tSTATE\n");

    /* TCP (IPv4) SCANNING */
    enum port_format tcp_type;
    enum port_status result;
    if ((tcp_type = user_args->tcp_type) != 0) {
        if (tcp_type == CONT) {
            for (int i = user_args->tcp.start; i < user_args->tcp.end; i++) {
                result = tcp_ipv4_scan(user_args->domain, user_args->interface, user_args->timeout, i);
                print_result(i, result, "tcp");
            }
        } else {
            for (int i = 0; i <= user_args->tcp.array_length; i++) {
                result = tcp_ipv4_scan(user_args->domain, user_args->interface, user_args->timeout, user_args->tcp.array[i]);
                print_result(user_args->tcp.array[i], result, "tcp");
            }
        }
    }

    return 0;
}
