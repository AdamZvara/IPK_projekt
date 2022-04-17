#include <stdio.h>
#include <argp.h>
#include "parse_args.h"
#include "network.h"

#define WRONG_ARG

#define DEBUG 1

int main(int argc, char const *argv[])
{
    struct arguments *user_args;
    user_args = parse_args(argc, (char **)argv);

    #ifdef DEBUG
    print_args(*user_args);
    #endif

    /* TCP (IPv4?) SCANNING */
    int tcp_type;
    if ((tcp_type = user_args->tcp_type) != 0) {
        if (tcp_type == CONT) {
            for (int i = user_args->tcp.start; i < user_args->tcp.end; i++) {
                //printf("scanning %d port\n", i);
                tcp_ipv4_scan(user_args->domain, user_args->interface, user_args->timeout, i);
            }
        } else {
            for (int i = 0; i < user_args->tcp.array_length; i++) {
                //printf("scanning %d port\n", user_args->tcp.array[i]);
                tcp_ipv4_scan(user_args->domain, user_args->interface, user_args->timeout, user_args->tcp.array[i]);
            }
        }
    }
    return 0;
}
