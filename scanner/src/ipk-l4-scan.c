#include <stdio.h>
#include <argp.h>
#include "parse_args.h"
#include "network.h"

#define WRONG_ARG

int main(int argc, char const *argv[])
{
    struct arguments *user_args;
    user_args = args_parse(argc, (char **)argv);
    args_print(*user_args);
    
    
    //printf("%d", scan(user_args->domain, user_args->interface, user_args->timeout, user_args->tcp.array[0]));

    return 0;
}