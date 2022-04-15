#include <stdio.h>
#include <argp.h>
#include "arg_parse.h"
#include "network.h"

#define WRONG_ARG

int main(int argc, char const *argv[])
{
    struct arguments *user_args;
    user_args = args_parse(argc, (char **)argv);

    if (!strcmp(user_args->interface, "")) {
        print_interfaces();
    }
    args_print(*user_args);

    return 0;
}
