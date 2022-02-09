#include <stdio.h>
#include <stdlib.h>         // strtol
#include <string.h>         // strcmp
#include <sys/socket.h>     // socket, bind, accept, listen
#include <sys/un.h>         // struct sockaddr_un
#include <netinet/in.h>     // struct sockaddr_in
#include <unistd.h>         // read

#define USAGE                                               \
do {                                                        \
    fprintf(stderr, "USAGE: ./hinfosvc port_number\n");     \
    return -1;                                              \
} while (0)                                                 \

#define ERR(msg)                    \
do {                                \
    fprintf(stderr, "Error: %s\n", msg);   \
    return -1;                      \
} while (0)                         \

long parse_arg(int argc, char const *argv[])
{
    if (argc != 2)
        USAGE;

    // convert extracted port
    char *end;
    const long port = strtol(argv[1], &end, 10);

    // ignore converting port 0 since it is reserved
    if (port <= 0 || strcmp(end, ""))
        USAGE;

    return port;
}

int main(int argc, char const *argv[])
{
    int scfd;
    long port;
    struct sockaddr_in sc_addr;
    struct sockaddr_un rc_addr;
    socklen_t rc_addr_size, option;

    // parse port argument
    if ((port = parse_arg(argc, argv)) < 0)
        return -1;

    if ((scfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        ERR("failed to create socket");

    // forcefully attach socket to given port
    option = 1;
    if (setsockopt(scfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)))
        ERR("Failed to reuse the socket address");

    sc_addr.sin_family = AF_INET;
    sc_addr.sin_addr.s_addr = INADDR_ANY;
    sc_addr.sin_port = htons(port);

    if (bind(scfd, (struct sockaddr *)&sc_addr, sizeof(struct sockaddr_in)) == -1)
        ERR("failed to bind socket");

    // listen with up to 3 request in queue
    if (listen(scfd, 3) < 0)
        ERR("server failed to listen to requests");

    // wait for requests
    rc_addr_size = sizeof(struct sockaddr_un);

    //while (1) {
        int rcfd = accept(scfd, (struct sockaddr *) &rc_addr, &rc_addr_size);
        if (rcfd == -1)
            ERR("could not accept request");

        char buffer[1024] = {0};
        int valread = read(rcfd, buffer, 1024);
        printf("%s\n", buffer);
        char msg[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\n\r\nTest";
        send(rcfd, msg, strlen(msg), 0);
    //}

    return 0;
}
