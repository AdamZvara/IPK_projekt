#include <stdio.h>
#include <stdlib.h>         // strtol
#include <string.h>         // strcmp
#include <sys/socket.h>     // socket, bind, accept, listen
#include <netinet/in.h>     // struct sockaddr_in
#include <unistd.h>         // read

#define USAGE                                               \
do {                                                        \
    fprintf(stderr, "USAGE: ./hinfosvc port_number\n");     \
    return -1;                                              \
} while (0)                                                 \

#define ERR(msg)                            \
do {                                        \
    fprintf(stderr, "Error: %s\n", msg);    \
    return -1;                              \
} while (0)                                 \

#define HOSTNAME "GET /hostname"
#define CPU_NAME "GET /cpu-name"
#define LOAD "GET /load"

const char msg[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\n\r\n";
const char err_msg[] = "HTTP/1.1 404 Not Found\n\n";

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

void hostname(int rcfd)
{
    char name[256];
    gethostname(name, 256);
    send(rcfd, msg, strlen(msg), 0);
    send(rcfd, name, strlen(name), 0);
}

void cpuname(int rcfd)
{
    FILE *pf;
    char data[1024] = {0};

    // Setup our pipe for reading and execute our command.
    pf = popen("lscpu","r");

    // Get the data from the process execution
    int lines = 0;
    while (lines < 13) {
        fgets(data, 1024, pf);
        lines++;
    }

    char *str;
    str = strtok(data, " ");
    str = strtok(NULL, " ");
    char name[200] = {0};

    while ((str = strtok(NULL, " ")) != NULL) {
        strcat(name, str);
        strcat(name, " ");
    }

    send(rcfd, msg, strlen(msg), 0);
    send(rcfd, name, strlen(name), 0);

    // todo check if successfull
    pclose(pf);
}

int percentage(int old[], int new[])
{
    int PrevIdle = old[3] + old[4];
    int Idle = new[3] + new[4];

    int PrevNonIdle = old[0] + old[1] + old[2] + old[5] + old[6] + old[7];
    int NonIdle = new[0] + new[1] + new[2] + new[5] + new[6] + new[7];

    int PrevTotal = PrevIdle + PrevNonIdle;
    int Total = Idle + NonIdle;

    int totald = Total - PrevTotal;
    int idled = Idle - PrevIdle;

    return (float)(totald - idled)/totald*100;

}

void get_cpuinfo(int arr[])
{
    FILE *proc;
    char string[1024] = {0};

    proc = fopen("/proc/stat", "r");
    fgets(string, 1024, proc);

    char *str;
    int counter = 0;
    str = strtok(string, " ");
    while ((str = strtok(NULL, " ")) != NULL) {
        arr[counter++] = atoi(str);
    }

    fclose(proc);
}

void cpuload(int rcfd)
{
    int old[10], new[10];
    get_cpuinfo(old);

    sleep(1);

    get_cpuinfo(new);

    char test[10] = {0};
    sprintf(test, "%d", percentage(old, new));
    strcat(test, "%");
    send(rcfd, msg, strlen(msg), 0);
    send(rcfd, test, strlen(test), 0);
}

int main(int argc, char const *argv[])
{
    int scfd;
    long port;
    struct sockaddr_in sc_addr;
    socklen_t addr_size, option;


    // parse port argument
    if ((port = parse_arg(argc, argv)) < 0)
        return -1;

    if ((scfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        ERR("failed to create socket");

    // forcefully attach socket to given port
    option = 1;
    //if (setsockopt(scfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)))
    if (setsockopt(scfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)))
        ERR("Failed to reuse the socket address");

    // set socket address parameters
    sc_addr.sin_family = AF_INET;
    sc_addr.sin_addr.s_addr = INADDR_ANY;
    sc_addr.sin_port = htons(port);

    if (bind(scfd, (struct sockaddr *)&sc_addr, sizeof(struct sockaddr_in)) == -1)
        ERR("failed to bind socket");

    // listen with up to 1 request in queue
    if (listen(scfd, 1) < 0)
        ERR("server failed to listen to requests");

    addr_size = sizeof(struct sockaddr_in);

    while (1) {
        // await comunication with user
        int rcfd = accept(scfd, (struct sockaddr *) &sc_addr, &addr_size);
        if (rcfd == -1)
            ERR("could not accept request");

        char buffer[1024] = {0};
        int valread = read(rcfd, buffer, 1024);
        printf("%s", buffer);
        if (valread <= 0)
            send(rcfd, err_msg, strlen(err_msg), 0);

        if (!strncmp(buffer, HOSTNAME, strlen(HOSTNAME))) {
            hostname(rcfd);
        } else if (!strncmp(buffer, CPU_NAME, strlen(CPU_NAME))) {
            cpuname(rcfd);
        } else if (!strncmp(buffer, LOAD, strlen(LOAD))) {
            cpuload(rcfd);
        } else {
            send(rcfd, err_msg, strlen(err_msg), 0);
        }

        close(rcfd);
    }

    return 0;
}
