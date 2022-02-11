#include <iostream>
#include <string>
#include <fstream>
#include <cstring>          // strlen
#include <sstream>          // istringstream
#include <sys/socket.h>     // socket, bind, accept, listen
#include <netinet/in.h>     // struct sockaddr_in
#include <unistd.h>         // read

using std::string;

#define ERR -1
#define HOSTNAME "GET /hostname"
#define CPU_NAME "GET /cpu-name"
#define LOAD "GET /load"
#define SLEEP_TIME 1

/**
 * @brief Convert port number from string format to integer
 * @details Function throws invalid_argument when port number is negative
 *  or floating point
 * @param[in] str_port Port number in string format
 * @return Converted port number as integer
 */
int get_port(char *str_port)
{
    int port;
    std::istringstream ss(str_port);
    if (!(ss >> port) || !ss.eof() || port > 65535) {
        throw std::invalid_argument("Incorrect port number - must be integer in range 0-65535");
    } else if (port < 0) {
        throw std::invalid_argument("Port number must be positive");
    }

    return port;
}

/**
 * @brief Get CPU name and store it in given char array
 * @details Function uses lscpu and awk to extract CPU name
 * @param[out] name Char array to store name into
 * @param[in] name_length Char length
 */
int get_cpuname(char *name, size_t name_length)
{
    FILE *pf;

    // extract cpu name from lscpu command using awk
    pf = popen("lscpu | awk -F' ' '{\
        if(NR==13) {                \
            for(i=3;i<NF;i++){      \
                printf(\"%s \", $i) \
            }                       \
        printf($NF)                 \
        }}'","r");

    if (pf == nullptr) {
        return ERR;

    }

    fgets(name, name_length, pf);
    pclose(pf);
    return 0;
}

/**
 * @brief Calculate CPU load percentage from 2 arrays
 * @param[in] old_v First array of measured CPU values
 * @param[in] new_v Second array of measured CPU values
 * @return CPU load percentage
 */
int cpu_percentage(int old_v[], int new_v[])
{
    int PrevIdle = old_v[3] + old_v[4];
    int Idle = new_v[3] + new_v[4];

    int PrevNonIdle = old_v[0] + old_v[1] + old_v[2] + old_v[5] + old_v[6] + old_v[7];
    int NonIdle = new_v[0] + new_v[1] + new_v[2] + new_v[5] + new_v[6] + new_v[7];

    int PrevTotal = PrevIdle + PrevNonIdle;
    int Total = Idle + NonIdle;

    int totald = Total - PrevTotal;
    int idled = Idle - PrevIdle;

    return (float)(totald - idled)/totald*100;
}

/**
 * @brief Get numeric values from /proc/stat (first line)
 * @param[out] arr Array to store extracted values into
 */
int cpuinfo(int arr[])
{
    std::ifstream proc;
    proc.open("/proc/stat", std::ifstream::in);

    if (!proc) {
        return ERR;
    }

    string values;
    getline(proc, values);
    // remove "cpu" from line
    values.erase(0, 4);
    std::istringstream stream(values);

    // convert numbers from string into integer array
    int n, counter = 0;
    while(stream >> n) {
        arr[counter++] = n;
    }

    proc.close();
    return 0;
}

/**
 * @brief Provide CPU usage percentage
 * @param[in] str String to store evaluated CPU usage
 * @param[in] str_length Length of given string
 * @param[in] sleep_time Time between CPU measurings
 * @return 0 if no error occured, otherwise return ERR
 */
int get_cpuload(char *str, size_t str_length, int sleep_time)
{
    // get 2 sets of CPU time values, separated by 1 second
    int old_values[10], new_values[10];
    if (cpuinfo(old_values)) {
        return ERR;
    }
    sleep(sleep_time);
    if (cpuinfo(new_values)) {
        return ERR;
    }

    string tmp = std::to_string(cpu_percentage(old_values, new_values));
    if (str_length > tmp.length()+1) {
        memcpy(str, tmp.data(), tmp.length()+1);
    }

    return 0;
}

/**
 * @brief Sends answer to user request on given socket
 * @param[in] socket_fd socket descriptor
 * @param[in] s_addr socket address
 * @param[in] addr_size address size
 * @return
 */
int accept_request(int socket_fd, sockaddr_in s_addr, socklen_t addr_size)
{
    int receive_fd;
    if ((receive_fd = accept(socket_fd, (sockaddr *) &s_addr, &addr_size)) < 0)
        return -1;

    string msg = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\n\r\n";
    const string err_msg = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain;\r\n\r\nBad Request";

    char request[1024] = {0};
    if (read(receive_fd, request, 1024) < 0) {
        close(receive_fd);
        return ERR;
    }

    const int content_len = 512;
    char http_content[content_len] = {0};

    if (!strncmp(request, HOSTNAME, strlen(HOSTNAME))) {
        if (gethostname(http_content, content_len))
            return ERR;
    } else if (!strncmp(request, CPU_NAME, strlen(CPU_NAME))) {
        if (get_cpuname(http_content, content_len))
            return ERR;
    } else if (!strncmp(request, LOAD, strlen(LOAD))) {
        if (get_cpuload(http_content, content_len, SLEEP_TIME))
            return ERR;
    } else {
        if (send(receive_fd, err_msg.data(), err_msg.length(), 0) < 0)
            return ERR;
        close(receive_fd);
        return 0;
    }

    msg.append(http_content);
    msg.append("\n");
    if (send(receive_fd, msg.data(), msg.length(), 0) < 0)
        return ERR;

    close(receive_fd);
    return 0;
}


int main(int argc, char *argv[])
{
    // get port number from argv
    int port;
    try {
        if (argc != 2) {
            throw std::invalid_argument("USAGE: ./hinfosvc port_number");
        } else {
            port = get_port(argv[1]);
        }
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return ERR;
    }


    int socket_fd;
    sockaddr_in s_addr;
    socklen_t s_addr_size = sizeof(sockaddr_in);

    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);

    // create socket, bind it to address and listen to it
    try {
        if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            throw std::runtime_error("could not create socket");

        int option = 1;
        //if (setsockopt(scfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)))
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)))
            throw std::runtime_error("setsockopt failed");

        if (bind(socket_fd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) < 0)
            throw std::runtime_error("failed to bind socket");

        if (listen(socket_fd, 1) < 0)
            throw std::runtime_error("server could not listen to requests");

    } catch(const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return ERR;
    }

    while (1) {
        // comunicate with user and process requests
        if (accept_request(socket_fd, s_addr, s_addr_size)) {
            std::cerr << "Internal error occured" << std::endl;
            return ERR;
        }
    }

    return 0;
}