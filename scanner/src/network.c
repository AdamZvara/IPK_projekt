#include <stdio.h>
#include <sys/socket.h>     // socket APIs
#include <arpa/inet.h>      // inet_ntoa
#include <netinet/ip.h>     // IP header
#include <net/if.h>         // if_nameindex
#include <netdb.h>          // gethostbyname
#include <unistd.h>         // close

// get client IP addres 
#include <sys/types.h>
#include <sys/ioctl.h>

#include "network.h"

bool valid_address(char *address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, address, &(sa.sin_addr));
    if (result == 0) {
        result = inet_pton(AF_INET6, address, &(sa.sin_addr));
    }
    return result != 0;
}

const char *resolve_hostname(char *domain)
{
    struct hostent *host;
    if ((host = gethostbyname(domain)) == NULL)
        error_internal();

    return inet_ntoa(*((struct in_addr*)host->h_addr));
}

void print_interfaces()
{
    struct if_nameindex *name_index, *intf;

    name_index = if_nameindex();
    if (name_index != NULL) {
        for (intf = name_index; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            printf("%s\n", intf->if_name);
        }
        if_freenameindex(name_index);
    }
}

/**
 * @brief Get IP addres of given interface 
 * @details code taken from https://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php 
 * @param[in] interface     Name of interface
 * @param[out] ip_address   Char buffer to store client IP address into
 */
void get_client_ip(char *interface, char *ip_address)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to interface given by user */
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    strncpy(ip_address, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), MAX_IP_SIZE);
}
/* NEW CODE */

// Compute checksum of IP header
// Refer to https://www.ietf.org/rfc/rfc793.txt for reference
unsigned short compute_checksum(unsigned short *dgm, int bytes) {
    register long sum = 0;
    register short answer;
    unsigned int odd_byte;

    while(bytes > 1) {
        sum += *dgm++;
        bytes -= 2;
    }

    if(bytes == 1) {
        odd_byte = 0;
        *((unsigned char*)&odd_byte) = *(unsigned char*)dgm;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

void setup_datagram(char *datagram, struct in_addr server_ip, const char *client_ip, struct iphdr *ip_head,  struct tcphdr *tcp_head) {
    // Clear datagram buffer
    memset(datagram, 0, DATAGRAM_BUF_SIZE);

    // Setup IP header
    ip_head->ihl = 5; // HELEN
    ip_head->version = 4;
    ip_head->tos = 0; // Type of service
    ip_head->tot_len = (sizeof(struct ip) + sizeof(struct tcphdr));
    ip_head->id = htons(36521);
    ip_head->frag_off = htons(16384);
    ip_head->ttl = 64;
    ip_head->protocol = IPPROTO_TCP;
    ip_head->check = 0;
    ip_head->saddr = inet_addr(client_ip);
    ip_head->daddr = server_ip.s_addr;
    ip_head->check = compute_checksum((unsigned short*)datagram, ip_head->tot_len >> 1);

    // Setup TCP header
    tcp_head->source = htons(46300); // Source port
    tcp_head->dest = htons(80);
    tcp_head->seq = htonl(1105024978);
    tcp_head->ack_seq = 0;
    tcp_head->doff = (sizeof(struct tcphdr) / 4);
    tcp_head->fin = 0;
    tcp_head->syn = 1; // Set SYN flag
    tcp_head->rst = 0;
    tcp_head->psh = 0;
    tcp_head->ack = 0;
    tcp_head->urg = 0;
    tcp_head->window = htons(14600); // Maximum window size
    tcp_head->check = 0;
    tcp_head->urg_ptr = 0;
}

// Print the scan result just like Nmap
void print_result(unsigned int port, enum port_status st) {
    printf("%d/tcp\t\t%s\n", port, (st == OPENED ? "open" : "closed"));
}

int tcp_ipv4_scan(char *domain, char *interface, int timeout, int port)
{
    // Open raw socket
    int sock_fd;

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock_fd < 0) {
        perror("Unable to create socket");
        return 1;
    }

    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("Unable to set socket interface");
        return 1;
    }

    // Prepare TCP/IP Header
    struct in_addr server_ip;
    server_ip.s_addr = inet_addr(domain);

    char ip_addr[MAX_IP_SIZE]; // Local IP address
    char datagram[DATAGRAM_BUF_SIZE];
    struct iphdr *ip_head = (struct iphdr*)datagram; // IP header
    struct tcphdr *tcp_head = (struct tcphdr*)(datagram + sizeof(struct ip)); // TCP header
    get_client_ip(interface, ip_addr);
    setup_datagram(datagram, server_ip, ip_addr, ip_head, tcp_head);

    struct sockaddr_in ip_dest;
    struct target_header th;
    struct pseudo_header psh;

    // Save target IP and port for later usage
    th.target_ip = server_ip;
    th.target_port = port;

    // Setup packet info
    ip_dest.sin_family = AF_INET;
    ip_dest.sin_addr.s_addr = server_ip.s_addr;

    // Setup TCP header
    tcp_head->dest = htons(port); // Set target port
    tcp_head->check = 0;

    // Configure pseudo header(needed for checksum)
    psh.source_addr = inet_addr(ip_addr);
    psh.dest_addr = ip_dest.sin_addr.s_addr;
    psh.plc = 0;
    psh.prt = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    // Copy TCP header into our pseudo header
    memcpy(&psh.tcp, tcp_head, sizeof(struct tcphdr));
    tcp_head->check = compute_checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

    int sock_raw;
    int saddr_size, data_size;
    struct sockaddr saddr;
    unsigned char *buf = (unsigned char*)malloc(BUF_SIZE);
    saddr_size = sizeof(saddr);

    // Create new raw socket
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock_raw < 0) {
        perror("Unable to create socket");
        exit(1);
    }

    int status = fcntl(sock_raw, F_SETFL, fcntl(socketfd, F_GETFL, 0) | O_NONBLOCK);

    if (status == -1){
    perror("calling fcntl");
    // handle the error.  By the way, I've never seen fcntl fail in this way
    }

    // Start receiving packets
    data_size = recvfrom(sock_raw, buf, BUF_SIZE, 0, (struct sockaddr*)&saddr, (socklen_t*)&saddr_size);
    if(data_size < 0) {
        perror("Unable to receive packets");
        exit(1);
    }

    // Send packet to target
    if(sendto(sock_fd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&ip_dest, sizeof(ip_dest)) < 0) {
        perror("Unable to send SYN packet");
        return 1;
    }

    close(sock_fd);


    // Process data
    struct iphdr *ip_head2 = (struct iphdr*)buf;
    struct sockaddr_in source;
    unsigned short ip_head_len = ip_head2->ihl*4;
    struct tcphdr *tcp_head2 = (struct tcphdr*)(buf + ip_head_len);
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_head2->saddr;

    if(ip_head2->protocol == IPPROTO_TCP) {
        // Now check whether it's a SYN-ACK packet or not
        if(tcp_head2->syn == 1 && tcp_head2->ack == 1 && source.sin_addr.s_addr == th.target_ip.s_addr)
            print_result(port, OPENED);
        else
            print_result(port, CLOSED);
    }
    free(buf);

    return 0;
}
