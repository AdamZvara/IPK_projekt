/**
 * @brief 	Implementation of UDP scanning functions
 * @author  xzvara01(@vutbr.cz)
 * @file    udp_scan.c
 * @date    20.04.2022
 */

#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <netinet/udp.h>	    // struct udphdr
#include <netinet/ip.h>	        // struct iphdr
#include <netinet/ip_icmp.h>	// struct udphdr
#include "udp_scan.h"

/**
 * @brief Send UDP packet
 * 
 * @param[in] socket Socket descriptor
 * @param[in] domain Domain (IP address) to send packet to
 * @param[in] interface Name of interface to send packet from
 * @param[in] port Port number to send packet to 
 */
void send_ipv4_udp(int socket, char *domain, char *interface, int port)
{
    /* Bind socket to interface given by user */
    if ((setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface))) == -1) {
        perror("Unable to bind socket to given interface");
        exit(ERR);
    }

    // set destination port and address for connection
    struct sockaddr_in dst_address;
    dst_address.sin_family = AF_INET;
    dst_address.sin_port = htons(port);
    inet_pton(AF_INET, domain, &(dst_address.sin_addr.s_addr));  // convert string IP address

    /* Create UDP header */
    struct udphdr *udph = malloc(sizeof(struct udphdr));
    memset(udph, 0, sizeof(struct udphdr)); // initialize udp header

    udph->source = htons(SENDER_PORT);
    udph->dest = htons(port);
    udph->len = htons(sizeof(struct udphdr));

    /* Connect to given interface on given port and send packet*/
    if (connect(socket, (struct sockaddr*)&dst_address, sizeof(dst_address)) == -1) {
        perror("Unable to connect to address");
        exit(ERR);
    }

    sendto(socket, udph, sizeof(struct udphdr), 0, (struct sockaddr*)&dst_address, sizeof(dst_address));
}

p_status udp_ipv4_scan(struct arguments uargs, int port)
{
     /* Create raw socket which will be using UDP protocol */
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_fd == -1) {
        perror("Unable to create socket");
        exit(1);
    }

    /* Set pcap filter string */
    struct bpf_program fp;
    bpf_u_int32 netp, maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_lookupnet(uargs.interface, &netp, &maskp, errbuf);
    char *filter_string = set_filter_string(uargs, port, "icmp");

    if (pcap_compile(handle, &fp, filter_string, 0, netp) == -1) {
        perror("Error calling pcap_compile");
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        perror("Error setting filter");
        exit(1);
    }

    /* Send UDP packet */
    send_ipv4_udp(socket_fd, uargs.domain, uargs.interface, port);

    /* Prepare alarm signal to interrupt pcap_next
     *  
     * source: https://stackoverflow.com/questions/4583386/listening-using-pcap-with-timeout
     * author: lemonsqueeze
     */
    if (signal(SIGALRM, breakloop) == SIG_ERR) {
        perror("Unable to catch SIGALRM");
        exit(1);
    }

    struct itimerval time;
    time.it_interval.tv_sec = time.it_interval.tv_usec = 0;
    time.it_value.tv_sec = uargs.timeout / 1000;
    time.it_value.tv_usec = (uargs.timeout % 1000) * 1000;

    if (setitimer(ITIMER_REAL, &time, NULL) == -1) {
        perror("Unable to send SIGALRM");
        exit(1);
    }

    /* Catch response */
    struct pcap_pkthdr hdr;
    const u_char *packet;
    packet = pcap_next(handle, &hdr);
    if (packet == NULL) {
        pcap_freecode(&fp);
        close(socket_fd);
        return OPENED;
    }
    
    /* Get to ICMP header from incoming packet and check type */
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HEADER_LEN);
    int ip_header_length = ((ip->ihl) & 0xf) * 4;

    struct icmphdr* icmp_header = (struct icmphdr*) (packet + ETHER_HEADER_LEN + ip_header_length);
    if (icmp_header->type == 3) {
        pcap_freecode(&fp);
        close(socket_fd);
        return CLOSED;
    }
 
    pcap_freecode(&fp);
    close(socket_fd);

    return NONE;
}