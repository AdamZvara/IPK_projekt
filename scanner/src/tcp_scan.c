/**
 * @brief 	Implementation of TCP scanning functions
 * @author  xzvara01(@vutbr.cz)
 * @file    tcp_scan.c
 * @date    20.04.2022
 */

#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>	    // struct tcphdr
#include <netinet/ip.h>	        // struct iphdr
#include <sys/ioctl.h>          // ioctl

#include "tcp_scan.h"

/**
 * @brief Get IP address of used interface for pseudo header
 *
 * @return 32bit IP address of interface
 *
 * source: https://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php
 * author: Akimichi Ogawa
 */
uint32_t get_interface_ip(int socket, char *interface)
{
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(socket, SIOCGIFADDR, &ifr);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

/**
 * @brief Calculate generic checksum 
 * 
 * @return Calculated checksum
 *
 * source: https://www.binarytides.com/raw-sockets-c-code-linux/
 * author: Silver Moon
 */
unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

/* Event handler for SIGALRM used for stopping pcap_next */
void breakloop(int signum)
{
    (void) signum;
    pcap_breakloop(handle);
}

/**
 * @brief Send TCP packet with SYN flag set
 * 
 * @param[in] socket Socket descriptor
 * @param[in] domain Domain to send packet to
 * @param[in] interface Name of interface to send packet from
 * @param[in] port Port number to send packet to 
 */
void send_ipv4_syn(int socket, char *domain, char *interface, int port)
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

    /* Create TCP header
     * source: https://www.binarytides.com/raw-sockets-c-code-linux/
     * author: Silver Moon */
    struct tcphdr *tcph = malloc(sizeof(struct tcphdr));
    memset(tcph, 0, sizeof(struct tcphdr)); // initialize tcp header
    tcph->source = htons(SENDER_PORT);
	tcph->dest = htons(port);
	tcph->doff = 5;	                        // tcp header size
	tcph->syn = 1;                          // SYN flag
	tcph->window = htons(5840);	            // maximum allowed window size

    // fill IP pseudo header 
	struct pseudo_header psh;
    psh.source_address = get_interface_ip(socket, interface);
	psh.dest_address = dst_address.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char *pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));

    // calculate TCP header checksum
	tcph->check = csum( (unsigned short*) pseudogram , psize);

    /* Connect to given interface on given port and send packet*/
    if (connect(socket, (struct sockaddr*)&dst_address, sizeof(dst_address)) == -1) {
        perror("Unable to connect to address");
        exit(ERR);
    }

    sendto(socket, tcph, sizeof(struct tcphdr), 0, (struct sockaddr*)&dst_address, sizeof(dst_address));

    free(tcph);
    free(pseudogram);
}

/**
 * @brief Create string to filter out unwanted traffic
 * @details Example output string: tcp and src port 1234 and dst port 1234 and src host 127.0.0.1 and dst host 127.0.0.1
 * 
 * @param[in] uargs Program arguments
 * @param[in] port  Destination port number 
 * @param[in] socket_fd Socket descriptor
 * @param[in] protocol  Type of protocol
 * 
 * @return Pointer to static char array representing filter string
 */
char *set_filter_string(struct arguments uargs, int port, int socket_fd, char *protocol)
{
    static char filter_string[FILTER_STR_LEN];
    memset(filter_string, 0, FILTER_STR_LEN);

    strcat(filter_string, protocol);
    strcat(filter_string, " and src port ");
    char port_str[10] = "";
    snprintf(port_str, 10, "%d", port);
    strcat(filter_string, port_str);
    strcat(filter_string, " and dst port ");
    snprintf(port_str, 10, "%d", SENDER_PORT);
    strcat(filter_string, port_str);
    strcat(filter_string, " and src host ");
    strcat(filter_string, uargs.domain);
    strcat(filter_string, " and dst host ");
    int32_t IP_int = get_interface_ip(socket_fd, uargs.interface);
    char IP_str[INET6_ADDRSTRLEN];
    strcat(filter_string, inet_ntop(AF_INET, &IP_int, IP_str, INET6_ADDRSTRLEN));

    return filter_string;
}

p_status tcp_ipv4_scan(struct arguments uargs, int port)
{
    /* Create raw socket which will be using TCP protocol */
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (socket_fd == -1) {
        perror("Unable to create socket");
        exit(1);
    }

    /* Set pcap filter string */
    struct bpf_program fp;
    bpf_u_int32 netp, maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_lookupnet(uargs.interface, &netp, &maskp, errbuf);
    char *filter_string = set_filter_string(uargs, port, socket_fd, "tcp");

    if (pcap_compile(handle, &fp, filter_string, 0, netp) == -1) {
        perror("Error calling pcap_compile");
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        perror("Error setting filter");
        exit(1);
    }


    /* Send SYN packet */
    send_ipv4_syn(socket_fd, uargs.domain, uargs.interface, port);

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
        // no packet captured, resend packet with SYN flag
        send_ipv4_syn(socket_fd, uargs.domain, uargs.interface, port);

        if (setitimer(ITIMER_REAL, &time, NULL) == -1) {
            perror("Unable to send SIGALRM");
            exit(1);
        }

        packet = pcap_next(handle, &hdr);
        if (packet == NULL) {
            pcap_freecode(&fp);
            close(socket_fd);
            return FILTERED;
        }
    }

    /* Get to TCP header from incoming packet and check flags */
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HEADER_LEN);
    int ip_header_length = ((ip->ihl) & 0xf) * 4;

    struct tcphdr* tcp_header = (struct tcphdr*) (packet + ETHER_HEADER_LEN + ip_header_length);
    if(tcp_header->rst == 1 && tcp_header->ack == 1){
        pcap_freecode(&fp);
        close(socket_fd);
        return CLOSED;
    }
    else if(tcp_header->rst == 0 && tcp_header->ack == 1){
        pcap_freecode(&fp);
        close(socket_fd);
        return OPENED;
    }

    pcap_freecode(&fp);
    close(socket_fd);

    return NONE;
}