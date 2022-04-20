#include <stdio.h>
#include <sys/socket.h>     // socket API
#include <netinet/in.h>     // sockaddr_in, in_addr
#include <netinet/tcp.h>	// struct tcphdr 
#include <netinet/ip.h>	    // struct tcphdr 
#include <arpa/inet.h>      // inet_ntoa
#include <net/if.h>         // if_nameindex
#include <netdb.h>          // gethostbyname
#include <sys/ioctl.h>      // ioctl
#include <pcap.h>           // pcap API
#include <signal.h>         // signal

#include "scanner.h"

// TESTING ZONE
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <time.h>
#include <unistd.h>

pcap_t *handle;

bool valid_address(char *address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, address, &(sa.sin_addr));
    if (result == 0) {
        result = inet_pton(AF_INET6, address, &(sa.sin_addr));
    }
    return result != 0;
}

char *resolve_domain(char *domain)
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
 * @brief get ip address of used interface for pseudo header
 * 
 * @return 32bit IP address of interface
 * 
 * source: https://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php 
 * author: Akimichi Ogawa 
 */
int get_interface_ip(int rtcp_socket, char *interface)
{
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(rtcp_socket, SIOCGIFADDR, &ifr);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

/**
 * @brief Calculate checksum of TCP header 
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

void breakloop(int signum) 
{
    (void) signum;
    pcap_breakloop(handle);
}

int send_ipv4_syn(int rtcp_socket, char *domain, char *interface, int port)
{
    // bind socket to interface given by user
    if ((setsockopt(rtcp_socket, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface))) == -1) {
        perror("Unable to bind socket to given interface");
        exit(1);
    }

    // set destination port and address for connection
    struct sockaddr_in dst_address;
    dst_address.sin_family = AF_INET;
    dst_address.sin_port = htons(port);
    inet_pton(AF_INET, domain, &(dst_address.sin_addr.s_addr));  // convert string IP address

    /***********************************************************************************************
    create TCP header
    source: https://www.binarytides.com/raw-sockets-c-code-linux/
    author: Silver Moon */
    struct tcphdr *tcph = malloc(sizeof(struct tcphdr));
    memset(tcph, 0, sizeof(struct tcphdr)); // initialize tcp header to 0s
    tcph->source = htons(SENDER_PORT);
	tcph->dest = htons(port);
	tcph->doff = 5;	                        // tcp header size
	tcph->syn = 1;                          // SYN flag
	tcph->window = htons(5840);	            // maximum allowed window size

    /* fill IP pseudo header */
	struct pseudo_header psh;
    psh.source_address = get_interface_ip(rtcp_socket, interface);
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
    /***********************************************************************************************/

    // connect to given interface on given port
    if (connect(rtcp_socket, (struct sockaddr*)&dst_address, sizeof(dst_address)) == -1) {
        perror("Unable to connect to address");
        exit(1);
    }

    // send first TCP packet with SYN FLAG
    sendto(rtcp_socket, tcph, sizeof(struct tcphdr), 0, (struct sockaddr*)&dst_address, sizeof(dst_address));

    free(tcph);
    free(pseudogram);

    return 0;
}


enum port_status tcp_ipv4_scan(char *domain, char *interface, int timeout, int port)
{
    /* create raw socket which will be using TCP protocol */
    /* IP header will be provided for us, we just need to create TCP header */
    int rtcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rtcp_socket == -1) {
        perror("Unable to create socket");
        exit(1);
    }

    /* setup pcap */
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct pcap_pkthdr hdr;
    const u_char *packet = NULL;
    struct bpf_program fp;

    pcap_lookupnet(interface, &netp, &maskp, errbuf);

    handle = pcap_open_live(interface, BUFSIZ, 0, 100, errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    // create string to filter out other traffic
    char filter_string[1024] = "tcp and src port ";
    char port_str[10] = "";
    snprintf(port_str, 10, "%d", port);
    strcat(filter_string, port_str);
    strcat(filter_string, " and dst port ");
    snprintf(port_str, 10, "%d", SENDER_PORT);
    strcat(filter_string, port_str);
    strcat(filter_string, " and src host ");
    strcat(filter_string, domain);
    strcat(filter_string, " and dst host ");
    int32_t IP_int = get_interface_ip(rtcp_socket, interface);
    char IP_str[IP_LENGTH];
    strcat(filter_string, inet_ntop(AF_INET, &IP_int, IP_str, IP_LENGTH));

    if (pcap_compile(handle, &fp, filter_string, 0, netp) == -1) { 
        perror("Error calling pcap_compile"); 
        exit(1); 
    }

    if (pcap_setfilter(handle, &fp) == -1) { 
        perror("Error setting filter"); 
        exit(1); 
    }

    // send SYN packet
    send_ipv4_syn(rtcp_socket, domain, interface, port);

    /* prepare alarm signal to interrupt pcap_next waiting for next packet 
       idea taken from: https://stackoverflow.com/questions/4583386/listening-using-pcap-with-timeout
       author: lemonsqueeze
    */
    if (signal(SIGALRM, breakloop) == SIG_ERR) {
        perror("Unable to catch SIGALRM");
        exit(1);
    }  

    struct itimerval time;
    time.it_interval.tv_sec = time.it_interval.tv_usec = 0;
    time.it_value.tv_sec = timeout / 1000;
    time.it_value.tv_usec = (timeout % 1000) * 1000;

    if (setitimer(ITIMER_REAL, &time, NULL) == -1) {
        perror("Unable to send SIGALRM");
        exit(1);
    }

    // catch response
    packet = pcap_next(handle, &hdr);
    if (packet == NULL) {
        // no packet found, try to resend packet
        send_ipv4_syn(rtcp_socket, domain, interface, port);

        if (setitimer(ITIMER_REAL, &time, NULL) == -1) {
            perror("Unable to send SIGALRM");
            exit(1);
        }

        packet = pcap_next(handle, &hdr);
        if (packet == NULL) {
            pcap_freecode(&fp);
            pcap_close(handle);
            close(rtcp_socket);
            return FILTERED;
        }
    }

    //trying to get to TCP header from incoming packet, but first we need IP header size
    if (packet != NULL) {
        struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_LEN);
        int ip_header_length = ((ip->ihl) & 0xf) * 4;

        struct tcphdr* tcp_header = (struct tcphdr*) (packet + ETHER_HDR_LEN + ip_header_length);
        if(tcp_header->rst == 1 && tcp_header->ack == 1){
            pcap_freecode(&fp);
            pcap_close(handle);
            close(rtcp_socket);
            return CLOSED;
        }
        else if(tcp_header->rst == 0 && tcp_header->ack == 1){
            pcap_freecode(&fp);
            pcap_close(handle);
            close(rtcp_socket);
            return OPENED;
        }
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    close(rtcp_socket);

    return NONE;
}