#include <stdio.h>
#include <sys/socket.h>     // socket APIs
#include <netinet/in.h>     // sockaddr_in, in_addr
#include <netinet/tcp.h>	// struct tcphdr 
#include <arpa/inet.h>      // inet_ntoa
#include <net/if.h>         // if_nameindex
#include <netdb.h>          // gethostbyname
#include <sys/ioctl.h>      // ioctl

// TESTING ZONE
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <time.h>
#include <stdlib.h>

int main()
{
    // setup pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp; /* ip          */
    bpf_u_int32 maskp;/* subnet mask */
    struct in_addr addr;
    pcap_t* descr;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    const u_char *packet;
    int i;
    struct bpf_program fp;      /* hold compiled program     */

    u_char *ptr; /* printing out hardware header info */

    pcap_lookupnet("enp0s3",&netp,&maskp,errbuf);
    addr.s_addr = netp;
    addr.s_addr = maskp;


    descr = pcap_open_live("enp0s3",BUFSIZ,0,1,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    if(pcap_compile(descr,&fp,"src port 21",0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    packet = pcap_next(descr,&hdr);
    if(packet == NULL)
    {/* dinna work *sob* */
        printf("Didn't grab packet\n");
        exit(1);
    }

    printf("Grabbed packet of length %d\n",hdr.len);
    printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec)); 
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    printf("Grabbed packet of length %d\n",hdr.len);
    printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec)); 
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    /* Do a couple of checks to see what packet type we have..*/
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    }else {
        printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        exit(1);
    }

    /* copied from Steven's UNP */
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf(" Destination Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

}