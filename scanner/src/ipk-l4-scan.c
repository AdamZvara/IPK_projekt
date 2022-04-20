/**
 * @brief   Simple TCP/UDP port scanner 
 * @author  xzvara01(@vutbr.cz)
 * @file    ipk-l4-scan.c
 * @date    20.04.2022
 */

#include <stdio.h>
#include "parse_args.h" // struct arguments
#include "tcp_scan.h"   // scanner functions

/* Global variables */
pcap_t *handle;

/**
 * @brief Print status of single scanned port
 * 
 * @param[in] portnum   Port number
 * @param[in] status    Status of port
 * @param[in] protocol  Protocol type to be printed
 */
void print_status(int portnum, enum port_status status, char *protocol);

/**
 * @brief Print status of every opened scanned port (exclude closed and filtered ports)
 * 
 * @see print_status_all
 */
void print_status_opened(int portnum, enum port_status status, char *protocol);


int main(int argc, char const *argv[])
{
    struct arguments *user_args;
    user_args = parse_args(argc, (char **)argv);
    // print_args(*user_args);

    /* Prepare pcap handle for capturing responses from server */
    char error_buffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(user_args->interface, BUFSIZ, 0, 100, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", error_buffer);
        return 1;
    }

    printf("Interesting ports on %s:\n", user_args->domain);
    printf("PORT\tSTATE\n");

    enum port_format pformat;
    enum port_status pstatus;
    
    /* TCP (IPv4) scanning */
    if ((pformat = user_args->tcp_type) != 0) {    // check if user asked for any TCP ports
        if (pformat == CONT) {
            for (int i = user_args->tcp.start; i <= user_args->tcp.end; i++) {
                pstatus = tcp_ipv4_scan(*user_args, i);
                print_status(i, pstatus, "tcp");
            }
        } else {
            for (int i = 0; i < user_args->tcp.array_length; i++) {
                pstatus = tcp_ipv4_scan(*user_args, user_args->tcp.array[i]);
                print_status(user_args->tcp.array[i], pstatus, "tcp");
            }
        }
    }

    if ((pformat = user_args->udp_type) != 0) {    // check if user asked for any UDP ports
        if (pformat == CONT) {
            for (int i = user_args->udp.start; i <= user_args->udp.end; i++) {
                //pstatus = tcp_ipv4_scan(*user_args, i);
                printf("scanning UDP %d\n", i);
                print_status(i, pstatus, "udp");
            }
        } else {
            for (int i = 0; i < user_args->udp.array_length; i++) {
                //pstatus = tcp_ipv4_scan(*user_args, user_args->tcp.array[i]);
                printf("scanning UDP %d\n", user_args->udp.array[i]);
                print_status(user_args->udp.array[i], pstatus, "udp");
            }
        }
    }

    free_args(user_args);
    pcap_close(handle);
    
    return 0;
}

void print_status(int portnum, enum port_status status, char *protocol)
{
    printf("%d/%s\t", portnum, protocol);
    switch (status) {
        case OPENED:
            printf("opened\n");
            break;

        case CLOSED:
            printf("closed\n");
            break;

        case FILTERED:
            printf("filtered\n");
            break;
        
        default:
            printf("error occured\n");
            break;
    }
}

void print_status_opened(int portnum, enum port_status status, char *protocol)
{
    if (status == OPENED) {
        printf("%d/%s\t", portnum, protocol);
        printf("opened\n");
    }
}