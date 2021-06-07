// WRITTEN IN C
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

int count = 0;
void got_packet(unsigned char *, int);

int main(int argc, char *argv[])
{

    printf("\n-----------------------------------------------------------\n");
    printf(" Sniffing ICMP packets...\n");
    printf("-----------------------------------------------------------\n");

    /*--------------------------------------------------------------------------------
        1)  Create the raw socket
    --------------------------------------------------------------------------------*/
    //  htons(ETH_P_ALL) is setting for apture all types of packets
    int raw_socket;
    if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("listener: socket");
        return -1;
    }

    /*--------------------------------------------------------------------------------
        2)  Turn on the promiscuous mode
    --------------------------------------------------------------------------------*/
    struct packet_mreq mr;
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    /*--------------------------------------------------------------------------------
        3)  Get captured packet
    --------------------------------------------------------------------------------*/
    char BUFFER[IP_MAXPACKET];
    while (1)
    {
        bzero(BUFFER, IP_MAXPACKET);
        int received = recvfrom(raw_socket, BUFFER, ETH_FRAME_LEN, 0, NULL, NULL);
        got_packet(BUFFER, received);
    }
}

void got_packet(unsigned char *buffer, int size)
{
    struct iphdr *IPV4_HEADER = (struct iphdr *)(buffer + ETH_HLEN);
    if (IPV4_HEADER->protocol == IPPROTO_ICMP)
    { /* Check if the captured packet is ICMP */

        unsigned short iphdrlen = IPV4_HEADER->ihl * 4;
        struct icmphdr *ICMP_HEADER = (struct icmphdr *)(buffer + ETH_HLEN + iphdrlen);

        char *icmp_type_names[] = {"Echo ping Reply", "Unassigned", "Unassigned", "Destination Unreachable",
                                   "Source Quench", "Redirect", "Alternate Host Address", "Unassigned",
                                   "Echo ping", "Router Advertisement", "Router Selection", "Time Exceeded"};

        unsigned int type = (unsigned int)(ICMP_HEADER->type);
        if (type < 11)
        {
            struct sockaddr_in SOURCE, DESTINATION;
            memset(&SOURCE, 0, sizeof(SOURCE));
            SOURCE.sin_addr.s_addr = IPV4_HEADER->saddr;
            memset(&DESTINATION, 0, sizeof(DESTINATION));
            DESTINATION.sin_addr.s_addr = IPV4_HEADER->daddr;

            printf("~~~~~~~~~~~~~~~~~~~~~~~~ICMP Packet %d~~~~~~~~~~~~~~~~~~~~~~~~\n", ++count);
            printf("\nIP HEADER:\n");
            printf("SOURCE IP: %s\n", inet_ntoa(SOURCE.sin_addr));
            printf("DESTINATION IP: %s\n", inet_ntoa(DESTINATION.sin_addr));
            printf("\nICMP HEADER:\n");
            printf("CODE: %d\n", (unsigned int)(ICMP_HEADER->code));
            printf("TYPE: %d - %s\n", (unsigned int)(ICMP_HEADER->type), icmp_type_names[type]);
        }
    }
}