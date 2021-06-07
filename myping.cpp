// WRITTEN IN CPP
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define IPV4_HEADER_LENGTH 20
#define ICMP_HEADER_LENGTH 8
#define DESTINATION_IP "8.8.8.8"
#define DATA "This is the ping.\n"
#define DATA_LENGTH 19
using namespace std;

/*--------------------------------------------------------------------------------
            ************ Compute checksum (RFC 1071): ***************
--------------------------------------------------------------------------------*/
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int Length = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (Length > 1)
    {
        sum += *w++;
        Length -= 2;
    }

    if (Length == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

int main()
{
    /*--------------------------------------------------------------------------------
     ---------------------------Cooking the ICMP header: -----------------------------
    --------------------------------------------------------------------------------*/

    struct icmp icmpheader; // ICMP-header
    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmpheader.icmp_type = ICMP_ECHO;
    // Message Code (8 bits): echo request
    icmpheader.icmp_code = 0;
    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmpheader.icmp_id = 18;
    // Sequence Number (16 bits): starts at 0
    icmpheader.icmp_seq = 0;
    // ICMP header checksum (16 bits): set to 0 not to include checksum calculation
    icmpheader.icmp_cksum = 0;
    // Combine the packet
    char packet[IP_MAXPACKET];
    memcpy(packet, &icmpheader, ICMP_HEADER_LENGTH);
    // After ICMP header, add the ICMP data.
    memcpy((packet + ICMP_HEADER_LENGTH), DATA, DATA_LENGTH);
    // Calculate the ICMP header checksum using own function
    icmpheader.icmp_cksum = calculate_checksum((unsigned short *)packet, (ICMP_HEADER_LENGTH + DATA_LENGTH));
    memcpy(packet, &icmpheader, ICMP_HEADER_LENGTH);

    struct sockaddr_in PingDestination;
    memset(&PingDestination, 0, sizeof(struct sockaddr_in));
    PingDestination.sin_family = AF_INET;

    PingDestination.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs run by root user.\n\n");
        return -1;
    }

    /* Send the ICMP ECHO REQUEST packet: */

    struct timeval start, end;
    gettimeofday(&start, NULL);

    // Send the packet using sendto() to send it to the socket.
    int sent_size = sendto(sock, packet, (ICMP_HEADER_LENGTH + DATA_LENGTH), 0, (struct sockaddr *)&PingDestination, sizeof(PingDestination));
    if (sent_size == -1)
    {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("Sent one packet:\n");
    printf("\tSize: %d bytes: ICMP header(%d) + data(%d)\n", sent_size, ICMP_HEADER_LENGTH, DATA_LENGTH);
    printf("\tData: %s \n", packet + ICMP_HEADER_LENGTH);

    /* Receive the ICMP ECHO REPLY packet: */

    bzero(packet, IP_MAXPACKET);
    socklen_t len = sizeof(PingDestination);
    int get_size = -1;
    while (get_size < 0)
    {
        get_size = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&PingDestination, &len);
    }
    cout << endl
         << "Recieved one packet:" << endl;
    cout << "Size: " << get_size << " bytes IP HEADER LENGTH IS: " << IPV4_HEADER_LENGTH << " ICMP HEADER LENGTH IS: " << ICMP_HEADER_LENGTH << " DATA LENGTH SIZE IS: " << DATA_LENGTH;
    gettimeofday(&end, NULL);
    cout << endl
         << "Data:" << (packet + ICMP_HEADER_LENGTH + IPV4_HEADER_LENGTH) << endl;

    // second > milliseconds (10^(-3) seconds) > microseconds (10^(-6) seconds)
    float milliseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
    unsigned long microseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec);
    cout << "Round-trip time (RTT): " << milliseconds << " (milliseconds), " << microseconds << " (microseconds)" << endl;

    // Close the raw socket
    close(sock);
    return 0;
}
