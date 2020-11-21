#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

#define UNUSED_PORT 1024
#define BUFFER_SIZE 1000

struct sockaddr* find_usable_addr(const char* url) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;

    struct addrinfo* res; 
    
    struct sockaddr* dest_addr; 
    if (getaddrinfo(url, NULL, &hints, &res) > 0) {
        perror("Unable to resolve address");
        exit(EXIT_FAILURE);
    }

    dest_addr = calloc(1, sizeof(struct sockaddr));
    memcpy(dest_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return dest_addr;
}

void send_tcp_syn_packet(int send_socket, struct sockaddr* send_addr, int ttl) {
    errno = 0;
    struct sockaddr_in dest_addr; 
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(UNUSED_PORT);
    dest_addr.sin_addr = ((struct sockaddr_in * ) send_addr)->sin_addr;
    setsockopt(send_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    connect( send_socket, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr));
}

bool read_icmp(int icmp_sock, int ttl) {
  char buffer[BUFFER_SIZE];
  bzero(buffer, BUFFER_SIZE);
  struct sockaddr_in cliaddr;
  socklen_t socklen = sizeof(cliaddr);
  if (recvfrom(icmp_sock, buffer, BUFFER_SIZE, 0, (struct sockaddr * ) &cliaddr, &socklen) < 0) {
        printf("%d: ERROR: %s\n", ttl, strerror(errno));
        return false;
  }
  
  // 1. IP HEADER
  struct ip *ip_hdr = (struct ip *)buffer;
  int ip_hdr_length = 4 * ip_hdr -> ip_hl;
  
  // 2. ICMP HEADER
  struct icmp * icmp_hdr = (struct icmp * ) (buffer + ip_hdr_length);
  if (icmp_hdr->icmp_type == ICMP_TIMXCEED && icmp_hdr->icmp_code == ICMP_UNREACH_NET) {
      printf("%d %s\n", ttl, inet_ntoa(ip_hdr->ip_src));
      return true;
  } else if (icmp_hdr->icmp_type == ICMP_UNREACH){
      printf("%d %s[DESTINATION]\n", ttl,inet_ntoa(ip_hdr->ip_src));
      return false;
  } else {
      printf("ERROR: %d %d\n",icmp_hdr->icmp_type, icmp_hdr->icmp_code);
      exit(EXIT_FAILURE);
  }
}


int main (int argc, char *argv[]){
    if (argc != 2) {
        printf("usage: tcptraceroute <URL>\n");
        exit(EXIT_FAILURE);
    }
    char * url = argv[1];
    struct sockaddr* result = find_usable_addr(url);

    printf("tcptraceroute to %s (%s)\n", url, inet_ntoa(((struct sockaddr_in*)result)->sin_addr));


    int send_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (send_socket < 0) {
        perror("Error creating tcp socket");
        exit(EXIT_FAILURE);
    }
     struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    if (setsockopt(send_socket, SOL_SOCKET, SO_SNDTIMEO,
            (struct timeval *)&timeout, sizeof(struct timeval))< 0 ) {
        perror("Error setting timeout for tcp socket");
        exit(EXIT_FAILURE);
    }

    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout, sizeof(struct timeval))) {
        perror("Error setting timeout for icmp socket");
        exit(EXIT_FAILURE);
    }

    for (int ttl = 1; ttl < 15; ttl ++ ){
        send_tcp_syn_packet(send_socket, result, ttl);
        if (errno == EINPROGRESS || errno == EALREADY || errno == ETIMEDOUT) {
            printf("%d * * * * * *\n", ttl);
        } else {
            if (!read_icmp(icmp_sock, ttl)) {
                printf("Completed\n");
                break;
            }
        }
    }
}