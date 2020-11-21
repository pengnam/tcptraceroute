# tcptraceroute

## Background

traceroute utilizes a trick in the IP header. It sets the TTL field of the header to limit the number of hops that a packet take before it is dropped. When it is dropped, the router sends a ICMP packet to notify the sender that the packet has dropped. 

Typically, traceroute tools send either an ICMP ping packet or a UDP packet. However, given that most modern firewalls blocks UDP or ICMP messages, it limits the effectiveness of these tools.

This implementation sends a TCP SYN packet instead.

A few friends had to do it for a class project, which I thought was interesting to do on my own.

My design is simple: use `connect` call on a tcp socket to send the syn packet, and read the ICMP message through a raw ICMP socket.


## Comparison against other tools
There are other users that wrote a tcptraceroute implementation.


The original implementation is [here](https://github.com/mct/tcptraceroute/).

A friend wrote [this](https://github.com/rrtheonlyone/traceroute/blob/master/main.c). 

They both have the same design: custom syn packet with `pcap` library to retrieve and parse the received packets.

I'm personally a fan of simple things that work as intended. The advantage is that there is no need for external libraries, and code is easier to understand as a simple `connect` call replaces the custom crafted TCP message. 

At the time of writing, my code is 150 lines while my friend's code and Michael's code are at least 700 lines.

I have written an implementation that used custom TCP messages, and the snippet of code used to create the custom TCP messages is at the bottom of the README. I found that it does the same as this implementation.


## Set-up

To set-up, run make. It has been tested to work on an Ubuntu system and a MacOSX Catalina 10.15.7.

## Appendix

```

void sendTcpSynPacket(std::string & dstAddr) {
  int connection = getConnection();
  std::cout << "First connection: " << connection << std::endl;

  ip ipHeader;
  ipHeader.ip_v = 4;
  //==========CHANGE=======
  ipHeader.ip_ttl = 2;
  //==========ENDCHANGE=======
  ipHeader.ip_hl = 5;
  ipHeader.ip_tos = 0;
  ipHeader.ip_id = htons(rand() % 65535);
  ipHeader.ip_p = IPPROTO_TCP;
  ipHeader.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
  inet_pton(AF_INET, dstAddr.c_str(), &(ipHeader.ip_dst));



  tcphdr tcpHeader;
  //TODO: think about src and dst ports
  //======CHANGE======
  tcpHeader.th_sport = htons(12);
  tcpHeader.th_dport = htons(80);
  //======ENDCHANGE======
  tcpHeader.th_seq = htonl(0);
  tcpHeader.th_ack = htonl(0);
  tcpHeader.th_flags = TH_SYN;
  tcpHeader.th_win = htons(500);
  tcpHeader.th_off = 5;
  tcpHeader.th_sum = 0;
  tcpHeader.th_x2 = 0;
  tcpHeader.th_urp = htons(0);

  ipHeader.ip_sum = ip_checksum(ipHeader);
  tcpHeader.th_sum = tcp_checksum(tcpHeader, ipHeader);

  char * buffer = (char *) malloc(sizeof(tcpHeader));
  memcpy(buffer, &tcpHeader, sizeof(tcpHeader));

  char * header = (char *) malloc(sizeof(tcpHeader) + sizeof(ipHeader));
  memcpy(header, &ipHeader, sizeof(ipHeader));
  memcpy(header + sizeof(ipHeader), &tcpHeader, sizeof(tcpHeader));

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(12);
  sin.sin_addr.s_addr = inet_addr(dstAddr.c_str());

  if (sendto(connection, header, ipHeader.ip_len, 0, (struct sockaddr *)&sin,
             sizeof(sin)) < 0) {
    perror("sendto failed");
    return;
  }
}


unsigned short tcp_checksum(tcphdr& tcpHeader, ip & ipHeader) {
      //add pseudo header
    struct pseudo_header {
        struct in_addr src;
        struct in_addr dest;
        u_char padding;
        u_char protocol;
        u_short length;
    } ph;

    ph.src = ipHeader.ip_src;
    ph.dest = ipHeader.ip_dst;
    ph.padding = 0;
    ph.protocol = ipHeader.ip_p;
    ph.length = htons(sizeof(struct tcphdr));
    size_t len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);

    char * pseudo_pkt = (char *) malloc(len);
    if (pseudo_pkt == NULL) {
        perror("error in allocation");
        exit(EXIT_FAILURE);
    }

    memcpy(pseudo_pkt, &ph, sizeof(ph));
    memcpy(pseudo_pkt + sizeof(ph), &tcpHeader, sizeof(struct tcphdr));
    return checksum((unsigned short *)pseudo_pkt, len);

}



```
