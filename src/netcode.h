#ifndef NETCODE_H
#define NETCODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>             // For close()
#include <sys/socket.h>         // For socket functions
#include <netinet/if_ether.h>   // For Ethernet header definitions
#include <arpa/inet.h>          // For htons()
#include <net/if.h>             // For interface structures
#include <sys/ioctl.h>          // For ioctl()
#include <netpacket/packet.h>    // For sockaddr_ll
#include <errno.h>              // For errno

#include "general_utils.h"
#include "objects.h"
#define MTUMAX 1500


void writeNetThread(const DhcpStats* stats); //thead in charge of writing to the socket

void readNetThread(const DhcpStats* stats); //thread responsible of reading from the socket

int createRawSocket(const char *iface);

int sendRawPacket(int sockfd, const unsigned char *buffer, int size);

ssize_t receiveRawPacket(int sockfd, uint8_t *buffer, size_t size);

//create packets
int createDHCPExhaust(DhcpStats* stats, unsigned char* packet);

int createDHCflap(DhcpStats* stats, unsigned char* packet);

int createDHCPDos(DhcpStats* stats, unsigned char* packet);

int createDHCPOffer(DhcpStats* stats, unsigned char* packet, unsigned char* discover, int discover_len);

int createDHCPAck(DhcpStats* stats, unsigned char* packet, unsigned char* discover, int discover_len, unsigned char* offered_ip);

//netcode manipulators

bool isDHCPDiscovery(DhcpStats* stats, unsigned char* packet, int packet_len);

bool isDHCPRequest(unsigned char* packet, int packet_len);

void setSrcMac(unsigned char *packet, unsigned char *src, int src_len);

void setDSTMac(unsigned char *packet, unsigned char *src, int src_len);

void setIPType(unsigned char *packet, unsigned char *src, int src_len);

void setIPDest(unsigned char *packet, unsigned char *src, int src_len);


void setChecksum(unsigned char *packet);

void createRandomMac(unsigned char *mac); //expect this to be 6 bytes

void setSrcIp(unsigned char *packet, unsigned char *src, int src_len);



#endif //NETCODE_H
