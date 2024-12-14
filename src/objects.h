#ifndef OBJECTS_H327PROJ
#define OBJECTS_H327PROJ
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#define DHCP_ERROR_MSG_LEN 128



typedef struct dhcp_stats
{
  pthread_mutex_t lock;

  bool serverRunning; //should bet set to run till

  bool interfaceSet;
  char interfaceID[1024];

  //suppresssion stuff
  bool DOSready;
  int dhcpAttackMode; //1 = off, 2 = dos, 3 = dhcp exhaustion, 4 = mac flapping

  //attacking dhcp settings
  bool targetMacSet;
  unsigned char hexTargetMacAddress[7];

  bool myMacSet;
  unsigned char myMacAddress[7];

  //responding to DHCP settings
  bool serveDHCP; //is the dhcp responder active
  bool ipBaseSet;
  char ipBase[128];

  bool subnetMaskSet;
  int subnetMask;

  bool defaultGatewaySet;
  char defaultGateway[128];

  bool providedDNSSet;
  char providedDNS[128];

  //basic errors
  char errorMessage[1024];//error logging stuff for the user

  //socket stuff
  int serverFD;

} DhcpStats;




void initDhcpStats(DhcpStats *dhcpStats);

void freeDhcpStats(DhcpStats *dhcpStats);

bool attackMACReady(DhcpStats *stats);

bool respondDHCPReady(DhcpStats *stats);



static const unsigned char broadcastAddress[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const unsigned char headerChecksum[2] = {0x00, 0x00};

static const unsigned char UDPdesignator = 0x11;

static const unsigned char allZeroSrcAddress[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const unsigned char broadcastIPAddress[4] = {0xff, 0xff, 0xff, 0xff};



#endif