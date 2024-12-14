#include "objects.h"



void initDhcpStats(DhcpStats *dhcpStats)
{
    pthread_mutex_init(&((*dhcpStats).lock), NULL);

    (*dhcpStats).serverRunning = true;

    //need the interface for the raw socket to work
    (*dhcpStats).interfaceSet = false;
    memset((*dhcpStats).interfaceID, 0, 1023);

    //basic suppression stuff
    (*dhcpStats).DOSready = false;
    (*dhcpStats).dhcpAttackMode = 1; //start in off mode
    (*dhcpStats).targetMacSet = false;
    memset((*dhcpStats).hexTargetMacAddress, 0, 6); //set the mac to be nothing

    (*dhcpStats).myMacSet = false;
    memset((*dhcpStats).myMacAddress, 0, 6); //set the mac to be nothing

    //dhcp responder stuff
    (*dhcpStats).serveDHCP = false;
    (*dhcpStats).ipBaseSet = false;
    memset(((*dhcpStats).ipBase), 0, 127);

    (*dhcpStats).subnetMaskSet = false;
    (*dhcpStats).subnetMask = 0;

    (*dhcpStats).defaultGatewaySet = false;
    memset(((*dhcpStats).defaultGateway), 0, 127);

    (*dhcpStats).providedDNSSet = false;
    memset(((*dhcpStats).providedDNS), 0, 127);

    memset(((*dhcpStats).errorMessage), 0, 1023);
    return;
}

void freeDhcpStats(DhcpStats *dhcpStats)
{
    pthread_mutex_destroy(&((*dhcpStats).lock));

    return;
}

bool attackMACReady(DhcpStats *stats)
{
    if ((*stats).targetMacSet)
    {
        return true;
    }
    return false;
}

bool respondDHCPReady(DhcpStats *stats)
{
    if ((*stats).ipBaseSet && (*stats).subnetMaskSet && (*stats).defaultGatewaySet && (*stats).providedDNSSet)
    {
        return true;
    }
    return false;
}