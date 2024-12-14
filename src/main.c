#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>  //sockaddr_ll
#include <net/if.h>            //for ifreq to get interface index and MAC address i think
#include <netinet/if_ether.h>  //ethernet header definitions (ETH_P_ALL)
#include <arpa/inet.h>
#include <pthread.h> //for threading
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>

#include "UI_utils.h" //tools for the CLI UI
#include "objects.h" //custom objects we are using
#include "netcode.h" //network code where network threads will be run

//https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
//https://www.linuxquestions.org/questions/programming-9/raw-socket-programming-with-c-503513/
//https://gist.github.com/INT0x00/a93af8c62851932844ca351ade25e971


void payload();
void payload(int port);



int main(void)
{
  //start the statistics server for the UI stuff have the threads wait till enough data is inputted to start.
 DhcpStats* stats = malloc(sizeof(DhcpStats));


  initDhcpStats(stats); //initialize the statistics struct

 //create the threads that will be used
 pthread_t thread_IOuser; //manages the IO of the user updates the dhcp stats
 pthread_t thread_TX; //transmits the IO from the socket
 pthread_t thread_RX; //receives the IO from the socket

    bool IOuserFlag = false;
    bool TXflag = false;
    bool RXflag = false;

    //start the threads begin initialization of attack script
    if (pthread_create(&thread_IOuser, NULL, ioThread, (void*)stats) != 0)
    {
        fprintf(stderr, "Error creating thread read IO\n");
        return 1;
    }
    IOuserFlag = true;

    //keep waiting for raw socket to be good to go
    bool waitForInterface = true;
    while (waitForInterface)
    {
        if ((*stats).interfaceSet || (*stats).serverRunning == false)
        {
            waitForInterface = false;
            break;
        }

        sleep(1);
    }

    if ((*stats).serverRunning == true)//only start the server if server set to running
    {
        sleep(2);
        printf("creating the socket\n");
        int fdHolder = createRawSocket((*stats).interfaceID);
        (*stats).serverFD = fdHolder;
        if (fdHolder <= 0)//check for failures
        {
            (*stats).interfaceSet = false;
            memset((*stats).interfaceID,0,1022);
            strcpy((*stats).errorMessage, "Error creating socket give new socket name please\n");
        }
        else
        {
            (*stats).serverFD = fdHolder;
            memset((*stats).errorMessage, 0, sizeof((*stats).errorMessage));
        }


        sleep(2);
        printf("creating the threads\n");
        //start the attack server TX thread
        if (pthread_create(&thread_TX, NULL, writeNetThread, (void*)stats) != 0)
        {
            fprintf(stderr, "Error creating thread TX\n");
            return 1;
        }
        TXflag = true;
        //start the attack server rx thread
        if (pthread_create(&thread_RX, NULL, readNetThread, (void*)stats) != 0)
        {
            fprintf(stderr, "Error creating thread RX\n");
            return 1;
        }
        RXflag = true;
    }

    //only call join on stuff that is actually running
    if (IOuserFlag == true)
    {
        pthread_join(thread_IOuser, NULL);
    }
    if (TXflag == true)
    {
        pthread_join(thread_TX, NULL);
    }
    if (RXflag == true)
    {
        pthread_join(thread_RX, NULL);
    }


  //delete dynamically allocated data
  free(stats);
  return 0;
}

