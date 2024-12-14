#ifndef UI_UTILS_C
#define UI_UTILS_C
#include "UI_utils.h"
#include "general_utils.h"
#include "objects.h"

void ioThread(DhcpStats* stats)
{
    char inputBuffer[256];

    while ((*stats).serverRunning == true)
    {
        printf("\033[2J\033[H"); // Clear the screen and reset cursor position
        printf("DHCP attack tool menu\n");
        printf("------------------------------\n");

        pthread_mutex_lock(&stats->lock); // Lock before reading shared data

        // is DHCP suppression working UI stuff
        printf("is DHCP attack mode working? %s\n", boolToString(attackMACReady(stats)));
        printf("attack network interface set to: %s\n", (*stats).interfaceID);
        printf("DHCP attack mode set to %s\n", attackIntToString((*stats).dhcpAttackMode));
        printf("attacking MAC address  set to ");
        printHexArray((*stats).hexTargetMacAddress, 6); // 6 here is the size in bytes of a MAC address
        printf("\n");

        printf("src Mac address set to ");
        printHexArray((*stats).myMacAddress, 6);
        printf("\n");


        // is DHCP responder working UI stuff
        printf("is DHCP responder working? %s\n", boolToString(respondDHCPReady(stats)));
        printf("ip base set to: %s\n", (*stats).ipBase);
        printf("subnet mask set to: %i\n", (*stats).subnetMask);
        printf("default Gateway set to: %s\n", (*stats).defaultGateway);
        printf("DNS set to: %s\n", (*stats).providedDNS);

        if ((*stats).errorMessage != NULL) // encountered error somewhere print this out
        {
            printf("Error message: %s\n", (*stats).errorMessage);
        }

        pthread_mutex_unlock(&stats->lock); // Unlock after reading shared data

        printf("------------------------------\n");

        // main if statement blocks
        printf("Type 'q' to quit. 'h' for help\n");

        memset(inputBuffer, 0, sizeof(inputBuffer));
        fflush(stdout);
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        inputBuffer[strcspn(inputBuffer, "\n")] = 0;

        // buffers for commands and arguments
        char command[1024] = {0};
        char commandArg[1024] = {0};

        // Extract the command and optional argument
        int args = sscanf(inputBuffer, "%s %s", command, commandArg);

        if (args < 1) // No valid command was entered
        {
            printf("Invalid input. Please try again.\n");
            printf("\033[u");
            fflush(stdout); // Ensure immediate output
            continue;
        }

        // Handle commands without arguments
        if (strcmp(command, "h") == 0 || strcmp(command, "H") == 0)
        {
            printf("\033[2J\033[H");
            printHelp();
            linuxPause();
            printf("\033[u"); // Restore cursor position
            fflush(stdout);    // Ensure immediate output
            continue;
        }

        if (strcmp(command, "q") == 0 || strcmp(command, "Q") == 0)
        {
            pthread_mutex_lock(&stats->lock);
            (*stats).serverRunning = false;
            pthread_mutex_unlock(&stats->lock);
            continue;
        }

        // Handle commands with arguments
        if (args == 2)
        {
            if (strcmp(command, "suppressmode") == 0)
            {
                int mode = atoi(commandArg);
                if (mode < 1 || mode > 4) // Check bounds
                {
                    printf("Invalid mode. Please enter a value between 1 and 4.\n");
                    printf("\033[u");
                    fflush(stdout); // Ensure immediate output
                    continue;
                }
                pthread_mutex_lock(&stats->lock);
                (*stats).dhcpAttackMode = mode;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "targetmacaddress") == 0)
            {
                pthread_mutex_lock(&stats->lock);
                stringToHex((*stats).hexTargetMacAddress, commandArg, 6);
                (*stats).targetMacSet = true;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "ipbase") == 0)
            {
                pthread_mutex_lock(&stats->lock);
                strncpy((*stats).ipBase, commandArg, sizeof((*stats).ipBase) - 1);
                (*stats).ipBaseSet = true;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "subnetmask") == 0)
            {
                int mask = atoi(commandArg);
                if (mask < 1 || mask > 32)
                {
                    printf("Invalid subnet mask. Please enter a value between 1 and 32.\n");
                    linuxPause();
                    continue;
                }
                pthread_mutex_lock(&stats->lock);
                (*stats).subnetMaskSet = true;
                (*stats).subnetMask = mask;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "defaultgateway") == 0)
            {
                pthread_mutex_lock(&stats->lock);
                strncpy((*stats).defaultGateway, commandArg, sizeof((*stats).defaultGateway) - 1);
                (*stats).defaultGatewaySet = true;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "dns") == 0)
            {
                pthread_mutex_lock(&stats->lock);
                strncpy((*stats).providedDNS, commandArg, sizeof((*stats).providedDNS) - 1);
                (*stats).providedDNSSet = true;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "srcmac") == 0)
            {
                pthread_mutex_lock(&stats->lock);
                stringToHex((*stats).myMacAddress, commandArg, 6);
                (*stats).myMacSet = true;
                pthread_mutex_unlock(&stats->lock);
            }
            else if (strcmp(command, "attackinterface") == 0)
            {
                pthread_mutex_lock(&stats->lock);
                strncpy((*stats).interfaceID, commandArg, 1022);
                (*stats).interfaceSet = true;
                pthread_mutex_unlock(&stats->lock);
            }
            else
            {
                printf("Unknown command with argument: %s\n", command);
                printf("\033[u");
                fflush(stdout); // Ensure immediate output
            }
        }
        else
        {
            printf("Unknown or incomplete command: %s\n", command);
            printf("\033[u");
            fflush(stdout); // Ensure immediate output
        }

        printf("\033[u"); // Restore cursor position
        fflush(stdout); // Ensure immediate output

    }
    return;
}

void printHelp()
{
    printf("list of commands:\n");
    printf("suppressmode <integer> 1 = off, 2 = dos, 3 = dhcp exhaustion, 4 = mac flapping\n");
    printf("suppressmode is to set how dhcp will be suppressed and to set its suppression target\n");

    printf("\n");

    printf("targetmacaddress <hex code here> \n");
    printf("target mac address command used to tell what dhcp server to suppress\n");
    printf("give this in proper hex format 0xFFFFFFFF etc.\n");

    printf("\n");

    printf("ipbase <name of ip network to generate from>\n");
    printf("ipbase command gives base name of network eg 192.168.0.0\n");

    printf("\n");

    printf("subnetmask <integer 1-32>\n");
    printf("sets the mask of the network to generate an ip address to assign\n");

    printf("\n");

    printf("defaultgateway <standard ip address>\n");
    printf("sets the default gateway dhcp parameter\n");

    printf("\n");

    printf("dns <standard ip address>\n");
    printf("sets the default dns parameter for dhcp\n");

    printf("\n");

    printf("srcmac <mac address>\n");
    printf("sets the default mac address parameters to use\n");

    printf("\n");

    printf("attackinterface <interface to use>\n");
    printf("sets the default interface to use use forms from ifconfig like eth0\n");

    printf("\n");
    return;
}

#endif