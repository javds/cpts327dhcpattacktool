
#ifndef GENERAL_UTILS_C
#define GENERAL_UTILS_C
//
// Created by javds on 12/6/24.
//
#include "general_utils.h"
void linuxPause(void)
{
    printf("press enter to continue\n");
    getchar();
    return;
}

bool withinBounds(int given, int lowerBound, int upperBound)
{
    if (lowerBound > upperBound)
    {
        return false;
    }
    if (given >= lowerBound && given <= upperBound)
    {
        return true;
    }

    return false;
}


bool isChrHex(char input) {
    switch (input)
    {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return true;
        break;
    default:
        return false;
        break;
    }
}

bool isStrHex(char* input)
{
    if (input == NULL)
    {
        return false;
    }

    int nonhexChars = 0;
    for (int i = 0; i < strlen(input); i++)
    {
        if (!isChrHex(input[i]))
        {
            return false;
        }
    }
    return true;
}

int strReplaceWith(char* input, char toReplace, char replaceWith)
{
    int replaced = 0;
    for (int i = 0; i < strlen(input); i++)
    {
        if (input[i] == toReplace)
        {
            ++replaced;
            input[i] = replaceWith;
        }
    }
    return replaced;
}

unsigned int hexToInt(char input)
{
    switch (input)
    {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
        return 4;
    case '5':
        return 5;
    case '6':
        return 6;
    case '7':
        return 7;
    case '8':
        return 8;
    case '9':
        return 9;
    case 'A':
        return 10;
    case 'B':
        return 11;
    case 'C':
        return 12;
    case 'D':
        return 13;
    case 'E':
        return 14;
    case 'F':
        return 15;
    case 'a':
        return 10;
    case 'b':
        return 11;
    case 'c':
        return 12;
    case 'd':
        return 13;
    case 'e':
        return 14;
    case 'f':
        return 15;
        break;
    }

    return -1;
}


unsigned char convertCharToHex(unsigned char first, unsigned char second)
{
    int firstInt = hexToInt(first);
    int secondInt = hexToInt(second);

    if (withinBounds(firstInt, 0, 15) && withinBounds(secondInt, 0, 15))
    {
        return (firstInt << 4) | secondInt;
    }
    else
    {
        return 0;
    }
}

char* attackIntToString(int attack)
{
    switch (attack)
    {
    case 1:
        return "OFF";
        break;
    case 2:
        return "DOS";
        break;
    case 3:
        return "DHCP EXHAUSTION";
        break;
    case 4:
        return "MAC FLAPPING";
        break;
    default:
        return "INVALID ATTACK PARAM";
        break;
    }
}

void printHexArray(unsigned char* input, int length)
{
    for (int i = 0; i < length; ++i)
    {
     printf("%02X", input[i]);
    }
}

char* boolToString(bool input)
{
    if (input)
    {
        return "true";
    }
    return "false";
}

int stringToHex(unsigned char* dest, const char* src, int length)
{
    // Validate inputs
    if (src == NULL || dest == NULL || length <= 0)
    {
        fprintf(stderr, "inputs not valid");
        return -1; // Invalid input
    }

    int srclen = strlen(src);
    /*if (srclen < length) // Ensure source length is sufficient
    {
        fprintf(stderr, "string too short");
        return -1; // Source string too short
    }*/

    if (length % 2 != 0) // Hex string must have even length
    {
        fprintf(stderr, "invalid length");
        return -1; // Invalid length
    }

    int finalStringLength = 0;

    // Process each pair of hex characters
    for (int i = 0; i < srclen; i += 2)
    {
        unsigned int byte;
        // Read two hex characters and convert to a byte
        if (sscanf(src + i, "%2x", &byte) != 1)
        {
            fprintf(stderr, "hex conversion error");
            return -1; // Conversion error
        }
        dest[i / 2] = (unsigned char)byte; // Store in destination buffer
        ++finalStringLength;
    }

    return finalStringLength; // Return number of bytes written
}

bool isOdd(int input)
{
    if (input%2 == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void copyUnsignedCharN(unsigned char *packet, unsigned char *src, int src_len)
{
    for(int i = 0; i < src_len; ++i)
    {
        packet[i] = src[i];
    }
    return;
}

void copyUnsignedCharPosToN(unsigned char *packet, int packetPos, unsigned char *src, int src_len)
{
    packet  = (packet + packetPos); //get packet to its position it needs to start at
    for(int i = 0; i < src_len; ++i)
    {
        packet[i] = src[i];
    }
}


#endif