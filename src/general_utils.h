//
// Created by javds on 10/11/24.
//

#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "UI_utils.h"
#include "general_utils.h"
#include "objects.h"

void linuxPause(void);

bool withinBounds(int given, int lowerBound, int upperBound);

bool isChrHex(char input);

bool isStrHex(char* input);

int strReplaceWith(char* input, char toReplace, char replaceWith);

unsigned int hexToInt(char input);

unsigned int setLeft4bits(unsigned int x);

unsigned int setRight4bits(unsigned int x);

unsigned char convertCharToHex(unsigned char first, unsigned char second);

char* attackIntToString(int attack);

void printHexArray(unsigned char* input, int length);

char* boolToString(bool input);

int stringToHex(unsigned char* dest, const char* src, int length);

bool isOdd(int input);

void copyUnsignedCharN(unsigned char *packet, unsigned char *src, int src_len);

void copyUnsignedCharPosToN(unsigned char *packet, int packetPos, unsigned char *src, int src_len);


#endif //GENERAL_UTILS_H
