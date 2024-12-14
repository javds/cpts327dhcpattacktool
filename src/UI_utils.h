#ifndef UI_UTILS_H
#define UI_UTILS_H
#include <pthread.h> //for threading
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "UI_utils.h"

#include "objects.h"




void ioThread(DhcpStats* stats); //allowed to edit the stats

void printHelp();

#endif