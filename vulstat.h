/*
 * vulstat.h
 *
 *  Created on: May 7, 2020
 *      Author: sasha
 */

#ifndef VULSTAT_H_
#define VULSTAT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <curl/curl.h>

#include "cve_details.h"

#define STAT_PREPARATION			1
#define STAT_PROCESSING				2
#define STAT_STOPPED				3

#endif /* VULSTAT_H_ */
