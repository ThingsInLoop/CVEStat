/*
 * fstek.h
 *
 *  Created on: May 8, 2020
 *      Author: sasha
 */

#ifndef FSTEK_H_
#define FSTEK_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <curl/curl.h>

#ifndef PAGES_
#define PAGES_
struct all_pages {
	char* url;
	struct all_pages* next;
};
#endif

#ifndef DESCRS_
#define DESCRS_
struct descriptor {
	void* data;
	unsigned long index;
	unsigned char in_use;
};
#endif

#ifndef PRSTAT_
#define PRSTAT_
struct processing_stat {
	unsigned int is_l7;
	unsigned int is_l5;
	unsigned int is_l4;
	unsigned int is_l3;
	unsigned int is_l2;
	unsigned int is_other;
	unsigned int is_error;
};
#endif

#define FSTEK_MAX_PARALLEL			8
#define BDU_PAGE_PREFIX				"https://bdu.fstec.ru/vul?ajax=vuls&size=100&page="

#define HTML_END					"</html>"

#define FSTEK_SEARCHT_START			"table table-striped table-vuls"
#define FSTEK_SEARCHT_END			"link-pager"
#define FSTEK_SEARCHT_DATA			"<tr>"

#define SCORE_LOW					"bsc bsc-low"
#define SCORE_MIDDLE				"bsc bsc-middle"
#define SCORE_HIGH					"bsc bsc-high"
#define SCORE_CRITICAL				"bsc bsc-critical"

#define DESCRIPTORS_SIZE			(10 * MB)

int					fstek_main_processing			(int , struct processing_stat* , unsigned int* );
unsigned int		fstek_preparations				();

#endif /* FSTEK_H_ */
