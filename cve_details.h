/*
 * cve_details.h
 *
 *  Created on: May 8, 2020
 *      Author: sasha
 */

#ifndef CVE_DETAILS_H_
#define CVE_DETAILS_H_

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

#define MAX_PARALLEL				16

#define URL_START					"https://www.cvedetails.com"
#define CVE_DETAILS_PAGES_NMB		(sizeof(CVE_DETAILS_PAGES) / sizeof(char*))

#define HTML_END					"</html>"
#define PADDING_START				"id=\"pagingb\""
#define PADDING_END					"id=\"footer"
#define PADDING_PAGE_ADDR_START		"href=\""
#define PADDING_PAGE_ADDR_END		"title=\"Go to page"

#define SEARCHT_START				"vulnslisttable"
#define SEARCHT_END					"pagingb"
#define SEARCHT_DATA				"srrowns"
#define SEARCHT_TEXT				"cvesummarylong"

int					cved_main_processing			(int , struct processing_stat* , unsigned int* );
unsigned int		cved_preparations				();

#endif /* CVE_DETAILS_H_ */
