/*
 * vulstat.c
 *
 *  Created on: May 7, 2020
 *      Author: sasha
 */

#include "vulstat.h"

static unsigned int total_pages_nmb = 0;
static unsigned int current_page_nmb = 0;

static int cved_fp = 0;
//static int fstek_fp = 0;

static struct processing_stat statistics;

static unsigned char stats_state = 0;
time_t start_time = 0;

void *print_statistics();

int main(int argc, char* argv[])
{
	pthread_t stt_t;

	if (argc < 2){
		printf("vulstat cved_file\n");
	}

	if ((cved_fp = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 666)) == -1){
		fprintf(stderr, "Cannot open cved file!\n");
		return -1;
	}

	start_time = time(NULL);
	stats_state = STAT_PREPARATION;
	pthread_create(&stt_t, NULL, print_statistics, NULL);

	curl_global_init(CURL_GLOBAL_ALL);
	total_pages_nmb += cved_preparations();

	stats_state = STAT_PROCESSING;
	cved_main_processing(cved_fp, &statistics, &current_page_nmb);

	close(cved_fp);

	stats_state = STAT_STOPPED;
	printf("Done\n");

	return 0;
}

void *print_statistics()
{
	time_t current_time = 0;
	unsigned int perc = 0;
	int i = 0;

	while (1){
		sleep(1);
		if (system("clear"))
			fprintf(stdout, "Cannot clear screen!\n");

		current_time = time(NULL);
		printf("Uptime: %ld seconds\n", current_time - start_time);

		if (stats_state == STAT_PREPARATION){
			printf("Making some preparations!\n");
		} else if (stats_state == STAT_PROCESSING){
			perc = (unsigned int)((float)current_page_nmb / (float)total_pages_nmb * 100);
			printf("%d%% [", perc);
			for (i = 0; i < 20; i++){
				if (perc > i * 5){
					printf("\u2588");
				} else {
					printf(".");
				}
			}
			printf("]\n");
			printf("\tL7: %d\n\tL5: %d\n\tL4: %d\n\tL3: %d\n\tL2: %d\n\tOthers: %d\n",
					statistics.is_l7, statistics.is_l5, statistics.is_l4, statistics.is_l3, statistics.is_l2, statistics.is_other);
		} else if (stats_state == STAT_STOPPED){
			printf("\tL7: %d\n\tL5: %d\n\tL4: %d\n\tL3: %d\n\tL2: %d\n\tOthers: %d\n",
					statistics.is_l7, statistics.is_l5, statistics.is_l4, statistics.is_l3, statistics.is_l2, statistics.is_other);
			pthread_exit(0);
			break;
		}
	}

	return 0;
}
