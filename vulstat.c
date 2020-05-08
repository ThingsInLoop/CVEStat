/*
 * vulstat.c
 *
 *  Created on: May 7, 2020
 *      Author: sasha
 */

#include "vulstat.h"

static unsigned int total_pages_nmb = 0;
static unsigned int current_page_nmb = 0;

struct search_body* sb_padding = NULL;
struct search_body* sb_end = NULL;

struct search_body* sb_searcht = NULL;
struct search_body* sb_L7 = NULL;
struct search_body* sb_L5 = NULL;
struct search_body* sb_L4 = NULL;
struct search_body* sb_L3 = NULL;
struct search_body* sb_L2 = NULL;

struct descriptor descrs[MAX_PARALLEL];
struct all_pages* page_ptr = NULL;

static int fp = 0;

static unsigned int is_l7 = 0;
static unsigned int is_l5 = 0;
static unsigned int is_l4 = 0;
static unsigned int is_l3 = 0;
static unsigned int is_l2 = 0;
static unsigned int is_other = 0;

static unsigned char stats_state = 0;

time_t start_time = 0;

void *print_statistics();

int page_preparation_event(char* word, char* next, char* last)
{
	static char* prev_a_tag = NULL;
	struct all_pages* tmp = NULL;
	static unsigned char processing = 0;
	char* c = NULL;

	if (!strcmp(word, PADDING_START)){
		processing = 1;
	} else if (!strcmp(word, PADDING_END)){
		processing = 0;
	} else if (!strcmp(word, PADDING_PAGE_ADDR_START) && processing){
		prev_a_tag = next;
	} else if (!strcmp(word, PADDING_PAGE_ADDR_END) && processing){
		for (c = next - strlen(word); *c != '\"'; c--);

		tmp = (struct all_pages*)malloc(sizeof(struct all_pages));
		tmp->url = (char*)malloc(sizeof(char) * (unsigned long)(strlen(URL_START) + c - prev_a_tag + 1));
		strcpy(tmp->url, URL_START);
		memcpy(tmp->url + strlen(URL_START), prev_a_tag, c - prev_a_tag);
		tmp->url[strlen(URL_START) + c - prev_a_tag] = '\0';

		if (!page_ptr){
			tmp->next = NULL;
		} else {
			tmp->next = page_ptr;
		}
		page_ptr = tmp;

		total_pages_nmb++;
	}

	return 0;
}

static size_t write_preparation_data(char *data, size_t n, size_t l, void *userp)
{
	struct descriptor* descr = userp;

	if (descr->index + l <= 5 * MB){
		memcpy(descr->data + descr->index, data, l);
		descr->index += l;
	} else {
		printf("Not Enough mem\n");
	}

	if (sf_find_left(sb_end, data, l)){
		sf_call_event_handler(sb_padding, descr->data, descr->index, page_preparation_event);
		descr->index = 0;
		descr->in_use = 0;
	}

	return n*l;
}

int preparations ()
{
	  CURLM *cm;
	  CURLMsg *msg;
	  int msgs_left = -1;
	  int still_alive = 1;
	  unsigned int transfers = 0;
	  int j = 0;


	  sb_end = sf_init_sb(HTML_END);
	  sb_padding = sf_init_sb(PADDING_START"|"PADDING_END"|"PADDING_PAGE_ADDR_START"|"PADDING_PAGE_ADDR_END);

	  cm = curl_multi_init();

	  /* Limit the amount of simultaneous connections curl should allow: */
	  curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

	  for(transfers = 0; transfers < MAX_PARALLEL && transfers < CVE_DETAILS_PAGES_NMB; transfers++){
		  CURL *eh = curl_easy_init();
		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_preparation_data);
		  for (j = 0; j < MAX_PARALLEL; j++){
			  if (!descrs[j].in_use){
				  descrs[j].index = 0;
				  descrs[j].in_use = 1;
				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, descrs + j);
				  break;
			  }
		  }
		  curl_easy_setopt(eh, CURLOPT_URL, CVE_DETAILS_PAGES[transfers]);
		  curl_easy_setopt(eh, CURLOPT_PRIVATE, CVE_DETAILS_PAGES[transfers]);
		  curl_multi_add_handle(cm, eh);
	  }

	  do {
	    curl_multi_perform(cm, &still_alive);

	    while((msg = curl_multi_info_read(cm, &msgs_left))) {
	    	if(msg->msg == CURLMSG_DONE) {
	    		CURL *e = msg->easy_handle;
	    		curl_multi_remove_handle(cm, e);
	    		curl_easy_cleanup(e);
	    	}
	    	else {
	    		fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
	    	}
	    	if (transfers < CVE_DETAILS_PAGES_NMB){
	  		  CURL *eh = curl_easy_init();
	  		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_preparation_data);
	  		  for (j = 0; j < MAX_PARALLEL; j++){
	  			  if (!descrs[j].in_use){
	  				  descrs[j].index = 0;
	  				  descrs[j].in_use = 1;
	  				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, descrs + j);
	  				  break;
	  			  }
	  		  }
	  		  curl_easy_setopt(eh, CURLOPT_URL, CVE_DETAILS_PAGES[transfers]);
	  		  curl_easy_setopt(eh, CURLOPT_PRIVATE, CVE_DETAILS_PAGES[transfers]);
	  		  curl_multi_add_handle(cm, eh);
	  		  transfers++;
	    	}
	    }
	    if(still_alive)
	      curl_multi_wait(cm, NULL, 0, 1000, NULL);

	  } while(still_alive || (transfers < CVE_DETAILS_PAGES_NMB));

	  curl_multi_cleanup(cm);
	  curl_global_cleanup();

	  return 0;
}

int page_event(char* word, char* next, char* last)
{
	static unsigned char processing = 0;
	unsigned int str_len = 0;
	unsigned int cur_len = 0;
	char* new_data = NULL;
	char* cve_name = NULL;
	char* cve_name_end = NULL;
	char* cve_class = NULL;
	char* cve_class_end = NULL;
	char* cve_date = NULL;
	char* cve_date_end = NULL;
	char* cve_score = NULL;
	char* cve_score_end = NULL;
	char* text = NULL;
	char* text_end = NULL;

	if (!strcmp(word, SEARCHT_START)){
		processing = 1;
	} else if (!strcmp(word, SEARCHT_END)){
		processing = 0;
	} else if (!strcmp(word, SEARCHT_DATA) && processing){
		cve_name = strstr(next, "title=\"CVE");
		cve_name = strchr(cve_name, '>') + 1;
		cve_name_end = strstr(cve_name, "</a>");

		cve_class = strstr(cve_name_end, "<td>") + 1;
		cve_class = strstr(cve_class, "<td>") + 1;
		for (cve_class += 3; *cve_class == '\n' || *cve_class == ' ' || *cve_class == '\t'; cve_class++);
		cve_class_end = strstr(cve_class, "</td>");
		for (cve_class_end--; *cve_class == '\n' || *cve_class_end == ' ' || *cve_class_end == '\t'; cve_class_end--);
		cve_class_end++;

		cve_date = strstr(cve_class_end, "<td>") + 4;
		cve_date_end = strstr(cve_date, "</td>");

		cve_score = strstr(cve_date_end, "cvssbox");
		cve_score = strchr(cve_score, '>') + 1;
		cve_score_end = strstr(cve_score, "</div>");

		text = strstr(cve_score_end, SEARCHT_TEXT);
		text = strchr(text, '>') + 1;
		text_end = strstr(text, "</td>");

		if (sf_find_left(sb_L7, text, text_end - text)){
			is_l7++;
			str_len += strlen(L7_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L7_PREFIX";");
			cur_len = strlen(new_data);

		} else if (sf_find_left(sb_L5, text, text_end - text)){
			is_l5++;
			str_len += strlen(L5_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L5_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(sb_L4, text, text_end - text)){
			is_l4++;
			str_len += strlen(L4_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L4_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(sb_L3, text, text_end - text)){
			is_l3++;
			str_len += strlen(L3_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L3_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(sb_L2, text, text_end - text)){
			is_l2++;
			str_len += strlen(L2_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L2_PREFIX";");
			cur_len = strlen(new_data);
		} else {
			is_other++;
			str_len += strlen(OTHER_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1) + (text_end - text + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, OTHER_PREFIX";");
			cur_len = strlen(new_data);
		}
		memcpy(new_data + cur_len, cve_name, cve_name_end - cve_name);
		cur_len += cve_name_end - cve_name;
		new_data[cur_len++] = ';';
		memcpy(new_data + cur_len, cve_class, cve_class_end - cve_class);
		cur_len += cve_class_end - cve_class;
		new_data[cur_len++] = ';';
		memcpy(new_data + cur_len, cve_date, cve_date_end - cve_date);
		cur_len += cve_date_end - cve_date;
		new_data[cur_len++] = ';';
		memcpy(new_data + cur_len, cve_score, cve_score_end - cve_score);
		cur_len += cve_score_end - cve_score;
		new_data[cur_len++] ='\n';
		if (write(fp, new_data, cur_len) == -1)
			fprintf(stderr, "Didnt write somewhat");

		free(new_data);
	}

	return 0;
}

static size_t write_data(char *data, size_t n, size_t l, void *userp)
{
	struct descriptor* descr = userp;

	if (descr->index + l <= 5 * MB){
		memcpy(descr->data + descr->index, data, l);
		descr->index += l;
	} else {
		printf("Not Enough mem\n");
	}

	if (sf_find_left(sb_end, data, l)){
		current_page_nmb++;
		sf_call_event_handler(sb_searcht, descr->data, descr->index, page_event);
		descr->index = 0;
		descr->in_use = 0;
	}

	return n*l;
}

int main_processing(char* file_name)
{
	  CURLM *cm;
	  CURLMsg *msg;
	  int msgs_left = -1;
	  int still_alive = 1;
	  unsigned int transfers = 0;
	  int j = 0;

	  static int pg_c = 0;

	  sb_searcht = sf_init_sb(SEARCHT_START"|"SEARCHT_END"|"SEARCHT_DATA);
	  sb_L7 = sf_init_sb((char*)L7_NAMES);
	  sb_L5 = sf_init_sb((char*)L5_NAMES);
	  sb_L4 = sf_init_sb((char*)L4_NAMES);
	  sb_L3 = sf_init_sb((char*)L3_NAMES);
	  sb_L2 = sf_init_sb((char*)L2_NAMES);

	  fp = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, 666);
	  if (fp == -1)
		  fprintf(stderr, "Cannot open file to write");

	  cm = curl_multi_init();

	  /* Limit the amount of simultaneous connections curl should allow: */
	  curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

	  for(transfers = 0; transfers < MAX_PARALLEL && page_ptr; transfers++, page_ptr = page_ptr->next){
		  CURL *eh = curl_easy_init();
		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_data);
		  for (j = 0; j < MAX_PARALLEL; j++){
			  if (!descrs[j].in_use){
				  descrs[j].index = 0;
				  descrs[j].in_use = 1;
				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, descrs + j);
				  break;
			  }
		  }
		  curl_easy_setopt(eh, CURLOPT_URL, page_ptr->url);
		  curl_easy_setopt(eh, CURLOPT_PRIVATE, page_ptr->url);
		  curl_multi_add_handle(cm, eh);
	  }

	  do {
	    curl_multi_perform(cm, &still_alive);

	    while((msg = curl_multi_info_read(cm, &msgs_left))) {
	    	if(msg->msg == CURLMSG_DONE) {
	            CURL *e = msg->easy_handle;
	    		curl_multi_remove_handle(cm, e);
	    		curl_easy_cleanup(e);
	    		pg_c++;
	    	}
	    	else {
	    		fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
	    	}
	    	if (page_ptr){
	  		  CURL *eh = curl_easy_init();
	  		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, write_data);
	  		  for (j = 0; j < MAX_PARALLEL; j++){
	  			  if (!descrs[j].in_use){
	  				  descrs[j].index = 0;
	  				  descrs[j].in_use = 1;
	  				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, descrs + j);
	  				  break;
	  			  }
	  		  }
	  		  curl_easy_setopt(eh, CURLOPT_URL, page_ptr->url);
	  		  curl_easy_setopt(eh, CURLOPT_PRIVATE, page_ptr->url);
	  		  curl_multi_add_handle(cm, eh);
	  		  page_ptr = page_ptr->next;
	    	}
	    }
	    if(still_alive)
	      curl_multi_wait(cm, NULL, 0, 1000, NULL);

	  } while(still_alive || page_ptr);

	  curl_multi_cleanup(cm);
	  curl_global_cleanup();
	  close(fp);

	return 0;
}

int main(int argc, char* argv[])
{
	pthread_t stt_t;
	int i = 0;

	if (argc < 2){
		printf("vulstat file\n");
	}

	start_time = time(NULL);
	stats_state = STAT_PREPARATION;
	pthread_create(&stt_t, NULL, print_statistics, NULL);

	curl_global_init(CURL_GLOBAL_ALL);

	memset(&descrs, 0, sizeof(struct descriptor) * MAX_PARALLEL);
	for (i = 0; i < MAX_PARALLEL; i++){
		descrs[i].data = (void*)malloc(5 * MB);
	}
	preparations();

	stats_state = STAT_PROCESSING;
	main_processing(argv[1]);

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
			printf("\tL7: %d\n\tL5: %d\n\tL4: %d\n\tL3: %d\n\tL2: %d\n\tOthers: %d\n", is_l7, is_l5, is_l4, is_l3, is_l2, is_other);
		} else if (stats_state == STAT_STOPPED){
			printf("\tL7: %d\n\tL5: %d\n\tL4: %d\n\tL3: %d\n\tL2: %d\n\tOthers: %d\n", is_l7, is_l5, is_l4, is_l3, is_l2, is_other);
			pthread_exit(0);
			break;
		}
	}

	return 0;
}
