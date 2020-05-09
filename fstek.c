/*
 * fstek.c
 *
 *  Created on: May 8, 2020
 *      Author: sasha
 */

#include <math.h>
#include "fstek.h"
#include "search_functions.h"
#include "prots.h"

static struct search_body* fstek_sb_end = NULL;
static struct search_body* fstek_sb_searcht = NULL;

static struct search_body* fstek_sb_L7 = NULL;
static struct search_body* fstek_sb_L5 = NULL;
static struct search_body* fstek_sb_L4 = NULL;
static struct search_body* fstek_sb_L3 = NULL;
static struct search_body* fstek_sb_L2 = NULL;

static struct descriptor fstek_descrs[FSTEK_MAX_PARALLEL];
static struct all_pages* fstek_page_ptr = NULL;

static struct processing_stat fstek_stat;

static int fstek_fp = 0;

static unsigned int fstek_total_pages_nmb = 0;
static unsigned int fstek_current_page_nmb = 0;


static const char*
FSTEK_PAGE = "https://bdu.fstec.ru/vul?ajax=vuls&size=100&page=1";

int create_pages_list(int nmb)
{
	int i = 0;
	int twin_i = 0;
	int nmb_size = 0;
	int len = 0;
	struct all_pages* tmp = NULL;

	for (i = 1; i <= nmb; i++){
		tmp = (struct all_pages*)malloc(sizeof(struct all_pages));
		nmb_size = 0;
		twin_i = i;
		while (twin_i){
			nmb_size++;
			twin_i /= 10;
		}
		twin_i = i;
		tmp->url = (char*)malloc(sizeof(char) * (strlen(BDU_PAGE_PREFIX) + nmb_size + 1));
		strcpy(tmp->url, BDU_PAGE_PREFIX);
		len = strlen(tmp->url);
		while (nmb_size){
			nmb_size--;
			tmp->url[len] = (twin_i / (int)pow((float)10, (float)nmb_size) % 10) + '0';
			len++;
		}
		tmp->url[len] = '\0';
		if (!fstek_page_ptr){
			tmp->next = NULL;
		} else {
			tmp->next = fstek_page_ptr;
		}
		fstek_page_ptr = tmp;
	}

	return 0;
}

static size_t fstek_write_preparation_data(char *data, size_t n, size_t l, void *userp)
{
	struct descriptor* descr = userp;
	char* last_page_ptr = NULL;
	unsigned int pages_amount = 0;

	if (descr->index + l <= DESCRIPTORS_SIZE){
		memcpy(descr->data + descr->index, data, l);
		descr->index += l;
	} else {
		printf("Not Enough mem\n");
	}

	if (sf_find_left(fstek_sb_end, data, l)){
		last_page_ptr = strstr(descr->data, "id=\"yw1\"");
		if (!last_page_ptr){
			fstek_stat.is_error++;
			descr->index = 0;
			descr->in_use = 0;
		} else {
			last_page_ptr = strstr(last_page_ptr, "class=\"last\"");
			last_page_ptr = strstr(last_page_ptr, "page=") + 5;
			for (; *last_page_ptr >= '0' && *last_page_ptr <= '9'; last_page_ptr++){
				pages_amount = pages_amount * 10 + (*last_page_ptr - '0');
			}
			create_pages_list(pages_amount);
			fstek_total_pages_nmb = pages_amount;
			descr->index = 0;
			descr->in_use = 0;
		}
	}

	return n*l;
}

unsigned int fstek_preparations ()
{
	CURL* eh;
	  int j = 0;
	  int i = 0;

	  memset(&fstek_descrs, 0, sizeof(struct descriptor) * FSTEK_MAX_PARALLEL);
	  for (i = 0; i < FSTEK_MAX_PARALLEL; i++){
		  fstek_descrs[i].data = (void*)malloc(DESCRIPTORS_SIZE);
	  }


	  fstek_sb_end = sf_init_sb(HTML_END);

	  eh = curl_easy_init();
	  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, fstek_write_preparation_data);
	  for (j = 0; j < FSTEK_MAX_PARALLEL; j++){
		  if (!fstek_descrs[j].in_use){
			  fstek_descrs[j].index = 0;
			  fstek_descrs[j].in_use = 1;
			  curl_easy_setopt(eh, CURLOPT_WRITEDATA, fstek_descrs + j);
			  break;
		  }
	  }
	  curl_easy_setopt(eh, CURLOPT_URL, FSTEK_PAGE);
	  curl_easy_setopt(eh, CURLOPT_PRIVATE, FSTEK_PAGE);

	  curl_easy_perform(eh);
	  curl_easy_cleanup(eh);

	  for (i = 0; i < FSTEK_MAX_PARALLEL; i++){
		  free(fstek_descrs[i].data);
	  }
	  sf_free_sb(fstek_sb_end);

	  return fstek_total_pages_nmb;
}

int fstek_page_event(char* word, char* next, char* last)
{
	static unsigned char processing = 0;
	unsigned int str_len = 0;
	unsigned int cur_len = 0;
	char* new_data = NULL;
	char* cve_name = NULL;
	char* cve_name_end = NULL;
	char* cve_date = NULL;
	char* cve_date_end = NULL;
	char* cve_score = NULL;
	char* cve_score_end = NULL;
	char* text = NULL;
	char* text_end = NULL;

	if (!strcmp(word, FSTEK_SEARCHT_START)){
		processing = 1;
	} else if (!strcmp(word, FSTEK_SEARCHT_END)){
		processing = 0;
	} else if (!strcmp(word, FSTEK_SEARCHT_DATA) && processing){
		cve_name = strstr(next, "<a");
		cve_name = strchr(cve_name, '>') + 1;
		cve_name_end = strstr(cve_name, "</a>");

		text = strstr(cve_name_end, "<h5");
		text = strstr(text, "=\"") + 2;
		text_end = strchr(text, '\"');

		cve_score = strstr(text_end, "class=\"td-inner") + 5;
		cve_score = strstr(cve_score, "bsc");
		cve_score_end = strchr(cve_score, '\"');

		cve_date = strstr(cve_score_end, "<span>") + 6;
		cve_date_end = strstr(cve_date, "</span>");

		if (sf_find_left(fstek_sb_L7, text, text_end - text)){
			fstek_stat.is_l7++;
			str_len += strlen(L7_PREFIX) + 1 + (cve_name_end - cve_name + 1) +
					(cve_date_end - cve_date + 1) + (1 + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L7_PREFIX";");
			cur_len = strlen(new_data);

		} else if (sf_find_left(fstek_sb_L5, text, text_end - text)){
			fstek_stat.is_l5++;
			str_len += strlen(L5_PREFIX) + 1 + (cve_name_end - cve_name + 1) +
					(cve_date_end - cve_date + 1) + (1 + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L5_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(fstek_sb_L4, text, text_end - text)){
			fstek_stat.is_l4++;
			str_len += strlen(L4_PREFIX) + 1 + (cve_name_end - cve_name + 1) +
					(cve_date_end - cve_date + 1) + (1 + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L4_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(fstek_sb_L3, text, text_end - text)){
			fstek_stat.is_l3++;
			str_len += strlen(L3_PREFIX) + 1 + (cve_name_end - cve_name + 1) +
					(cve_date_end - cve_date + 1) + (1 + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L3_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(fstek_sb_L2, text, text_end - text)){
			fstek_stat.is_l2++;
			str_len += strlen(L2_PREFIX) + 1 + (cve_name_end - cve_name + 1) +
					(cve_date_end - cve_date + 1) + (1 + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L2_PREFIX";");
			cur_len = strlen(new_data);
		} else {
			fstek_stat.is_other++;
			str_len += strlen(OTHER_PREFIX) + 1 + (cve_name_end - cve_name + 1) +
					(cve_date_end - cve_date + 1) + (1 + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, OTHER_PREFIX";");
			cur_len = strlen(new_data);
		}
		memcpy(new_data + cur_len, cve_name, cve_name_end - cve_name);
		cur_len += cve_name_end - cve_name;
		new_data[cur_len++] = ';';
		memcpy(new_data + cur_len, cve_date, cve_date_end - cve_date);
		cur_len += cve_date_end - cve_date;
		new_data[cur_len++] = ';';
		if (!memcmp(cve_score, SCORE_LOW, strlen(SCORE_LOW))){
			new_data[cur_len++] = '1';
		} else if (!memcmp(cve_score, SCORE_MIDDLE, strlen(SCORE_MIDDLE))){
			new_data[cur_len++] = '2';
		} else if (!memcmp(cve_score, SCORE_HIGH, strlen(SCORE_HIGH))){
			new_data[cur_len++] = '3';
		} else if (!memcmp(cve_score, SCORE_CRITICAL, strlen(SCORE_CRITICAL))){
			new_data[cur_len++] = '4';
		}
		new_data[cur_len++] ='\n';
		if (write(fstek_fp, new_data, cur_len) == -1)
			fprintf(stderr, "Didnt write somewhat");

		free(new_data);
	}

	return 0;
}

static size_t fstek_write_data(char *data, size_t n, size_t l, void *userp)
{
	struct descriptor* descr = userp;

	if (descr->index + l <= DESCRIPTORS_SIZE){
		memcpy(descr->data + descr->index, data, l);
		descr->index += l;
	} else {
		printf("Not Enough mem\n");
	}

	if (sf_find_left(fstek_sb_end, data, l)){
		fstek_current_page_nmb++;

		if (sf_call_event_handler(fstek_sb_searcht, descr->data, descr->index, fstek_page_event)){
			fstek_stat.is_error++;
		}
		descr->index = 0;
		descr->in_use = 0;
	}

	return n*l;
}

int fstek_main_processing(int write_file, struct processing_stat* stats, unsigned int* current_page)
{
	  CURLM *cm;
	  CURLMsg *msg;
	  int msgs_left = -1;
	  int still_alive = 1;
	  unsigned int transfers = 0;
	  int j = 0;
	  int i = 0;

	  if (!fstek_page_ptr)
		  return -1;

	  memset(&fstek_descrs, 0, sizeof(struct descriptor) * FSTEK_MAX_PARALLEL);
	  for (i = 0; i < FSTEK_MAX_PARALLEL; i++){
		  fstek_descrs[i].data = (void*)malloc(DESCRIPTORS_SIZE);
	  }

	  memset(&fstek_stat, 0, sizeof(struct processing_stat));
	  fstek_fp = write_file;

	  fstek_sb_searcht = sf_init_sb(FSTEK_SEARCHT_START"|"FSTEK_SEARCHT_END"|"FSTEK_SEARCHT_DATA);
	  fstek_sb_end = sf_init_sb(HTML_END);
	  fstek_sb_L7 = sf_init_sb((char*)L7_NAMES);
	  fstek_sb_L5 = sf_init_sb((char*)L5_NAMES);
	  fstek_sb_L4 = sf_init_sb((char*)L4_NAMES);
	  fstek_sb_L3 = sf_init_sb((char*)L3_NAMES);
	  fstek_sb_L2 = sf_init_sb((char*)L2_NAMES);

	  cm = curl_multi_init();

	  curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)FSTEK_MAX_PARALLEL);

	  for(transfers = 0; transfers < FSTEK_MAX_PARALLEL && fstek_page_ptr; transfers++, fstek_page_ptr = fstek_page_ptr->next){
		  CURL *eh = curl_easy_init();
		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, fstek_write_data);
		  for (j = 0; j < FSTEK_MAX_PARALLEL; j++){
			  if (!fstek_descrs[j].in_use){
				  fstek_descrs[j].index = 0;
				  fstek_descrs[j].in_use = 1;
				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, fstek_descrs + j);
				  break;
			  }
		  }
		  curl_easy_setopt(eh, CURLOPT_URL, fstek_page_ptr->url);
		  curl_easy_setopt(eh, CURLOPT_PRIVATE, fstek_page_ptr->url);
		  curl_multi_add_handle(cm, eh);
	  }

	  do {
	    curl_multi_perform(cm, &still_alive);

	    while((msg = curl_multi_info_read(cm, &msgs_left))) {
	    	if(msg->msg == CURLMSG_DONE) {
	            CURL *e = msg->easy_handle;
	    		curl_multi_remove_handle(cm, e);
	    		curl_easy_cleanup(e);
	    		(*current_page)++;
	    		if (fstek_stat.is_l2){
	    			stats->is_l2 += fstek_stat.is_l2;
	    			fstek_stat.is_l2 = 0;
	    		}
	    		if (fstek_stat.is_l3){
	    			stats->is_l3 += fstek_stat.is_l3;
	    			fstek_stat.is_l3 = 0;
	    		}
	    		if (fstek_stat.is_l4){
	    			stats->is_l4 += fstek_stat.is_l4;
	    			fstek_stat.is_l4 = 0;
	    		}
	    		if (fstek_stat.is_l5){
	    			stats->is_l5 += fstek_stat.is_l5;
	    			fstek_stat.is_l5 = 0;
	    		}
	    		if (fstek_stat.is_l7){
	    			stats->is_l7 += fstek_stat.is_l7;
	    			fstek_stat.is_l7 = 0;
	    		}
	    		if (fstek_stat.is_other){
	    			stats->is_other += fstek_stat.is_other;
	    			fstek_stat.is_other = 0;
	    		}
	    		if (fstek_stat.is_error){
	    			stats->is_error += fstek_stat.is_error;
	    			fstek_stat.is_error = 0;
	    		}
		    	if (fstek_page_ptr){
		  		  e = curl_easy_init();
		  		  curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, fstek_write_data);
		  		  for (j = 0; j < FSTEK_MAX_PARALLEL; j++){
		  			  if (!fstek_descrs[j].in_use){
		  				  fstek_descrs[j].index = 0;
		  				  fstek_descrs[j].in_use = 1;
		  				  curl_easy_setopt(e, CURLOPT_WRITEDATA, fstek_descrs + j);
		  				  break;
		  			  }
		  		  }
		  		  curl_easy_setopt(e, CURLOPT_URL, fstek_page_ptr->url);
		  		  curl_easy_setopt(e, CURLOPT_PRIVATE, fstek_page_ptr->url);
		  		  curl_multi_add_handle(cm, e);
		  		  fstek_page_ptr = fstek_page_ptr->next;
		    	}
	    	}
	    	else {
	    		fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
	    	}
	    }
	    if(still_alive)
	      curl_multi_wait(cm, NULL, 0, 1000, NULL);

	  } while(still_alive || fstek_page_ptr);

	  curl_multi_cleanup(cm);
	  curl_global_cleanup();

	  for (i = 0; i < FSTEK_MAX_PARALLEL; i++){
		 free(fstek_descrs[i].data);
	  }
	  sf_free_sb(fstek_sb_searcht);
	  sf_free_sb(fstek_sb_end);
	  sf_free_sb(fstek_sb_L7);
	  sf_free_sb(fstek_sb_L5);
	  sf_free_sb(fstek_sb_L4);
	  sf_free_sb(fstek_sb_L3);
	  sf_free_sb(fstek_sb_L2);

	return 0;
}
