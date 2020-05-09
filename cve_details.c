/*
 * cve_details.c
 *
 *  Created on: May 8, 2020
 *      Author: sasha
 */

#include "cve_details.h"
#include "search_functions.h"
#include "prots.h"

static struct search_body* cved_sb_padding = NULL;
static struct search_body* cved_sb_end = NULL;
static struct search_body* cved_sb_searcht = NULL;

static struct search_body* cved_sb_L7 = NULL;
static struct search_body* cved_sb_L5 = NULL;
static struct search_body* cved_sb_L4 = NULL;
static struct search_body* cved_sb_L3 = NULL;
static struct search_body* cved_sb_L2 = NULL;

static struct descriptor cved_descrs[MAX_PARALLEL];
static struct all_pages* cved_page_ptr = NULL;

static struct processing_stat cved_stat;

static int cved_fp = 0;

static unsigned int cved_total_pages_nmb = 0;
static unsigned int cved_current_page_nmb = 0;


static const char*
CVE_DETAILS_PAGES[] = {   "https://www.cvedetails.com/vulnerability-list/opdos-1/denial-of-service.html",
                        "https://www.cvedetails.com/vulnerability-list/opec-1/execute-code.html",
                        "https://www.cvedetails.com/vulnerability-list/opov-1/overflow.html",
                        "https://www.cvedetails.com/vulnerability-list/opmemc-1/memory-corruption.html",
                        "https://www.cvedetails.com/vulnerability-list/opsqli-1/sql-injection.html",
                        "https://www.cvedetails.com/vulnerability-list/opxss-1/xss.html",
                        "https://www.cvedetails.com/vulnerability-list/opdirt-1/directory-traversal.html",
                        "https://www.cvedetails.com/vulnerability-list/ophttprs-1/http-response-splitting.html",
                        "https://www.cvedetails.com/vulnerability-list/opbyp-1/bypass.html",
                        "https://www.cvedetails.com/vulnerability-list/opginf-1/gain-information.html",
                        "https://www.cvedetails.com/vulnerability-list/opgpriv-1/gain-privilege.html",
                        "https://www.cvedetails.com/vulnerability-list/opcsrf-1/csrf.html",
                        "https://www.cvedetails.com/vulnerability-list/opfileinc-1/file-inclusion.html"};

int cved_page_preparation_event(char* word, char* next, char* last)
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

		if (!cved_page_ptr){
			tmp->next = NULL;
		} else {
			tmp->next = cved_page_ptr;
		}
		cved_page_ptr = tmp;

		cved_total_pages_nmb++;
	}

	return 0;
}

static size_t cved_write_preparation_data(char *data, size_t n, size_t l, void *userp)
{
	struct descriptor* descr = userp;

	if (descr->index + l <= 5 * MB){
		memcpy(descr->data + descr->index, data, l);
		descr->index += l;
	} else {
		printf("Not Enough mem\n");
	}

	if (sf_find_left(cved_sb_end, data, l)){
		if (sf_call_event_handler(cved_sb_padding, descr->data, descr->index, cved_page_preparation_event)){
			cved_stat.is_error++;
		}
		descr->index = 0;
		descr->in_use = 0;
	}

	return n*l;
}

unsigned int cved_preparations ()
{
	  CURLM *cm;
	  CURLMsg *msg;
	  int msgs_left = -1;
	  int still_alive = 1;
	  unsigned int transfers = 0;
	  int j = 0;
	  int i = 0;

	  memset(&cved_descrs, 0, sizeof(struct descriptor) * MAX_PARALLEL);
	  for (i = 0; i < MAX_PARALLEL; i++){
		  cved_descrs[i].data = (void*)malloc(5 * MB);
	  }


	  cved_sb_end = sf_init_sb(HTML_END);
	  cved_sb_padding = sf_init_sb(PADDING_START"|"PADDING_END"|"PADDING_PAGE_ADDR_START"|"PADDING_PAGE_ADDR_END);

	  cm = curl_multi_init();

	  /* Limit the amount of simultaneous connections curl should allow: */
	  curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

	  for(transfers = 0; transfers < MAX_PARALLEL && transfers < CVE_DETAILS_PAGES_NMB; transfers++){
		  CURL *eh = curl_easy_init();
		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, cved_write_preparation_data);
		  for (j = 0; j < MAX_PARALLEL; j++){
			  if (!cved_descrs[j].in_use){
				  cved_descrs[j].index = 0;
				  cved_descrs[j].in_use = 1;
				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, cved_descrs + j);
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
	  		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, cved_write_preparation_data);
	  		  for (j = 0; j < MAX_PARALLEL; j++){
	  			  if (!cved_descrs[j].in_use){
	  				  cved_descrs[j].index = 0;
	  				  cved_descrs[j].in_use = 1;
	  				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, cved_descrs + j);
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

	  for (i = 0; i < MAX_PARALLEL; i++){
		  free(cved_descrs[i].data);
	  }
	  sf_free_sb(cved_sb_end);
	  sf_free_sb(cved_sb_padding);

	  return cved_total_pages_nmb;
}

int cved_page_event(char* word, char* next, char* last)
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

		if (sf_find_left(cved_sb_L7, text, text_end - text)){
			cved_stat.is_l7++;
			str_len += strlen(L7_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L7_PREFIX";");
			cur_len = strlen(new_data);

		} else if (sf_find_left(cved_sb_L5, text, text_end - text)){
			cved_stat.is_l5++;
			str_len += strlen(L5_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L5_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(cved_sb_L4, text, text_end - text)){
			cved_stat.is_l4++;
			str_len += strlen(L4_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L4_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(cved_sb_L3, text, text_end - text)){
			cved_stat.is_l3++;
			str_len += strlen(L3_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L3_PREFIX";");
			cur_len = strlen(new_data);
		} else if (sf_find_left(cved_sb_L2, text, text_end - text)){
			cved_stat.is_l2++;
			str_len += strlen(L2_PREFIX) + 1 + (cve_name_end - cve_name + 1) + (cve_class_end - cve_class + 1) +
					(cve_date_end - cve_date + 1) + (cve_score_end - cve_score + 1);
			new_data = (char*)malloc(sizeof(char) * str_len);
			strcpy(new_data, L2_PREFIX";");
			cur_len = strlen(new_data);
		} else {
			cved_stat.is_other++;
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
		if (write(cved_fp, new_data, cur_len) == -1)
			fprintf(stderr, "Didnt write somewhat");

		free(new_data);
	}

	return 0;
}

static size_t cved_write_data(char *data, size_t n, size_t l, void *userp)
{
	struct descriptor* descr = userp;

	if (descr->index + l <= 5 * MB){
		memcpy(descr->data + descr->index, data, l);
		descr->index += l;
	} else {
		printf("Not Enough mem\n");
	}

	if (sf_find_left(cved_sb_end, data, l)){
		cved_current_page_nmb++;
		if (sf_call_event_handler(cved_sb_searcht, descr->data, descr->index, cved_page_event)){
			cved_stat.is_error++;
		}
		descr->index = 0;
		descr->in_use = 0;
	}

	return n*l;
}

int cved_main_processing(int write_file, struct processing_stat* stats, unsigned int* current_page)
{
	  CURLM *cm;
	  CURLMsg *msg;
	  int msgs_left = -1;
	  int still_alive = 1;
	  unsigned int transfers = 0;
	  int j = 0;
	  int i = 0;

	  if (!cved_page_ptr)
		  return -1;

	  memset(&cved_descrs, 0, sizeof(struct descriptor) * MAX_PARALLEL);
	  for (i = 0; i < MAX_PARALLEL; i++){
		  cved_descrs[i].data = (void*)malloc(5 * MB);
	  }

	  memset(&cved_stat, 0, sizeof(struct processing_stat));
	  cved_fp = write_file;

	  cved_sb_searcht = sf_init_sb(SEARCHT_START"|"SEARCHT_END"|"SEARCHT_DATA);
	  cved_sb_end = sf_init_sb(HTML_END);
	  cved_sb_L7 = sf_init_sb((char*)L7_NAMES);
	  cved_sb_L5 = sf_init_sb((char*)L5_NAMES);
	  cved_sb_L4 = sf_init_sb((char*)L4_NAMES);
	  cved_sb_L3 = sf_init_sb((char*)L3_NAMES);
	  cved_sb_L2 = sf_init_sb((char*)L2_NAMES);

	  cm = curl_multi_init();

	  /* Limit the amount of simultaneous connections curl should allow: */
	  curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)MAX_PARALLEL);

	  for(transfers = 0; transfers < MAX_PARALLEL && cved_page_ptr; transfers++, cved_page_ptr = cved_page_ptr->next){
		  CURL *eh = curl_easy_init();
		  curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, cved_write_data);
		  for (j = 0; j < MAX_PARALLEL; j++){
			  if (!cved_descrs[j].in_use){
				  cved_descrs[j].index = 0;
				  cved_descrs[j].in_use = 1;
				  curl_easy_setopt(eh, CURLOPT_WRITEDATA, cved_descrs + j);
				  break;
			  }
		  }
		  curl_easy_setopt(eh, CURLOPT_URL, cved_page_ptr->url);
		  curl_easy_setopt(eh, CURLOPT_PRIVATE, cved_page_ptr->url);
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
	    		if (cved_stat.is_l2){
	    			stats->is_l2 += cved_stat.is_l2;
	    			cved_stat.is_l2 = 0;
	    		}
	    		if (cved_stat.is_l3){
	    			stats->is_l3 += cved_stat.is_l3;
	    			cved_stat.is_l3 = 0;
	    		}
	    		if (cved_stat.is_l4){
	    			stats->is_l4 += cved_stat.is_l4;
	    			cved_stat.is_l4 = 0;
	    		}
	    		if (cved_stat.is_l5){
	    			stats->is_l5 += cved_stat.is_l5;
	    			cved_stat.is_l5 = 0;
	    		}
	    		if (cved_stat.is_l7){
	    			stats->is_l7 += cved_stat.is_l7;
	    			cved_stat.is_l7 = 0;
	    		}
	    		if (cved_stat.is_other){
	    			stats->is_other += cved_stat.is_other;
	    			cved_stat.is_other = 0;
	    		}
	    		if (cved_stat.is_error){
	    			stats->is_error += cved_stat.is_error;
	    			cved_stat.is_error = 0;
	    		}
		    	if (cved_page_ptr){
		  		  e = curl_easy_init();
		  		  curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, cved_write_data);
		  		  for (j = 0; j < MAX_PARALLEL; j++){
		  			  if (!cved_descrs[j].in_use){
		  				  cved_descrs[j].index = 0;
		  				  cved_descrs[j].in_use = 1;
		  				  curl_easy_setopt(e, CURLOPT_WRITEDATA, cved_descrs + j);
		  				  break;
		  			  }
		  		  }
		  		  if (j != MAX_PARALLEL){
					  curl_easy_setopt(e, CURLOPT_URL, cved_page_ptr->url);
					  curl_easy_setopt(e, CURLOPT_PRIVATE, cved_page_ptr->url);
					  curl_multi_add_handle(cm, e);
					  cved_page_ptr = cved_page_ptr->next;
		  		  }
		    	}
	    	}
	    	else {
	    		fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
	    	}
	    }
	    if(still_alive)
	      curl_multi_wait(cm, NULL, 0, 1000, NULL);

	  } while(still_alive || cved_page_ptr);

	  curl_multi_cleanup(cm);

	  for (i = 0; i < MAX_PARALLEL; i++){
		 free(cved_descrs[i].data);
	  }
	  sf_free_sb(cved_sb_searcht);
	  sf_free_sb(cved_sb_end);
	  sf_free_sb(cved_sb_L7);
	  sf_free_sb(cved_sb_L5);
	  sf_free_sb(cved_sb_L4);
	  sf_free_sb(cved_sb_L3);
	  sf_free_sb(cved_sb_L2);

	return 0;
}
