/*
 * search_functions.h
 *
 *  Created on: Feb 21, 2020
 *      Author: root
 */

#ifndef SEARCH_FUNCTIONS_H_
#define SEARCH_FUNCTIONS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SF_TABLE_SIZE (256*256)

struct hash_el
{
	char* 				word;
	unsigned int 		word_len;
	unsigned int 		index;
	struct hash_el* 	next;
};

struct search_body
{
	char** 				words;
	unsigned int 		wordc;
	unsigned int 		word_min_len;
	struct hash_el* 	table[SF_TABLE_SIZE];
};

typedef int (*sf_event_handler)(char* word, char* next, char* last);

struct search_body* 	sf_init_sb 					(char*);
char*					sf_find_left 				(struct search_body*, char*, unsigned int);
char*					sf_find_next 				(struct search_body*, char*, unsigned int);
int						sf_call_event_handler 		(struct search_body*, char*, unsigned int, sf_event_handler eventHandler);
int 					sf_free_sb 					(struct search_body*);

#endif /* SEARCH_FUNCTIONS_H_ */
