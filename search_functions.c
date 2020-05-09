/*
 * search_functions.c
 *
 *  Created on: Feb 21, 2020
 *      Author: root
 */

#include "search_functions.h"

/**
 * Initial function. Purpose - create string searcher
 *  body.
 * @param str
 * Search pattern. Can include alternation symbol "|"
 * @return
 * Struct of string searcher body. search_body* ptr
 */
struct search_body* sf_init_sb(char* str)
{
	struct search_body* sb = (struct search_body*)malloc(sizeof(struct search_body));
	if (!sb)
		return NULL;
	memset(sb, 0, sizeof(struct search_body));

	unsigned int len = strlen(str);
	unsigned int i;
	unsigned int j;
	unsigned int el_number = 0;
	struct hash_el* tmp = NULL;
	int wordlen = 0;

	for (i = 0; i < len - 1; i++){
		if (str[i + 1] == '|' && (i + 1) != len && str[i] != '\\'){
			sb->wordc++;
		}
	}
	sb->wordc++;
	sb->words = malloc(sizeof(char*) * sb->wordc);
	sb->wordc = 0;

	for (i = 0, j = 0; i < len; i++){
		if ((i + 1) != len && str[i + 1] == '|' && str[i] != '\\' && str[i] != '|'){
			sb->words[sb->wordc] = malloc(sizeof(char) * (i - j + 2));
			memcpy(sb->words[sb->wordc], str + j, i - j + 1);
			sb->words[sb->wordc][i - j + 1] = '\0';
			sb->wordc++;
			for (j = i + 1; str[j] == '|'; j++);
			i++;
		}
	}
	if (len > 0){
		sb->words[sb->wordc] = malloc(sizeof(char) * (i - j + 2));
		memcpy(sb->words[sb->wordc], str + j, i - j + 1);
		sb->words[sb->wordc][i - j + 1] = '\0';
		sb->wordc++;
	}


	for (i = 0; i < sb->wordc; i++){
		wordlen = strlen(sb->words[i]);
		if (sb->word_min_len == 0 || sb->word_min_len > wordlen)
			sb->word_min_len = wordlen;
		for (j = 0; j < wordlen - 1; j++){
			el_number = *((unsigned short*)(sb->words[i] + j));
			if (sb->table[el_number]){
				for (tmp = sb->table[el_number]; tmp->next; tmp = tmp->next);
				tmp->next = malloc(sizeof(struct hash_el));
				tmp = tmp->next;
				tmp->next = NULL;
				tmp->index = j;
				tmp->word = sb->words[i];
				tmp->word_len = strlen(sb->words[i]);
			} else {
				sb->table[el_number] = malloc(sizeof(struct hash_el));
				sb->table[el_number]->next = NULL;
				sb->table[el_number]->index = j;
				sb->table[el_number]->word = sb->words[i];
				sb->table[el_number]->word_len = strlen(sb->words[i]);
			}
		}
	}

	return sb;
}

/**
 * Freeing memory after use of search body.
 * @param sb
 * Struct search_body* to be freed
 * @return
 * 0
 */
int sf_free_sb (struct search_body* sb)
{
	unsigned int i;

	if (!sb)
		return -1;

	if (sb->words){
		for (i = 0; i < sb->wordc; i++){
			if(sb->words[i])
				free(sb->words[i]);
		}
		free(sb->words);
	}

	for (i = 0; i < SF_TABLE_SIZE; i++){
		free(sb->table[i]);
	}

	return 0;
}

int sf_free_hash_el(struct hash_el* h_el)
{
	if (h_el){
		sf_free_hash_el(h_el->next);
		free(h_el);
	}

	return 0;
}

/**
 * Search for left character of match.
 * @param sb
 * Search body struct pointer. Body with search pattern.
 * @param haystack
 * Where to find pattern.
 * @param len
 * Length of haystack in bytes.
 * @return
 * char* ptr - pointer to first char after pattern in haystack.
 * NULL
 */
char* sf_find_left (struct search_body* sb, char* haystack, unsigned int len)
{
	unsigned int i;
	struct hash_el* tmp;

	if (len < 2)
		return NULL;

	for (i = sb->word_min_len - 2; i < len; i += sb->word_min_len - 1){
		for (tmp = sb->table[*((unsigned short*)(haystack + i))]; tmp; tmp = tmp->next){
			if (tmp->index <= i && !memcmp(tmp->word, haystack + i - tmp->index, tmp->word_len)){
				return haystack + i - tmp->index;
			}
		}
	}
	i = len - 2;
	if ((tmp = sb->table[*((unsigned short*)(haystack + i))])){
		if (tmp->index <= i && !memcmp(tmp->word, haystack + i - tmp->index, tmp->word_len)){
			return haystack + i - tmp->index;
		}
	}

	return NULL;
}

/**
 * Search for right next character after match.
 * @param sb
 * Search body struct pointer. Body with search pattern.
 * @param haystack
 * Where to find pattern.
 * @param len
 * Length of haystack in bytes.
 * @return
 * char* ptr - pointer to next char after pattern in haystack.
 * NULL - no matches.
 */
char* sf_find_next (struct search_body* sb, char* haystack, unsigned int len)
{
	unsigned int i;
	struct hash_el* tmp;

	if (len < 2)
		return NULL;

	for (i = sb->word_min_len - 2; i < len; i += sb->word_min_len - 1){
		for (tmp = sb->table[*((unsigned short*)(haystack + i))]; tmp; tmp = tmp->next){
			if (tmp->index <= i && !memcmp(tmp->word, haystack + i - tmp->index, tmp->word_len)){
				return haystack + i - tmp->index + tmp->word_len;
			}
		}
	}
	i = len - 2;
	if ((tmp = sb->table[*((unsigned short*)(haystack + i))])){
		if (tmp->index <= i && !memcmp(tmp->word, haystack + i - tmp->index, tmp->word_len)){
			return haystack + i - tmp->index + tmp->word_len;
		}
	}

	return NULL;
}

int sf_call_event_handler (struct search_body* sb, char* haystack, unsigned int len, sf_event_handler eventHandler)
{
	unsigned int i;
	struct hash_el* tmp;
	unsigned char found= 0;

	if (len < 2)
		return 0;

	for (i = sb->word_min_len - 2; i < len; i += sb->word_min_len - 1){
		for (tmp = sb->table[*((unsigned short*)(haystack + i))]; tmp; tmp = tmp->next){
			if (tmp->index <= i && !memcmp(tmp->word, haystack + i - tmp->index, tmp->word_len)){
				found = 1;
				if (eventHandler(tmp->word, haystack + i - tmp->index + tmp->word_len, haystack + len)){
					return 0;
				}
				i += strlen(tmp->word);
			}
		}
	}
	i = len - 2;
	if ((tmp = sb->table[*((unsigned short*)(haystack + i))])){
		if (tmp->index <= i && !memcmp(tmp->word, haystack + i - tmp->index, tmp->word_len)){
			found = 1;
			eventHandler(tmp->word, haystack + i - tmp->index + tmp->word_len, haystack + len);
		}
	}

	if (found){
		return 0;
	} else {
		return -1;
	}
}
