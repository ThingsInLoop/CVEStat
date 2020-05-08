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

#include "search_functions.h"

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
static const char*
L7_NAMES =     "ADC|AFP|BACnet|BitTorrent|BOOTP|DIAMETER|DICOM|DICT|DNS|DHCP|ED2K|FTP|Finger|Gnutella|Gopher|HTTP|IMAP|IRC|ISUP|XMPP|LDAP|MIME|MSNP|MAP|NetBIOS|NNTP|NTP|"
		"NTCIP|POP3|RADIUS|Rlogin|rsync|RTP|RTSP|SSH|SISNAPI|SIP|SMTP|SNMP|SOAP|STUN|TUP|Telnet|TCAP|TFTP|WebDAV|DSM|RDP";

static const char*
L5_NAMES =		"9P|NCP|NFS|SMB|SOCKS|L2TP";

static const char*
L4_NAMES =		"AH|ESP|GRE|IL|SCTP|Sinec H1|SPX|TCP|UDP";

static const char*
L3_NAMES =		"CLNP|EGP|EIGRP|ICMP|IGMP|IGRP|IPv4|IPv6|IPsec|IPX|SCCP|AppleTalk|IS-IS|OSPF|BGP|RIP|IRDP|GDP";

static const char*
L2_NAMES =		"Attached|ATM|CDP|DCAP|DTP|Econet|FDDI|Frame|CCITT|HDLC|802.11|WiFi|802.16|LocalTalk|L2F|L2TP|LAPD|LLDP|LLDP-MED|PPP|PPTP|Q.710|NDP|RPR|Shortest|SLIP|StarLAN|"
		"STP|Token|VTP|ATM|Frame|MPLS|X.25|ARP|RARP|ARCNET|Ethernet";

struct all_pages {
	char* url;
	struct all_pages* next;
};

struct descriptor {
	void* data;
	unsigned long index;
	unsigned char in_use;
};

#define KB							(1024)
#define MB 							(1024 * KB)
#define MAX_PARALLEL				16
#define URL_START					"https://www.cvedetails.com"
#define CVE_DETAILS_PAGES_NMB		(sizeof(CVE_DETAILS_PAGES) / sizeof(char*))
#define L7_NAMES_NMB				(sizeof(L7_NAMES) / sizeof(char*))

#define HTML_END					"</html>"
#define PADDING_START				"id=\"pagingb\""
#define PADDING_END					"id=\"footer"
#define PADDING_PAGE_ADDR_START		"href=\""
#define PADDING_PAGE_ADDR_END		"title=\"Go to page"

#define SEARCHT_START				"vulnslisttable"
#define SEARCHT_END					"pagingb"
#define SEARCHT_DATA				"srrowns"
#define SEARCHT_TEXT				"cvesummarylong"

#define L7_PREFIX					"L7"
#define L5_PREFIX					"L5"
#define L4_PREFIX					"L4"
#define L3_PREFIX					"L3"
#define L2_PREFIX					"L2"
#define OTHER_PREFIX				"Other"

#define STAT_PREPARATION			1
#define STAT_PROCESSING				2
#define STAT_STOPPED				3

#endif /* VULSTAT_H_ */
