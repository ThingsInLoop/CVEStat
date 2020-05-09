/*
 * prots.h
 *
 *  Created on: May 8, 2020
 *      Author: sasha
 */

#ifndef PROTS_H_
#define PROTS_H_

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


#ifndef MKBYTES_
#define MKBYTES_
#define KB							(1024)
#define MB 							(1024 * KB)
#endif

#define L7_PREFIX					"L7"
#define L5_PREFIX					"L5"
#define L4_PREFIX					"L4"
#define L3_PREFIX					"L3"
#define L2_PREFIX					"L2"
#define OTHER_PREFIX				"Other"

#endif /* PROTS_H_ */
