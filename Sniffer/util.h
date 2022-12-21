#pragma once
#include "Protocol.h"
#ifndef UTIL_H
#define UTIL_H
/*  ���µ��ϴ��⵽��Э�����
	���к������ǳɹ�����0
	���ɹ�����1
	����ʱ��if(func(...))�������쳣
*/
/* DL */
bool analyze_frame(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);

/*�����*/
bool analyze_ip(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_ip6(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_arp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);

/*icmp*/
bool analyze_icmp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_icmp6(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
/*tcp udp*/
bool analyze_tcp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_udp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);

/*�����ݰ���ʮ�����Ƶķ�ʽ��ӡ*/
void print_packet_hex(const u_char* pkt_data, int size_pkt, CString* buf);

#endif

