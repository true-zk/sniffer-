#pragma once
#include "Protocol.h"
#ifndef UTIL_H
#define UTIL_H
/*  从下到上从外到内协议分析
	所有函数都是成功返回0
	不成功返回1
	调用时用if(func(...))来处理异常
*/
/* DL */
bool analyze_frame(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);

/*网络层*/
bool analyze_ip(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_ip6(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_arp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);

/*icmp*/
bool analyze_icmp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_icmp6(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
/*tcp udp*/
bool analyze_tcp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);
bool analyze_udp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T);

/*将数据包以十六进制的方式打印*/
void print_packet_hex(const u_char* pkt_data, int size_pkt, CString* buf);

#endif

