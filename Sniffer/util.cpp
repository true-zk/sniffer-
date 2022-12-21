#include "pch.h"
#include"util.h"

//vs安全性

#pragma warning(disable : 4996)
#define strcpy(a,b) strcpy_s((a),strlen((b))+1, (b)) 
#define strcat(a,b) strcat_s((a), strlen((a))+strlen((b))+1, (b))

/* DL */
bool analyze_frame(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_sum++;
	int i = 0;
	struct ethhdr* ethhead = (struct ethhdr*)pkt_data;
	if ((package_T->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr))) == NULL)
		return 1;
	for (i = 0; i < 6; i++)
	{
		package_T->ethh->dest[i] = ethhead->dest[i];
		package_T->ethh->src[i] = ethhead->src[i];
	}
	//type 为short类型 ntohs：net_short->host_short
	package_T->ethh->type = ntohs(ethhead->type);
	//分析网络层 指针移位到网络层包头部开始
	u_char* pkt_data_net = (u_char*)pkt_data + 14;
	switch (package_T->ethh->type)
	{
	case MACTYPE_IP:
		return analyze_ip(pkt_data_net, package_T, pktcount_T);
		break;
	case MACTYPE_ARP:
		return analyze_arp(pkt_data_net, package_T, pktcount_T);
		break;
	case MACTYPE_IP6:
		return analyze_ip6(pkt_data_net, package_T, pktcount_T);
		break;
	default:
		pktcount_T->n_other++;
		return -1;
		break;
	}
	return 0;
}

/*网络层*/
bool analyze_ip(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_ip++;
	struct iphdr* iphead = (struct iphdr*)pkt_data;
	if ((package_T->iph = (struct iphdr*)malloc(sizeof(struct iphdr))) == NULL)
		return 1;
	package_T->iph->version = iphead->version;
	package_T->iph->ihl = iphead->ihl;
	package_T->iph->tos = iphead->tos;
	package_T->iph->tlen = ntohs(iphead->tlen);
	package_T->iph->id = ntohs(iphead->id);
	package_T->iph->frag_off = iphead->frag_off;
	package_T->iph->ttl = iphead->ttl;
	package_T->iph->proto = iphead->proto;
	package_T->iph->check = iphead->check;
	package_T->iph->saddr = iphead->saddr;
	package_T->iph->daddr = iphead->daddr;
	package_T->iph->op_pad =  iphead->op_pad;
	//ipheadlength以4字节为单位
	u_char* pkt_data_t = (u_char*)pkt_data + 4 * iphead->ihl;
	switch (iphead->proto)
	{
	case 1:
		return analyze_icmp(pkt_data_t, package_T, pktcount_T);
		break;
	case 6:
		return analyze_tcp(pkt_data_t, package_T, pktcount_T);
		break;
	case 17:
		return analyze_udp(pkt_data_t, package_T, pktcount_T);
		break;
	default:
		return 1;
		break;
	}
	return 0;
}
bool analyze_ip6(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_ip6++;
	int i = 0;
	struct iphdr6* ip6head = (struct iphdr6*)pkt_data;
	if ((package_T->iph6 = (struct iphdr6*)malloc(sizeof(struct iphdr6))) == NULL)
		return 1;

	package_T->iph6->version = ip6head->version;
	package_T->iph6->flowtype = ip6head->flowtype;
	package_T->iph6->flowid = ip6head->flowid;
	package_T->iph6->plen = ntohs(ip6head->plen);
	package_T->iph6->nh = ip6head->nh;
	package_T->iph6->hlim = ip6head->hlim;
	for (i = 0; i < 8; i++)
	{
		package_T->iph6->saddr[i] = ntohs( ip6head->saddr[i]);
		package_T->iph6->daddr[i] = ntohs( ip6head->daddr[i]);
	}
	u_char* pkt_data_t = (u_char*)pkt_data + 40;
	switch (ip6head->nh)
	{
	case 0x3a:
		return analyze_icmp6(pkt_data_t, package_T, pktcount_T);
		break;
	case 0x06:
		return analyze_tcp(pkt_data_t, package_T, pktcount_T);
		break;
	case 0x11:
		return analyze_udp(pkt_data_t, package_T, pktcount_T);
		break;
	default:
		return 1;
		break;
	}
	return 0;
}
bool analyze_arp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_arp++;
	strcpy(package_T->pktType, "ARP");
	int i = 0;
	struct arphdr* arphead = (struct arphdr*)pkt_data;
	if ((package_T->arph = (struct arphdr*)malloc(sizeof(struct arphdr))) == NULL)
		return 1;

	for (i = 0; i < 6; i++)
	{
		if (i < 4)
		{
			package_T->arph->ar_destip[i] = arphead->ar_destip[i];
			package_T->arph->ar_srcip[i] = arphead->ar_srcip[i];
		}
		package_T->arph->ar_destmac[i] = arphead->ar_destmac[i];
		package_T->arph->ar_srcmac[i] = arphead->ar_srcmac[i];
	}
	package_T->arph->ar_hln = arphead->ar_hln;
	package_T->arph->ar_hrd = ntohs(arphead->ar_hrd);
	package_T->arph->ar_op = ntohs(arphead->ar_op);
	package_T->arph->ar_pln = arphead->ar_pln;
	package_T->arph->ar_pro = ntohs(arphead->ar_pro);
	return 0;
}

/*icmp*/
bool analyze_icmp(const u_char* pkt_data, struct pkt_T *package_T, struct pktcount* pktcount_T)
{
	strcpy(package_T->pktType, "ICMP");
	pktcount_T->n_icmp++;
	struct icmphdr* icmphead = (struct icmphdr*)pkt_data;
	if ((package_T->icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr))) == NULL)
		return 1;
	package_T->icmph->chksum = icmphead->chksum;
	package_T->icmph->type = icmphead->type;
	package_T->icmph->code = icmphead->code;
	package_T->icmph->seq = icmphead->seq;
	return 0;
}
bool analyze_icmp6(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_icmp6++;
	strcpy(package_T->pktType, "ICMPv6");
	int i = 0;
	struct icmphdr6* icmp6head = (struct icmphdr6*)pkt_data;
	if ((package_T->icmph6 = (struct icmphdr6*)malloc(sizeof(struct icmphdr6))) == NULL)
		return 1;
	package_T->icmph6->chksum = icmp6head->chksum;
	package_T->icmph6->code = icmp6head->code;
	package_T->icmph6->seq = icmp6head->seq;
	package_T->icmph6->type = icmp6head->type;
	package_T->icmph6->op_len = icmp6head->op_len;
	package_T->icmph6->op_type = icmp6head->op_type;
	for (i = 0; i < 6; i++)
		package_T->icmph6->op_ethaddr[i] = icmp6head->op_ethaddr[i];
	return 0;
}
/*tcp udp*/
bool analyze_tcp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_tcp++;
	struct tcphdr* tcphead = (struct tcphdr*)pkt_data;
	if ((package_T->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr))) == NULL)
		return 1;
	package_T->tcph->ack_seq = ntohf(tcphead->ack_seq);
	package_T->tcph->check = tcphead->check;
	//标志位：
	package_T->tcph->doff = tcphead->doff;
	package_T->tcph->res1 = tcphead->res1;
	package_T->tcph->cwr = tcphead->cwr;
	package_T->tcph->ece = tcphead->ece;
	package_T->tcph->urg = tcphead->urg;
	package_T->tcph->ack = tcphead->ack;
	package_T->tcph->psh = tcphead->psh;
	package_T->tcph->rst = tcphead->rst;
	package_T->tcph->syn = tcphead->syn;
	package_T->tcph->fin = tcphead->fin;

	package_T->tcph->dport = ntohs(tcphead->dport);
	package_T->tcph->seq = ntohf(tcphead->seq);
	package_T->tcph->sport = ntohs(tcphead->sport);
	package_T->tcph->urg_ptr = tcphead->urg_ptr;
	package_T->tcph->window = ntohs(tcphead->window);
	package_T->tcph->opt = tcphead->opt;
	//依据端口判断应用层
	{
		tcphead->sport = ntohs(tcphead->sport);
		tcphead->dport = ntohs(tcphead->dport);
		if (tcphead->sport == 80 || tcphead->dport == 80)
			strcpy(package_T->pktType, "HTTP");
		else if (tcphead->sport == 21 || tcphead->dport == 21)
			strcpy(package_T->pktType, "FTP");
		else if (tcphead->sport == 443 || tcphead->dport == 443)
			strcpy(package_T->pktType, "HTTPS");
		else
			strcpy(package_T->pktType, "TCP");
	}
	return 0;
}
bool analyze_udp(const u_char* pkt_data, struct pkt_T* package_T, struct pktcount* pktcount_T)
{
	pktcount_T->n_udp++;
	struct udphdr* udphead = (struct udphdr*)pkt_data;

	if ((package_T->udph = (struct udphdr*)malloc(sizeof(struct udphdr))) == NULL)
		return 1;
	package_T->udph->check = udphead->check;
	package_T->udph->dport = ntohs(udphead->dport);
	package_T->udph->len = ntohs(udphead->len);
	package_T->udph->sport = ntohs(udphead->sport);
	{
		udphead->sport = ntohs(udphead->sport);
		udphead->dport = ntohs(udphead->dport);
		if (udphead->sport == 53 || udphead->dport == 53)
			strcpy(package_T->pktType, "DNS");
		else if (udphead->sport == 68 || udphead->dport == 68)
			strcpy(package_T->pktType, "DHCP");
		else
			strcpy(package_T->pktType, "UDP");
	}
	return 0;
}

/*将数据包以十六进制的方式打印*/
void print_packet_hex(const u_char* pkt_data, int size_pkt, CString* buf)
{
	int i = 0, j = 0, rowcount;
	u_char ch;

	for (i = 0; i < size_pkt; i += 16)
	{
		buf->AppendFormat(_T("%04x:  "), (u_int)i);
		rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);

		for (j = 0; j < rowcount; j++)
			buf->AppendFormat(_T("%02x  "), (u_int)pkt_data[i + j]);

		//不足16，用空格补足
		if (rowcount < 16)
			for (j = rowcount; j < 16; j++)
				buf->AppendFormat(_T("    "));

		for (j = 0; j < rowcount; j++)
		{
			ch = pkt_data[i + j];
			ch = isprint(ch) ? ch : '.'; //可打印则打印否则输出个.吧
			buf->AppendFormat(_T("%c"), ch);
		}
		buf->Append(_T("\r\n"));
		if (rowcount < 16)
			return;
	}
}




