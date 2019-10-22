#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pcap.h>
#include <map>
#include <vector>

using namespace std;

struct session 
{
	uint32_t sender_ip;
	uint32_t target_ip;
};

extern uint8_t my_mac[6], my_ip[4];
extern int session_cnt;
extern map<uint32_t, uint8_t*> ip2mac;
extern pcap_t *fp;
extern vector<session> ip_vector;

struct ether_header {
	uint8_t	ether_dhost[6];
	uint8_t	ether_shost[6];
	uint16_t ether_type;
};

struct arp_header {
	uint16_t arp_hrd;
	uint16_t arp_pro;
	uint8_t arp_hln;
	uint8_t arp_pln;
	uint16_t arp_op;
	uint8_t arp_sha[6];
	uint8_t arp_spa[4];
	uint8_t arp_tha[6];
	uint8_t arp_tpa[4];
};

struct ip_header {
	uint8_t ip_vhl;		
	uint8_t ip_tos;		
	uint16_t ip_len;		
	uint16_t ip_id;		
	uint16_t ip_off;		
#define IP_RF 0x8000		
#define IP_DF 0x4000		
#define IP_MF 0x2000		
#define IP_OFFMASK 0x1fff	
	uint8_t ip_ttl;		
	uint8_t ip_p;		
	uint16_t ip_sum;		
	uint32_t ip_src,ip_dst; 
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

void get_my_ip(char * interface);

void get_my_mac(char * interface);

void get_mac(uint8_t * sender_mac, uint8_t * sender_ip);

void send_pkt(uint8_t * d_mac, uint8_t * s_mac, uint8_t * f_mac, uint8_t * d_ip, uint8_t * s_ip, uint16_t arp_operand);

void pkt_relay_recover(unsigned char *param,const struct pcap_pkthdr *header,const unsigned char *pkt_data);

void arp_infection(session s);

void add_to_num(char * address, uint8_t * ip);
