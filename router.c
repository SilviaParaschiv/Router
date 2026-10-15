#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

struct trie_node
{
	struct trie_node *child[2];
	struct route_table_entry *route;
};

struct trie_node *trie_root;

queue q;

struct waiting_packet
{
	char *buf;
	size_t len;
	int interface;
	uint32_t next_hop_ip;
};

struct trie_node *new_node(void)
{
	struct trie_node *node = calloc(1, sizeof(struct trie_node));
	return node;
}

int get_mask_len(uint32_t mask)
{
	int len = 0;
	mask = ntohl(mask);

	while (mask)
	{
		len++;
		mask <<= 1;
	}
	return len;
}

void build_trie(void)
{
	trie_root = new_node();

	for (int i = 0; i < rtable_len; i++)
	{
		struct route_table_entry *entry = &rtable[i];
		struct trie_node *node = trie_root;
		uint32_t net = ntohl(entry->prefix);
		int mask_bits = get_mask_len(entry->mask);
		int step = 31;

		while (mask_bits > 0)
		{
			int direction = (net >> step) & 1;

			if (!node->child[direction])
				node->child[direction] = new_node();

			node = node->child[direction];
			step--;
			mask_bits--;
		}
		node->route = entry;
	}
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{

	struct trie_node *node = trie_root;
	struct route_table_entry *best_route = NULL;
	uint32_t ip = ntohl(ip_dest);
	int bit = 31;

	while (node && bit >= 0)
	{
		if (node->route)
			best_route = node->route;

		//daca bitul bit din ip e 1
		if ((ip >> bit) & 1)
			node = node->child[1];
		else
			node = node->child[0];

		bit--;
	}

	if (node && node->route)
		best_route = node->route;

	return best_route;
}

struct arp_table_entry *get_arp_entry(uint32_t ip)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		struct arp_table_entry *entry = &arp_table[i];

		if (entry->ip == ip)
			return entry;
	}
	return NULL;
}

void add_arp_entry(uint32_t ip, uint8_t *mac)
{
	struct arp_table_entry *entry = get_arp_entry(ip);

	if (!entry)
	{
		struct arp_table_entry *new_entry = &arp_table[arp_table_len];

		new_entry->ip = ip;
		memcpy(new_entry->mac, mac, 6);
		arp_table_len++;
	}
	else
	{
		memcpy(entry->mac, mac, 6);
	}
}

void send_arp_request(uint32_t target_ip, int interface)
{
	char buf[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)] = {0};

	char *ptr = buf;
	struct ether_hdr *eth_hdr = (struct ether_hdr *)ptr;
	ptr = ptr + sizeof(struct ether_hdr);
	struct arp_hdr *arp_hdr = (struct arp_hdr *)ptr;

	for (int i = 0; i < 6; i++)
		eth_hdr->ethr_dhost[i] = 0xFF;

	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(0x0806);

	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1);

	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	arp_hdr->tprotoa = target_ip;

	send_to_link(sizeof(buf), buf, interface);
}

void send_arp_reply(struct arp_hdr *arp_request, int interface)
{

	char buf[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)] = {0};
	char *ptr = buf;
	struct ether_hdr *eth_hdr = (struct ether_hdr *)ptr;
	ptr = ptr + sizeof(struct ether_hdr);
	struct arp_hdr *arp_hdr = (struct arp_hdr *)ptr;

	memcpy(eth_hdr->ethr_dhost, arp_request->shwa, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(0x0806);

	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(2);

	get_interface_mac(interface, arp_hdr->shwa);
	memcpy(arp_hdr->thwa, arp_request->shwa, 6);

	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	arp_hdr->tprotoa = arp_request->sprotoa;

	send_to_link(sizeof(buf), buf, interface);
}

int is_router_ip(uint32_t ip_dest)
{
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
	{
		if (inet_addr(get_interface_ip(i)) == ip_dest)
			return 1;
	}

	return 0;
}

int get_interface_by_ip(uint32_t ip)
{
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
	{
		if (inet_addr(get_interface_ip(i)) == ip)
			return i;
	}
	return -1;
}

void send_icmp_echo(char *buf, size_t len, int interface)
{
	char *ptr = buf;

	struct ether_hdr *eth_hdr = (struct ether_hdr *)ptr;
	ptr = ptr + sizeof(struct ether_hdr);

	struct ip_hdr *ip_hdr = (struct ip_hdr *)ptr;
	ptr = ptr + sizeof(struct ip_hdr);

	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)ptr;

	uint32_t aux_ip = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = aux_ip;

	icmp_hdr->mtype = 0;
	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

	ip_hdr->ttl = 64;
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);

	send_to_link(len, buf, interface);
}

void send_icmp_error(char *old_buf, size_t old_len, uint8_t type, uint8_t code)
{
	char buf[MAX_PACKET_LEN] = {0};

	struct ip_hdr *old_ip_hdr = (struct ip_hdr *)(old_buf + sizeof(struct ether_hdr));

	struct route_table_entry *route = get_best_route(old_ip_hdr->source_addr);

	uint32_t next_hop_ip = route->next_hop;
	if (next_hop_ip == 0)
		next_hop_ip = old_ip_hdr->source_addr;

	struct arp_table_entry *arp_entry = get_arp_entry(next_hop_ip);

	int data_len = 8;
	if (old_len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + 8)
		data_len = old_len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);

	char *ptr = buf;

	struct ether_hdr *eth_hdr = (struct ether_hdr *)ptr;
	ptr = ptr + sizeof(struct ether_hdr);

	struct ip_hdr *ip_hdr = (struct ip_hdr *)ptr;
	ptr = ptr + sizeof(struct ip_hdr);

	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)ptr;

	memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
	get_interface_mac(route->interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(0x0800);
	uint16_t ip_total_len = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_len;

	ip_hdr->ver = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(ip_total_len);
	ip_hdr->id = htons(4);
	ip_hdr->frag = 0;
	ip_hdr->ttl = 64;
	ip_hdr->proto = 1;
	ip_hdr->source_addr = inet_addr(get_interface_ip(route->interface));
	ip_hdr->dest_addr = old_ip_hdr->source_addr;
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
	memcpy((uint16_t *)icmp_hdr + sizeof(struct icmp_hdr), old_ip_hdr, sizeof(struct ip_hdr) + data_len);

	icmp_hdr->mtype = type;
	icmp_hdr->mcode = code;
	icmp_hdr->check = 0;
	icmp_hdr->un_t.gateway_addr = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_len));

	uint16_t frame_total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_len;
	send_to_link(frame_total_len, buf, route->interface);
}

void init_packet(struct waiting_packet *pkt, char *buf, size_t len, int interface, uint32_t next_hop_ip)
{
	pkt->len = len;
	pkt->interface = interface;
	pkt->next_hop_ip = next_hop_ip;

	pkt->buf = malloc(len);
	memcpy(pkt->buf, buf, len);
}

int release_packet_if_ready(struct waiting_packet *packet, struct arp_hdr *arp)
{
	if (packet->next_hop_ip != arp->sprotoa)
		return 0;

	struct ether_hdr *eth_hdr = (struct ether_hdr *)packet->buf;

	for (int i = 0; i < 6; i++)
		eth_hdr->ethr_dhost[i] = arp->shwa[i];

	get_interface_mac(packet->interface, eth_hdr->ethr_shost);
	send_to_link(packet->len, packet->buf, packet->interface);

	free(packet->buf);
	free(packet);

	return 1;
}

int main(int argc, char *argv[])
{

	char buf[MAX_PACKET_LEN];

	/* Don't touch this */
	init(argv + 2, argc - 2);

	q = create_queue();

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory failed");

	arp_table = malloc(sizeof(struct arp_table_entry) * 1000);
	DIE(arp_table == NULL, "memory allocation failed");

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;

	build_trie();

	while (1)
	{
		size_t len;
		recv_from_any_link(buf, &len);

		if (len < sizeof(struct ether_hdr))
		{
			continue;
		}

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		if (ntohs(eth_hdr->ethr_type) == 0x0806)
		{

			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			add_arp_entry(arp_hdr->sprotoa, arp_hdr->shwa);

			uint16_t opcode = ntohs(arp_hdr->opcode);

			switch (opcode)
			{
			case 1:
			{
				if (is_router_ip(arp_hdr->tprotoa))
				{
					int reply_interface = -1;

					for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
					{
						if (inet_addr(get_interface_ip(i)) == arp_hdr->tprotoa)
						{
							reply_interface = i;
							break;
						}
					}

					if (reply_interface != -1)
						send_arp_reply(arp_hdr, reply_interface);
				}
				break;
			}
			case 2:
			{
				queue aux = create_queue();

				while (!queue_empty(q))
				{
					struct waiting_packet *pkt = queue_deq(q);

					if (!release_packet_if_ready(pkt, arp_hdr))
						queue_enq(aux, pkt);
				}

				q = aux;
				break;
			}

			default:
				break;
			}

			continue;
		}

		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		size_t ip_header_len = ip_hdr->ihl * 4;
		uint16_t old_checksum = ip_hdr->checksum;

		ip_hdr->checksum = 0;

		uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, ip_header_len));

		if (old_checksum != new_checksum)
			continue;

		ip_hdr->checksum = old_checksum;

		if (is_router_ip(ip_hdr->dest_addr))
		{
			if (ip_hdr->proto == 1 && len >= sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr))
			{
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

				if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0)
				{
					int reply_interface = get_interface_by_ip(ip_hdr->dest_addr);
					if (reply_interface != -1)
						send_icmp_echo(buf, len, reply_interface);
				}
			}
			continue;
		}

		if (ip_hdr->ttl <= 1)
		{
			send_icmp_error(buf, len, 11, 0);
			continue;
		}

		struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);
		if (best_route == NULL)
		{
			send_icmp_error(buf, len, 3, 0);
			continue;
		}

		ip_hdr->ttl--;
		ip_hdr->checksum = 0;
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ip_header_len));

		uint32_t next_hop_ip = best_route->next_hop;

		if (next_hop_ip == 0)
			next_hop_ip = ip_hdr->dest_addr;

		struct arp_table_entry *arp_entry = get_arp_entry(next_hop_ip);

		if (arp_entry == NULL)
		{
			struct waiting_packet *pkt = malloc(sizeof(struct waiting_packet));
			DIE(pkt == NULL, "malloc failed");

			init_packet(pkt, buf, len, best_route->interface, next_hop_ip);

			queue_enq(q, pkt);

			send_arp_request(next_hop_ip, best_route->interface);
			continue;
		}

		memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
		get_interface_mac(best_route->interface, eth_hdr->ethr_shost);

		send_to_link(len, buf, best_route->interface);
	}

	free(rtable);
	free(arp_table);

	return 0;
}
