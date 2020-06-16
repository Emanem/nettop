/*
*	nettop (C) 2017-2020 E. Oriani, ema <AT> fastwebnet <DOT> it
*
*	This file is part of nettop.
*
*	nettop is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	nettop is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with nettop.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "cap_mgr.h"
#include "utils.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <chrono>
#include <thread>
#include <atomic>
#include "addr_t.h"

namespace {

	typedef std::list<nettop::packet_stats>	st_pkt_list;

	// linux cooked header
	// glanced from libpcap/ssl.h
	#define SLL_ADDRLEN     	(8)               /* length of address field */
	#define SLL_PROTOCOL_IP		(0x0008)
	#define SLL_PROTOCOL_IP6	(0xDD86)
	struct sll_header {
        	u_int16_t	sll_pkttype;          /* packet type */
        	u_int16_t	sll_hatype;           /* link-layer address type */
        	u_int16_t	sll_halen;            /* link-layer address length */
        	u_int8_t	sll_addr[SLL_ADDRLEN]; /* link-layer address */
        	u_int16_t	sll_protocol;         /* protocol */
	};

	inline void process_tcp(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len, const addr_t& src, const addr_t& dst) {
		const struct tcphdr	*tcp = (struct tcphdr*)data;
		const uint16_t		p_src = ntohs(tcp->source),
					p_dst = ntohs(tcp->dest);
		p_list.push_back(nettop::packet_stats(src, dst, p_src, p_dst, len, nettop::packet_stats::type::PACKET_TCP, ts));
	}

	inline void process_udp(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len, const addr_t& src, const addr_t& dst) {
		const struct udphdr	*udp = (struct udphdr*)data;
		const uint16_t		p_src = ntohs(udp->source),
					p_dst = ntohs(udp->dest);
		p_list.push_back(nettop::packet_stats(src, dst, p_src, p_dst, len, nettop::packet_stats::type::PACKET_UDP, ts));
	}

	inline void process_ip(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len) {
		const struct ip *ip = (struct ip*)data;
		const addr_t	src(ip->ip_src),
				dst(ip->ip_dst);
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				process_tcp(data + sizeof(struct ip), p_list, ts, len, src, dst);
				break;
			case IPPROTO_UDP:
				process_udp(data + sizeof(struct ip), p_list, ts, len, src, dst);
				break;
			default:
				//std::cerr << "Unknown ip protocol " << (int)ip->ip_p << ", skipping packet" << std::endl;
				break;
		}
	}

	inline void process_ip6(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len) {
		const struct ip6_hdr	*ip6 = (struct ip6_hdr*)data;
		const addr_t		src(ip6->ip6_src),
					dst(ip6->ip6_dst);
		switch(ip6->ip6_nxt) {
			case IPPROTO_TCP:
				process_tcp(data + sizeof(struct ip6_hdr), p_list, ts, len, src, dst);
				break;
			case IPPROTO_UDP:
				process_udp(data + sizeof(struct ip6_hdr), p_list, ts, len, src, dst);
				break;
			default:
				//std::cerr << "Unknown ip protocol " << (int)ip6->ip6_nxt << ", skipping packet" << std::endl;
				break;
		}
	}

	void p_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {
		const struct sll_header *sll = (struct sll_header*)data;
		st_pkt_list& 		p_list = *(st_pkt_list*)user;
		const double		ts = nettop::tv_to_sec(header->ts);
		switch(sll->sll_protocol) {
			case SLL_PROTOCOL_IP:
				process_ip(data + sizeof(struct sll_header), p_list, ts, header->len);
				break;
			case SLL_PROTOCOL_IP6:
				process_ip6(data + sizeof(struct sll_header), p_list, ts, header->len);
				break;
			default:
				//std::cerr << "Unknown SLL protocol " << (int)sll->sll_protocol << ", skipping packet" << std::endl;
				break;
		}
	}
}

nettop::cap_mgr::cap_mgr() : p_(0) {
	// open all network devices
	char	err[PCAP_ERRBUF_SIZE+1];
	p_ = pcap_open_live(NULL, BUFSIZ, 0, 250, err);
	if(!p_)
		throw runtime_error(err);
	// only support Linux Cooked Socket link!
	const int link_type = pcap_datalink(p_);
	if(DLT_LINUX_SLL != link_type) {
		pcap_close(p_);
		throw runtime_error("Link type: ") << link_type << ", only DLT_LINUX_SLL (" << DLT_LINUX_SLL << ") supported!";
	}
}

nettop::cap_mgr::~cap_mgr() {
	pcap_close(p_);
}

void nettop::cap_mgr::capture_dispatch(packet_list& p_list) {
	st_pkt_list	lcl_list;
	const int dres = pcap_dispatch(p_, -1, p_handler, (u_char*)&lcl_list);
	// we never call pcap_breakloop
	if(-1 == dres)
		throw runtime_error(pcap_geterr(p_));
	p_list.push_many(lcl_list);
	p_list.total_pkts += dres;
}

void nettop::cap_mgr::async_cap(packet_list& p_list, volatile bool& quit) {
	while(!quit) {
		capture_dispatch(p_list);
	}
}

