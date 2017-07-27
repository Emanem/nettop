/*
*	nettop (C) 2017 E. Oriani, ema <AT> fastwebnet <DOT> it
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

#include "proc.h"
#include "utils.h"
#include "settings.h"
#include <algorithm>
#include <dirent.h>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <set>
#include <sstream>

namespace {

	/* Parses /proc/<pid>/cmdline */
	std::string get_cmd_line(const pid_t pid) {
		char		cur_fd[64];
		std::snprintf(cur_fd, 64, "/proc/%i/cmdline", pid);
		// need to use C APIs...
		int fd = open(cur_fd, O_RDONLY);
		if(-1 == fd)
			return "(no cmd line)";
		char	buf[1024] = "";
		const int rb = read(fd, buf, 1024);
		if(rb >= 0) {
			const size_t max_rb = (1024 > rb) ? rb : 1024;
			for(size_t i = 0; i < max_rb; ++i) {
				if(buf[i] == '\0')
					buf[i] = ' ';
			}
			buf[max_rb-1] = '\0';
		}
		close(fd);
		return buf;
	}

	typedef std::vector<unsigned long>	v_inodes;

	// get the inodes for sockets only
	void get_sockets_inodes(const pid_t pid, v_inodes& out) {
		char		cur_fd[64];
		std::snprintf(cur_fd, 64, "/proc/%i/fd", pid);
		DIR*		dir = opendir(cur_fd);
		if(!dir)
			return;		
		for(struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
			// skip . and ..
			if(!std::strcmp(entry->d_name, ".") || !std::strcmp(entry->d_name, ".."))
				continue;
			// we're not interested in directories
        		if (entry->d_type == DT_DIR)
				continue;
			// prepare and read the sym link
			char		cur_sd[128],
					buf_sd[128];
			std::snprintf(cur_sd, 128, "/proc/%i/fd/%s", pid, entry->d_name);
			const size_t rb = readlink(cur_sd, buf_sd, 128);
			if(rb >= 128)
				buf_sd[127] = '\0';
			// check if it's a socket or not
			unsigned long	inode = 0;
			if(1 != std::sscanf(buf_sd, "socket:[%ld]", &inode))
				continue;
			// else add it ot the vector
			out.push_back(inode);
    		}
    		closedir(dir);
		std::sort(out.begin(), out.end());
	}

	// get an address from hex string
	inline const addr_t get_addr_hexstr(const char* addr_s) {
		const size_t	str_len = std::strlen(addr_s);
		addr_t		ret;
		switch(str_len) {
			case 8: {
				struct in_addr	in_local;
				if(1 != std::sscanf(addr_s, "%08X", &in_local.s_addr))
					throw nettop::runtime_error("Invalid ipv4 hex network address: \"") << addr_s << "\"";
				ret = addr_t(in_local);
			}	break;
			case 32: {
				struct in6_addr in6_local;
				if(4 != std::sscanf(addr_s, "%08X%08X%08X%08X", &in6_local.s6_addr32[0], &in6_local.s6_addr32[1], &in6_local.s6_addr32[2], &in6_local.s6_addr32[3]))
					throw nettop::runtime_error("Invalid ipv6 hex network address: \"") << addr_s << "\"";
				ret = addr_t(in6_local);
			} 	break;
			default:
				throw nettop::runtime_error("Invalid hex network address: \"") << addr_s << "\"";
				break;
		}
		return ret;
	}

	/* Parses /proc/<pid>/net/(tc|ud)p(6) lines of the following form:
  	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   	 0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15850 1 0000000000000000 100 0 0 10 0                     
   	 1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11154 1 0000000000000000 100 0 0 10 0                     
   	 2: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34652 1 0000000000000000 100 0 0 10 0                     
   	 3: 00000000:7199 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 79489 1 0000000000000000 100 0 0 10 0                     
   	 4: 00000000:01BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 727 1 0000000000000000 100 0 0 10 0                       
   	 5: 00000000:008B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 729 1 0000000000000000 100 0 0 10 0                       
   	 6: 0800A8C0:7199 24F63F4E:7CFC 01 00000000:00000000 00:00000000 00000000  1000        0 203505 1 0000000000000000 26 4 8 10 -1                    
   	 7: 0800A8C0:7199 24F63F4E:7D4E 01 00000000:00000000 00:00000000 00000000  1000        0 202262 1 0000000000000000 25 4 24 10 -1                   
   	 8: 0800A8C0:AB65 51480D1F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 201391 1 0000000000000000 22 4 28 10 -1                   
   	 9: 0800A8C0:E347 AB29C2AD:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 203276 1 0000000000000000 23 4 28 10 -1                   
  	10: 0800A8C0:C813 51480D1F:0050 06 00000000:00000000 03:00001662 00000000     0        0 0 3 0000000000000000                                      
  	11: 0800A8C0:A8CE 5442C2AD:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 198523 1 0000000000000000 22 4 30 10 -1                   
  	12: 0800A8C0:D66A D8B178D5:0050 06 00000000:00000000 03:00001662 00000000     0        0 0 3 0000000000000000                                      
  	13: 0800A8C0:9FCD AF29C2AD:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 198480 1 0000000000000000 20 4 26 10 -1                   
  	14: 0800A8C0:AF33 BB29C2AD:0050 06 00000000:00000000 03:000016C6 00000000     0        0 0 3 0000000000000000       
	Remember, multiple inodes can be mapped to same local <host>:<port>!                               	
	*/
	typedef std::map<nettop::ext_sd, std::vector<unsigned long> >	m_inodes;

	void get_sockets_raw(const bool tcp, const bool v6, m_inodes& out) {
		// open /proc directories and scan for all processes
		char		cur_fd[64];
		std::snprintf(cur_fd, 64, "/proc/net/%s%s", tcp ? "tcp" : "udp", v6 ? "6" : "");
		std::ifstream	istr(cur_fd);
		std::set<int>	lcl_ports;
		while(istr) {
			std::string cur_line;
			std::getline(istr, cur_line);
			char		rem_addr[128],
					local_addr[128];
			int 		local_port = -1,
					rem_port = -1;
			unsigned long	inode = 0;
			const int matches = std::sscanf(cur_line.c_str(), "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n", local_addr, &local_port, rem_addr, &rem_port, &inode);
			if(5 != matches || lcl_ports.end() != lcl_ports.find(local_port))
				continue;
			// get the address
			const addr_t		lcl_addr = get_addr_hexstr(local_addr);
			const nettop::ext_sd	esd(lcl_addr, local_port, tcp ? nettop::packet_stats::type::PACKET_TCP : nettop::packet_stats::type::PACKET_UDP);
			out[esd].push_back(inode);
			lcl_ports.insert(local_port);
		}
	}

	void get_all_sockets(m_inodes& out) {
		get_sockets_raw(true, false, out);
		get_sockets_raw(false, false, out);
		get_sockets_raw(true, true, out);
		get_sockets_raw(false, true, out);
		// now we need to sort all vectors of inodes
		for(auto& i : out)
			std::sort(i.second.begin(), i.second.end());
	}

	// async log events
	struct log_evt : public nettop::async_line {
		enum type {
			UNDET = 0,
			UNMAP_R,
			UNMAP_S
		};

		const nettop::packet_stats	ps;
		const type			t;

		log_evt(const nettop::packet_stats& ps_, const enum type t_) : ps(ps_), t(t_) {
		}

		virtual std::string log(nettop::name_res& nr) const {
			std::ostringstream	oss;
			switch(t) {
				case type::UNDET:
					oss << "UNDET  :";
					break;
				case type::UNMAP_R:
					oss << "UNMAP_R:";
					break;
				case type::UNMAP_S:
					oss << "UNMAP_S:";
					break;
			}
			oss << nr.to_str(ps.src) << ":" << ps.p_src << " --> " << nr.to_str(ps.dst) << ":" << ps.p_dst;
			return oss.str();
		}
	};

	nettop::sp_async_line gen_log(const nettop::packet_stats& ps, const enum log_evt::type t) {
		return nettop::sp_async_line(new log_evt(ps, t));
	}
}

nettop::proc_mgr::proc_mgr() {
	// get all the links between ext_sd --> inode
	m_inodes	inodes_link;
	get_all_sockets(inodes_link);
	// create reverse map
	std::map<unsigned long, m_inodes::const_iterator>	link_inodes;
	for(m_inodes::const_iterator it = inodes_link.begin(); it != inodes_link.end(); ++it)
		for(const auto& i : it->second)
			link_inodes[i] = it;
	// open /proc directories and scan for all processes
	DIR*		dir = opendir("/proc");
	if(!dir)
		throw runtime_error("Can't open /proc directory!");
	for(struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
		// skip . and ..
		if(!std::strcmp(entry->d_name, ".") || !std::strcmp(entry->d_name, ".."))
			continue;
		// we're only interested in directories
        	if (entry->d_type != DT_DIR)
			continue;
		// get the pid (again, has to be a precise number!)
		errno = 0;
		char            *endptr = 0;
                const pid_t 	pid = std::strtol(entry->d_name, &endptr, 10);
                if(errno || *endptr != '\0')
                        continue;
		// get all inodes
		v_inodes	inodes;
		get_sockets_inodes(pid, inodes);
		if(inodes.empty())
			continue;
		// find links to esd
		sd_vec		sds;
		for(const auto& i : inodes) {
			const auto	p_link_inodes = link_inodes.find(i);
			if(p_link_inodes == link_inodes.end())
				continue;
			sds.push_back(p_link_inodes->second->first);
		}
		if(sds.empty())
			continue;
		// get the command line
		const std::string	cmd_line = get_cmd_line(pid);
		// sort the vector
		std::sort(sds.begin(), sds.end());
		// initialize the map
		p_map_[proc_info(pid, cmd_line, sds)];
    	}
    	closedir(dir);
}

//#include <iostream>

void nettop::proc_mgr::bind_packets(const std::list<packet_stats>& p_list, const local_addr_mgr& lam, ps_vec& out, stats& st, async_log_list& log_list) {
	// create a utility map from port/proto/ipv --> pid
	std::map<ext_sd, proc_map::iterator>	sd_pid_map;
	for(proc_map::iterator it = p_map_.begin(); it != p_map_.end(); ++it) {
		//std::cout << it->first.pid << "(" << it->first.cmd << ")\t";
		for(const auto& i : it->first.sd_v) {
			//std::cout << "(" << i.t << ")" << i.addr.to_str() << ":" << i.port << "\t";
			if(sd_pid_map.end() != sd_pid_map.find(i)) {
				//std::cout << __FUNCTION__ << " " << i.addr.to_str() << ":" << i.port << "(" << i.t << ") local address is already mapped to another process!" << std::endl;
				continue;
			}
			sd_pid_map[i] = it;
		}
		//std::cout << std::endl;
	}
	// Identify the process 0 (as kernel). All unmapped packet will go there...
	proc_map::iterator	it_kernel = p_map_.find(proc_info(-1, "(kernel)", sd_vec()));
	if(it_kernel == p_map_.end()) {
		it_kernel = p_map_.insert(std::make_pair<proc_info, std::pair<ps_list, ps_list> >(proc_info(-1, "(kernel)", sd_vec()), std::pair<ps_list, ps_list>())).first;
	}
	// first assign packets to processes
	for(const auto& i : p_list) {
		// refresh timestamp stats - this is a coarse measurement
		if(st.min_ts < 0.0 || st.min_ts > i.ts)
			st.min_ts = i.ts;
		if(st.max_ts < 0.0 || st.max_ts < i.ts)
			st.max_ts = i.ts;
		// exclude packets where src and dst are the same (they should not impact over the network)
		// the kernel should be smart enough to let them "live" on shared memory only when those are
		// localhost --> localhost...
		if(i.dst == i.src)
			continue; 
		const bool	is_recv = lam.is_local(i.dst),
				is_sent = lam.is_local(i.src);
		if(!(is_recv ^ is_sent)) {
			log_list.push(gen_log(i, log_evt::type::UNDET));
			++st.undet_pkts;
			continue;
		}
		// from this point we're sure about a packet has been sent or received...
		if(is_recv && (settings::CAPTURE_ASR & CAPTURE_RECV)) {
			const ext_sd	cur_sd(i.dst, i.p_dst, i.t);
			auto 		it = sd_pid_map.find(cur_sd);
			if(it == sd_pid_map.end()) {
				// last resort, if we can't find it, we should try with the default ANY address (0.0.0.0)
				const ext_sd	cur_sd_ANY(addr_t(i.dst.get_af_type()), i.p_dst, i.t);
				it = sd_pid_map.find(cur_sd_ANY);
				if(it == sd_pid_map.end()) {
					log_list.push(gen_log(i, log_evt::type::UNMAP_R));
					++st.unmap_r_pkts;
					it_kernel->second.first.push_back(i);
					continue;
				}
			}
			it->second->second.first.push_back(i);
		} else if(settings::CAPTURE_ASR & CAPTURE_SEND) {
			const ext_sd	cur_sd(i.src, i.p_src, i.t);
			auto 		it = sd_pid_map.find(cur_sd);
			if(it == sd_pid_map.end()) {
				// last resort, if we can't find it, we should try with the default ANY address (0.0.0.0)
				const ext_sd	cur_sd_ANY(addr_t(i.src.get_af_type()), i.p_src, i.t);
				it = sd_pid_map.find(cur_sd_ANY);
				if(it == sd_pid_map.end()) {
					log_list.push(gen_log(i, log_evt::type::UNMAP_S));
					++st.unmap_s_pkts;
					it_kernel->second.second.push_back(i);
					continue;
				}
			}
			it->second->second.second.push_back(i);
		}
		++st.proc_pkts;
	}
	// now prepare output structure
	out.reserve(p_map_.size());
	for(const auto& i : p_map_) {
		proc_stats	ps(i.first.pid, i.first.cmd);
		for(const auto& r : i.second.first) {
			ps.total_rs.first += r.len;
			proc_stats::st& cur_stats = ps.addr_rs_map[r.src];
			cur_stats.recv += r.len;
			switch(r.t) {
				case packet_stats::type::PACKET_TCP:
					cur_stats.tcp_t += r.len;
					break;
				case packet_stats::type::PACKET_UDP:
					cur_stats.udp_t += r.len;
					break;
			} 
		}
		for(const auto& r : i.second.second) {
			ps.total_rs.second += r.len;
			proc_stats::st& cur_stats = ps.addr_rs_map[r.dst];
			cur_stats.sent += r.len;
			switch(r.t) {
				case packet_stats::type::PACKET_TCP:
					cur_stats.tcp_t += r.len;
					break;
				case packet_stats::type::PACKET_UDP:
					cur_stats.udp_t += r.len;
					break;
			}
		}
		out.push_back(ps);
	}
}

