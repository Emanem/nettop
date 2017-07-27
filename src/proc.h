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

#ifndef _PROC_H_
#define _PROC_H_

#include <sys/types.h>
#include <map>
#include <list>
#include <vector>
#include <memory>
#include "packet_stats.h"
#include "async_log.h"
#include "name_res.h"

namespace nettop {

	struct ext_sd {
		addr_t			addr;
		int			port;
		enum packet_stats::type t;

		ext_sd(const addr_t& addr_ = addr_t(), const int port_ = 0, const enum packet_stats::type t_ = packet_stats::type::PACKET_TCP) : addr(addr_), port(port_), t(t_) {
		}

		inline bool operator==(const ext_sd& rhs) const {
			return port == rhs.port && t == rhs.t && addr == rhs.addr;
		}

		inline bool operator<(const ext_sd& rhs) const {
			if(port == rhs.port) {
				if(t == rhs.t) {
					return addr < rhs.addr;
				}
				return t < rhs.t;
			}
			return port < rhs.port;
		}
	};

	typedef std::vector<ext_sd>	sd_vec;

	class proc_info {

		proc_info& operator=(const proc_info&) = delete;
	
	public:
		const pid_t		pid;
		const std::string	cmd;
		const sd_vec		sd_v;

		proc_info(const pid_t pid_, const std::string& cmd_, const sd_vec& sd_v_) : pid(pid_), cmd(cmd_), sd_v(sd_v_) {
		}

		proc_info(const proc_info& rhs) : pid(rhs.pid), cmd(rhs.cmd), sd_v(rhs.sd_v) {
		}
	
		inline bool operator==(const proc_info& rhs) const{
			return pid == rhs.pid;
		}

		inline bool operator<(const proc_info& rhs) const {
			return pid < rhs.pid;
		}
	};

	struct proc_stats {
		struct st {
			size_t	recv,
				sent,
				udp_t,
				tcp_t;

			st() : recv(0), sent(0), udp_t(0), tcp_t(0) {
			}
		};

		typedef std::map<addr_t, st>	addr_st_map;
	
		pid_t				pid;
		std::string			cmd;
		addr_st_map			addr_rs_map;
		std::pair<size_t, size_t>	total_rs;
		
		proc_stats(const pid_t pid_, const std::string& cmd_) : pid(pid_), cmd(cmd_), total_rs(std::pair<size_t, size_t>(0, 0)) {
		}
	};

	typedef std::vector<proc_stats>	ps_vec;

	class proc_mgr {
		typedef std::list<packet_stats>					ps_list;
		typedef std::map<proc_info, std::pair<ps_list, ps_list> >	proc_map;

		proc_map	p_map_;
	public:
		struct stats {
			size_t	total_pkts,
				proc_pkts,
				undet_pkts,
				unmap_r_pkts,
				unmap_s_pkts;
			double	min_ts,
				max_ts;

			stats() : total_pkts(0), proc_pkts(0), undet_pkts(0), unmap_r_pkts(0), unmap_s_pkts(0), min_ts(-1.0), max_ts(-1.0) {
			}
		};

		proc_mgr();

		void bind_packets(const std::list<packet_stats>& p_list, const local_addr_mgr& lam, ps_vec& out, stats& st, async_log_list& log_list);
	};
}

#endif //_PROC_H_

