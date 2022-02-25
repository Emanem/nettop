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

#ifndef _PACKET_STATS_H_
#define _PACKET_STATS_H_

#include "addr_t.h"
#include <set>

namespace nettop {

	class packet_stats {
		packet_stats& operator=(const packet_stats&) = delete;
	public:
		enum type {
			PACKET_TCP = 0,
			PACKET_UDP
		};

		const addr_t	src,
				dst;
		const uint16_t	p_src,
				p_dst;
		const size_t	len;
		const enum type	t;
		const double	ts;

		//const uint64_t	recognized_process_index;
		packet_stats(const addr_t& src_, const addr_t& dst_, const uint16_t p_src_, const uint16_t p_dst_, const size_t len_, const enum type t_, const double ts_) : src(src_), dst(dst_), p_src(p_src_), p_dst(p_dst_), len(len_), t(t_), ts(ts_) {
		}

		packet_stats(const packet_stats& rhs) : src(rhs.src), dst(rhs.dst), p_src(rhs.p_src), p_dst(rhs.p_dst), len(rhs.len), t(rhs.t), ts(rhs.ts) {
		}
	};

	class local_addr_mgr {
		std::set<addr_t>	local_addrs_;
	public:
		local_addr_mgr();

		bool is_local(const addr_t& in) const;
	};
}

#endif //_PACKET_STATS_H_

