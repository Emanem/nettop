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

#include "name_res.h"

void nettop::name_res::thread_proc(void) {
	while(!exit_) {
		std::list<addr_t>	lcl_list;
		list_.swap(lcl_list);
		for(const auto& i : lcl_list) {
			const std::string	full_nm = i.to_str(true);
			// add into the map
			{
				std::lock_guard<std::mutex>	lg(mtx_);
				addr_map_[i] = full_nm;
			} 
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
	}
}

nettop::name_res::name_res(volatile bool& e, bool do_not_resolve) : exit_(e) {
	thrd_ = std::shared_ptr<std::thread>(do_not_resolve ? 0 : new std::thread(&name_res::thread_proc, this));
}

std::string nettop::name_res::to_str(const addr_t& in) {
	// if we don't have a running thread
	// just return the IP address
	if (!thrd_)
		return in.to_str();
	// try to find if we have it
	std::lock_guard<std::mutex>	lg(mtx_);
	auto				it = addr_map_.find(in);
	if(addr_map_.end() == it) {
		const std::string	nm = in.to_str();
		addr_map_[in] = nm;
		list_.push(in);
		return nm;
	}
	return it->second;
}

nettop::name_res::~name_res() {
	if(thrd_)
		thrd_->join();
}

