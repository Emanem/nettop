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

#ifndef _NAME_RES_H_
#define _NAME_RES_H_

#include "addr_t.h"
#include "mt_list.h"
#include <thread>
#include <string>
#include <mutex>
#include <map>

namespace nettop {
	typedef mt_list<addr_t>		async_addr_list;

	class name_res {
		name_res(const name_res&) = delete;
		name_res& operator=(const name_res&) = delete;

		volatile bool&			exit_;
		async_addr_list			list_;
		std::shared_ptr<std::thread>	thrd_;
		std::mutex			mtx_;
		std::map<addr_t, std::string>	addr_map_;
		
		void thread_proc(void);
public:
		name_res(volatile bool& e);

		std::string to_str(const addr_t& in);
		
		~name_res();
	};
} 

#endif //_NAME_RES_H_

