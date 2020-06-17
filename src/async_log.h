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

#ifndef _ASYNC_LOG_H_
#define _ASYNC_LOG_H_

#include "mt_list.h"
#include <memory>
#include <chrono>
#include <string>
#include <fstream>
#include <thread>
#include "name_res.h"

namespace nettop {
	class async_line {
		const std::chrono::system_clock::time_point	tp_;		

		async_line(const async_line&) = delete;
		async_line& operator=(const async_line&) = delete;
public:
		async_line() : tp_(std::chrono::system_clock::now()) {
		}

		const std::chrono::system_clock::time_point& get_tp(void) {
			return tp_;
		}

		virtual std::string log(name_res& nr) const = 0;

		virtual ~async_line() {
		};
	};

	typedef std::shared_ptr<async_line>	sp_async_line;
	typedef mt_list<sp_async_line>		async_log_list;

	class async_log {
		async_log(const async_log&) = delete;
		async_log& operator=(const async_log&) = delete;

		volatile bool&			exit_;
		name_res&			nr_;
		std::shared_ptr<std::ostream>	ostr_;
		async_log_list&			list_;
		std::shared_ptr<std::thread>	thrd_;
		
		void thread_proc(void);
public:
		async_log(volatile bool& e, name_res& nr, const std::string& fname, async_log_list& list);
		
		~async_log();
	};
}

#endif //_ASYNC_LOG_H_

