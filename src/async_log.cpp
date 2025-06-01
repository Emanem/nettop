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

#include "async_log.h"
#include <fstream>
#include <thread>
#include <ctime>
#include "utils.h"

void nettop::async_log::thread_proc(void) {
	while(!exit_) {
		// sleep for a bit
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
		// get the current list
		list_arena<sp_async_line>	cur_list;
		list_.swap(cur_list);
		if (!*ostr_)
			continue;
		auto fn_iter = [this](const sp_async_line& i) {
			const std::time_t	now_c = std::chrono::system_clock::to_time_t(i->get_tp());
			const size_t		now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(i->get_tp().time_since_epoch()).count()%1000;
			std::tm			now_tm;
			localtime_r(&now_c, &now_tm);
			char	tm_str[64];
			std::strftime(tm_str, 128, "%Y-%m-%d %H:%M:%S.%%03d", &now_tm);
			char	tm_full_str[64];
			std::snprintf(tm_full_str, 64, tm_str, now_ms);
			(*ostr_) << tm_full_str << " " << i->log(nr_) << std::endl;
		};
		cur_list.iterate(fn_iter);
	}
}

nettop::async_log::async_log(volatile bool& e, name_res& nr, const std::string& fname, nettop::async_log_list& list) : exit_(e), nr_(nr), ostr_(new std::ofstream(fname.c_str(), std::ios_base::app)), list_(list) {
	if(!fname.empty()) {
		if(!*ostr_)
			throw runtime_error("Can't open file \"") << fname << "\" to write async_log";
		(*ostr_) << "Log opened/appended" << std::endl;
	}
	thrd_ = std::shared_ptr<std::thread>(new std::thread(&async_log::thread_proc, this));
}

nettop::async_log::~async_log() {
	if(thrd_)
		thrd_->join();
}

