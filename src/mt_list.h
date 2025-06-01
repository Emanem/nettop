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

#ifndef _MT_LIST_H_
#define _MT_LIST_H_

#include <mutex>
#include <list>
#include <algorithm>
#include "list_arena.h"

template<typename T>
class mt_list {
	
	mt_list(const mt_list&) = delete;
	mt_list& operator=(const mt_list&) = delete;
	
	std::mutex	mtx_;
	list_arena<T>	list_;
public:
	mt_list() {}

	~mt_list() {}

	void push(const T& in) {
		std::lock_guard<std::mutex>	lg(mtx_);
		list_.push_back(in);
	}

	void push_many(const list_arena<T>& in) {
		std::lock_guard<std::mutex>	lg(mtx_);
		auto fn_iter = [this](const T& t) {
			list_.push_back(t);
		};
		in.iterate(fn_iter);
	}

	void swap(list_arena<T>& out) {
		std::lock_guard<std::mutex>	lg(mtx_);
		list_.swap(out);
	}
};

#endif //_MT_LIST_H_

