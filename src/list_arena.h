/*
*	nettop (C) 2017-2025 E. Oriani, ema <AT> fastwebnet <DOT> it
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

#ifndef _LIST_ARENA_H_
#define _LIST_ARENA_H_

// this list has to satisfy the semantics of std::list::push_back,
// std::list::swap and size

template<typename T, size_t N_IDX = 16>
class list_arena {

	struct arena {

		arena(const arena&) = delete;
		arena operator=(const arena&) = delete;

		uint64_t	idx_vec[N_IDX];
		size_t		hint;
		arena		*next;
		T		buf[sizeof(uint64_t)*8*N_IDX];

		arena() : hint(0), next(0) {
			for(size_t i = 0; i < N_IDX; ++i)
				idx_vec[i] = 0;
		}

		T* get_slot(void) {
			for(size_t i = hint; i < N_IDX; ++i) {
				const int pos = __builtin_ffsll(~idx_vec[i]);
				if (pos > 0) {
					const int r_pos = pos-1;
					const size_t cur_idx = i*sizeof(uint64_t)*8 + r_pos;
					idx_vec[i] = (1ULL << r_pos) | idx_vec[i];
					hint = i;
					return &buf[cur_idx];
				}
			}
			return 0;
		}

		size_t size(void) const {
			if(next) {
				return sizeof(uint64_t)*8*N_IDX + next->size();
			}
			size_t cnt = 0;
			for(size_t i = 0; i < N_IDX; ++i)
				cnt += __builtin_popcountll(idx_vec[i]);
			return cnt;
		}

		arena* get_next(void) {
			if(next) return next;
			next = new arena();
			return next;
		}

		template<typename Fn>
		void iterate(Fn&& f) const {
			for(size_t i = 0; i < N_IDX; ++i) {
				for(size_t j = 0; j < sizeof(uint64_t)*8; ++j) {
					if((1ULL << j) & idx_vec[i]) {
						f(buf[i*sizeof(uint64_t)*8 + j]);
					}
				}
			}
			if(next) next->iterate(f);
		}

		~arena() {
			if(next) delete next;
		}
	};

	arena	*head_,
		*latest_;

public:
	list_arena(const list_arena&) = delete;
	list_arena& operator=(const list_arena&) = delete;

	list_arena() : head_(new arena()) {
		latest_ = head_;
	}

	void push_back(const T& t) {
		auto cur_p = latest_->get_slot();
		if (cur_p) {
			*cur_p = t;
			return;
		} else {
			latest_ = latest_->get_next();
			return push_back(t);
		}
	}

	size_t size(void) const {
		return head_->size();
	}

	void swap(list_arena& rhs) {
		std::swap(head_, rhs.head_);
		std::swap(latest_, rhs.latest_);
	}

	template<typename Fn>
	void iterate(Fn&& f) const {
		head_->iterate(f);
	}

	~list_arena() {
		delete head_;
	}
};

#endif //_LIST_ARENA_H_

