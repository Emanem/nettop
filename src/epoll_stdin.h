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

#ifndef _EPOLL_STDIN_
#define _EPOLL_STDIN_

#include <sys/epoll.h>
#include <unistd.h>
#include "utils.h"

namespace utils {

	class epoll_stdin {
		int	efd_;
	public:
		epoll_stdin() : efd_(epoll_create1(0)) {
			if(-1 == efd_)
				throw nettop::runtime_error("Can't created epoll fd: ") << strerror(errno);
			// add stdin
			struct epoll_event event = {0};
    			event.events = EPOLLIN|EPOLLPRI|EPOLLERR;
    			event.data.fd = STDIN_FILENO;
    			if(epoll_ctl(efd_, EPOLL_CTL_ADD, STDIN_FILENO, &event)) {
				close(efd_);
				throw nettop::runtime_error("Can't add STDIN to epoll fd: ") << strerror(errno);
			}
		}

		// return true when need to do a refresh
		bool do_io(const size_t msec_tmout) {
			struct epoll_event	event = {0};
			const int		fds = epoll_wait(efd_, &event, 1, msec_tmout);
			if(0 == fds) return false;
			else if (0 > fds) {
				if(EINTR == errno)
					return false;
				throw nettop::runtime_error("Error in epoll_wait: ") << strerror(errno);
			}
			// we can only get 1 event at max...
			if (event.data.fd == STDIN_FILENO) {
				char		buf[128];
            			// read input line
            			const int	rb = read(STDIN_FILENO, &buf, 128);
				if(rb > 0) {
					return on_data(buf, rb);
				} else throw nettop::runtime_error("Error in reading STDIN: ") << strerror(errno);
			}
			return false;
		}

		virtual bool on_data(const char* p, const size_t sz) const = 0;

		virtual ~epoll_stdin() {
			close(efd_);
		}
	};

}

#endif //_EPOLL_STDIN_

