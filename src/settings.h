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

#ifndef _SETTINGS_H_
#define _SETTINGS_H_

#include <cstdlib>
#include <string>

#define CAPTURE_SEND	(0x01)
#define CAPTURE_RECV	(0x02)
#define CAPTURE_ALL	(CAPTURE_SEND|CAPTURE_RECV)

namespace nettop { 
	namespace settings {
		extern size_t		REFRESH_SECS;
		extern int		CAPTURE_ASR;
		extern bool		ORDER_TOP;
		extern bool		FILTER_ZERO;
		extern bool		TCP_UDP_TRAFFIC;
		extern bool		NO_RESOLVE;
		extern std::string	ASYNC_LOG_FILE;
		extern size_t		LIMIT_HOSTS_ROWS;
		extern std::string	VKDTO_FILE;
	}

	int parse_args(int argc, char *argv[], const char *prog, const char *version);
}

#endif //_SETTINGS_H_

