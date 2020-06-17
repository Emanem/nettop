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

#include "packet_stats.h"
#include <algorithm>
#include <ifaddrs.h>
#include <list>
#include "utils.h"

nettop::local_addr_mgr::local_addr_mgr() {
	struct ifaddrs		*ifaddr = 0, 
				*ifa = 0;
        int  			n = 0;

	if(-1 == getifaddrs(&ifaddr))
		throw runtime_error("Failure in getifaddrs");
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
                	continue;
		const int family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) {
			const struct sockaddr_in	*sa = (struct sockaddr_in*)ifa->ifa_addr;
			local_addrs_.insert(addr_t(sa->sin_addr));
		} else if(family == AF_INET6) {
			const struct sockaddr_in6	*sa = (struct sockaddr_in6*)ifa->ifa_addr;
			local_addrs_.insert(addr_t(sa->sin6_addr));
		}
	}
	freeifaddrs(ifaddr);
}

bool nettop::local_addr_mgr::is_local(const addr_t& in) const {
	return local_addrs_.find(in) != local_addrs_.end();
}

