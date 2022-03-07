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

#ifndef _ADDR_T_H_
#define _ADDR_T_H_

#include <netdb.h>
#include <cstring>
#include <string>

class addr_t {

       	typedef union {
               	in_addr         ipv4;
               	in6_addr        ipv6;
       	} ip_data;

       	int       af_type_;
       	ip_data   ip_data_;

       	static ip_data get_ip4_data(const void* b) {
               	ip_data ret;
                ret.ipv4 = *(in_addr*)b;
               	return ret;
       	}

	static ip_data get_ip6_data(const void* b) {
               	ip_data ret;
		ret.ipv6 = *(in6_addr*)b;
               	return ret;
       	}


public:
	addr_t() : af_type_(0) {
		std::memset(&ip_data_, 0x00, sizeof(ip_data));
	}

	addr_t(const int af_type) : af_type_(af_type) {
		std::memset(&ip_data_, 0x00, sizeof(ip_data));
		switch(af_type_) {
			case AF_INET:
				ip_data_.ipv4.s_addr = INADDR_ANY;
				break;
			case AF_INET6:
				ip_data_.ipv6 = IN6ADDR_ANY_INIT;
				break;
		}
	}

       	addr_t(const in_addr& ipv4) : af_type_(AF_INET), ip_data_(get_ip4_data(&ipv4)) {
	}

       	addr_t(const in6_addr& ipv6) : af_type_(AF_INET6), ip_data_(get_ip6_data(&ipv6)) {
       	}

       	addr_t(const addr_t& rhs) : af_type_(rhs.af_type_), ip_data_(rhs.ip_data_) {
       	}

	int get_af_type(void) const {
		return af_type_;
	}

	addr_t& operator=(const addr_t& rhs) {
		if(this != &rhs) {
			af_type_ = rhs.af_type_;
			ip_data_ = rhs.ip_data_;
		}
		return *this;
	}

	inline bool is_ipv6(void) const {
		return af_type_ == AF_INET6;
	}

	std::string to_str(const bool full_name = false, const int rec_calls = 0) const {
		const int	gni_flags = (full_name) ? 0 : NI_NUMERICHOST;
               	if(af_type_ == AF_INET) {
                       	struct sockaddr_in      in;
                       	in.sin_family = AF_INET;
                       	in.sin_port = 123;
                       	in.sin_addr = ip_data_.ipv4;
                       	char                    hbuf[NI_MAXHOST];
			if(const int rv = getnameinfo((const sockaddr*)&in, sizeof(struct sockaddr_in), hbuf, sizeof(hbuf), 0, 0, gni_flags)) {
				if(rec_calls > 1)
					return "<invalid host>";
				if(EAI_AGAIN == rv)
					return to_str(false, rec_calls+1);
			}
                       	return hbuf;
               	}
               	struct sockaddr_in6     in;
               	in.sin6_family = AF_INET6;
               	in.sin6_port = 123;
               	in.sin6_flowinfo = 0;
               	in.sin6_addr = ip_data_.ipv6;
               	in.sin6_scope_id = 0;
               	char                    hbuf[NI_MAXHOST];
		if(const int rv = getnameinfo((const sockaddr*)&in, sizeof(struct sockaddr_in6), hbuf, sizeof(hbuf), 0, 0, gni_flags)) {
			if(rec_calls > 1)
				return "<invalid host>";
			if(EAI_AGAIN == rv)
				return to_str(false, rec_calls+1);
		}
               	return hbuf;
       	}

       	friend bool operator==(const addr_t& lhs, const addr_t& rhs);

       	friend bool operator<(const addr_t& lhs, const addr_t& rhs);
};

inline bool operator==(const addr_t& lhs, const addr_t& rhs) {
        if(lhs.af_type_ == rhs.af_type_) {
                if(lhs.af_type_ == AF_INET) {
                        return lhs.ip_data_.ipv4.s_addr == rhs.ip_data_.ipv4.s_addr;
                }
                return !std::memcmp(&lhs.ip_data_.ipv6, &rhs.ip_data_.ipv6, sizeof(in6_addr));
        }
        return false;
}

inline bool operator<(const addr_t& lhs, const addr_t& rhs) {
        if(lhs.af_type_ == rhs.af_type_) {
                if(lhs.af_type_ == AF_INET) {
                        return lhs.ip_data_.ipv4.s_addr < rhs.ip_data_.ipv4.s_addr;
                }
                return std::memcmp(&lhs.ip_data_.ipv6, &rhs.ip_data_.ipv6, sizeof(in6_addr)) < 0;
        }
        return lhs.af_type_ < rhs.af_type_;
}

#endif //_ADDR_T_H_

