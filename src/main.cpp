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

#include <iostream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <curses.h>
#include <csignal>
#include "utils.h"
#include "cap_mgr.h"
#include "proc.h"
#include "name_res.h"
#include "settings.h"
#include "epoll_stdin.h"

// lior
#include <chrono>


namespace {
	volatile bool			quit = false,
					skip_sleep_time = true,
					paused = false;

	void sign_onexit(int param) {
		quit = true;
	}

	const char*			__version__ = "0.5";

	struct ps_sorted_iter {
		nettop::ps_vec::const_iterator					it_p_vec;
		std::vector<nettop::proc_stats::addr_st_map::const_iterator>	v_it_addr;

		ps_sorted_iter(nettop::ps_vec::const_iterator it_p_vec_) : it_p_vec(it_p_vec_) {
		}
	};

	typedef std::vector<std::shared_ptr<ps_sorted_iter> >		sorted_p_vec;



	void sort_filter_data(const nettop::ps_vec& p_vec, sorted_p_vec& out) {
		// copy the iterators into output vector
		out.resize(0);
		out.reserve(p_vec.size());
		for(nettop::ps_vec::const_iterator it = p_vec.begin(); it != p_vec.end(); ++it) {
			std::shared_ptr<ps_sorted_iter>	el(new ps_sorted_iter(it));
			el->v_it_addr.reserve(it->addr_rs_map.size());
			for(nettop::proc_stats::addr_st_map::const_iterator it_m = it->addr_rs_map.begin(); it_m != it->addr_rs_map.end(); ++it_m)
				el->v_it_addr.push_back(it_m);
			out.push_back(el);
		}
		// filter data if needed
		if(nettop::settings::FILTER_ZERO) {
			sorted_p_vec::iterator	it_erase = std::remove_if(out.begin(), out.end(), [](const std::shared_ptr<ps_sorted_iter>& ps){ return (ps->it_p_vec->total_rs.first + ps->it_p_vec->total_rs.second) == 0; });
			out.erase(it_erase, out.end());
		}
		// sort it (external)
		struct sort_fctr {
			bool operator()(const std::shared_ptr<ps_sorted_iter>& lhs, const std::shared_ptr<ps_sorted_iter>& rhs) {
				const size_t	lhs_sz = lhs->it_p_vec->total_rs.first + lhs->it_p_vec->total_rs.second,
						rhs_sz = rhs->it_p_vec->total_rs.first + rhs->it_p_vec->total_rs.second;
				return (nettop::settings::ORDER_TOP) ? lhs_sz > rhs_sz : lhs_sz < rhs_sz;
			}
		};
		std::sort(out.begin(), out.end(), sort_fctr());
		// sort it (internal)
		struct sort_fctr_int {
			bool operator()(const nettop::proc_stats::addr_st_map::const_iterator& lhs, const nettop::proc_stats::addr_st_map::const_iterator& rhs) {
				const size_t	lhs_sz = lhs->second.recv + lhs->second.sent,
						rhs_sz = rhs->second.recv + rhs->second.sent;
				return (nettop::settings::ORDER_TOP) ? lhs_sz > rhs_sz : lhs_sz < rhs_sz;
			}
		};
		for(auto& i : out) {
			std::sort(i->v_it_addr.begin(), i->v_it_addr.end(), sort_fctr_int());
		}
	}

	class curses_setup {
		WINDOW 			*w_;
		nettop::name_res&	nr_;
		const size_t		limit_hosts_;

		static char	BPS[],
				KBPS[],
				MBPS[],
				GBPS[];

		static void recv_send_format(const std::chrono::nanoseconds& tm_elapsed, const size_t recv, const size_t sent, double& recv_d, double& sent_d, const char* & fmt) {
			const double	tm_fct = 1000000000.0/tm_elapsed.count();
			const size_t	max_bytes = tm_fct*((recv > sent) ? recv : sent);
			if(max_bytes >= 1024*1024*1024) {
				const double	cnv_fct = 1.0/(1024.0*1024.0*1024.0);
				recv_d = cnv_fct*recv*tm_fct;
				sent_d = cnv_fct*sent*tm_fct;
				fmt = GBPS;
			} else if(max_bytes >= 1024*1024) {
				const double	cnv_fct = 1.0/(1024.0*1024.0);
				recv_d = cnv_fct*recv*tm_fct;
				sent_d = cnv_fct*sent*tm_fct;
				fmt = MBPS;
			} else if(max_bytes >= 1024) {
				const double	cnv_fct = 1.0/1024.0;
				recv_d = cnv_fct*recv*tm_fct;
				sent_d = cnv_fct*sent*tm_fct;
				fmt = KBPS;
			} else {
				recv_d = tm_fct*recv;
				sent_d = tm_fct*sent;
				fmt = BPS;
			}
		}
	public:
		curses_setup(nettop::name_res& nr, const size_t limit_hosts = 0) : w_(initscr()), nr_(nr), limit_hosts_(limit_hosts) {
		}
		
		~curses_setup() {
			endwin();
		}

		void draw_paused(void) {
			int 		row = 0; // number of terminal rows
        		int 		col = 0; // number of terminal columns
        		getmaxyx(stdscr, row, col);      /* find the boundaries of the screeen */
			if(col < 60 || row < 5) {
				refresh();
				return;
			}

			static const char	PAUSED[] = "--- PAUSED ---";
			const size_t		p_offset = (col - std::strlen(PAUSED))/2;
			attron(A_BOLD);
			mvprintw(1, p_offset, "%s", PAUSED);
			attroff(A_BOLD);
			refresh();
		}
	
		void redraw(const std::chrono::nanoseconds& tm_elapsed, const sorted_p_vec& s_v, const size_t total_pkts, const nettop::proc_mgr::stats& st) {
			clear();
			int 		row = 0; // number of terminal rows
        		int 		col = 0; // number of terminal columns
        		getmaxyx(stdscr, row, col);      /* find the boundaries of the screeen */
			// UI coordinates:
			// 6     2 23                     2 9        2 9        2 5
			// PIDXXX  cmdlineXXXXXXXXXXXXXXXX  recvXXXXX  sentXXXXX  KiB/s
			if(col < 60 || row < 5) {
				mvprintw(0, 0, "Need at least a screen of 60x5 (%d/%d)", col, row);
				refresh();
				return;
			}
			const size_t	cmdline_len = col - (6+2+9+2+9+2+6+3);
			int		cur_row = 2;
			size_t		tot_recv = 0,
					tot_sent = 0;
			// print header
			attron(A_REVERSE);
			mvprintw(cur_row++, 0, "%-6s  %-*s  %-9s  %-9s        ", "PID", cmdline_len, "CMDLINE", "RECV", "SENT");
			attroff(A_REVERSE);
			// print each entity
			for(const auto& sp_i : s_v) {
				// print each process row
				const auto&	i = *(sp_i->it_p_vec);
				std::string	r_cmd = i.cmd; r_cmd.resize(cmdline_len);
				double		r_d = 0.0,
						s_d = 0.0;
				const char*	fmt = "";
				recv_send_format(tm_elapsed, i.total_rs.first, i.total_rs.second, r_d, s_d, fmt);
				tot_recv += i.total_rs.first;
				tot_sent += i.total_rs.second;
				// if we don't have more UI space, don't bother printing this row..
				if(cur_row >= row-1)
					continue;
				attron(A_BOLD);
				mvprintw(cur_row++, 0, "%6d  %-*s %10.2f %10.2f  %-5s", i.pid, cmdline_len, r_cmd.c_str(), r_d, s_d, fmt);
				attroff(A_BOLD);
				// print each server txn
				size_t	cur_hosts = 0;
				for(const auto& sp_j : sp_i->v_it_addr) {
					if(limit_hosts_ && cur_hosts >= limit_hosts_) {
						attron(A_DIM);
						mvprintw(cur_row++, 0, "           ...");
						attroff(A_DIM);
						break;
					}
					const auto&	j = *sp_j;
					const size_t	host_line = cmdline_len-3,
							tot_t = j.second.udp_t + j.second.tcp_t,
							udp_p = (tot_t) ? 100.0*j.second.udp_t/(j.second.udp_t + j.second.tcp_t) : 0,
							tcp_p = (tot_t) ? 100 - udp_p : 0;
					char		tcp_udp_buf[32] = "[ na/ na] ";
					if(tot_t) {
						std::snprintf(tcp_udp_buf, 32, "[%3lu/%3lu] ", tcp_p, udp_p);
					}
					char		buf[256];
					std::snprintf(buf, 256, "%s%s", (nettop::settings::TCP_UDP_TRAFFIC) ? tcp_udp_buf : "", nr_.to_str(j.first).c_str());
					std::string	r_host = buf; r_host.resize(host_line);
					recv_send_format(tm_elapsed, j.second.recv, j.second.sent, r_d, s_d, fmt);
					attron(A_DIM);
					mvprintw(cur_row++, 0, "           %-*s %10.2f %10.2f  %-5s", host_line, r_host.c_str(), r_d, s_d, fmt);
					attroff(A_DIM);
					++cur_hosts;
				}
			}
			// print the totals and header
			double		r_d = 0.0,
					s_d = 0.0;
			const char*	fmt = "";
			recv_send_format(tm_elapsed, tot_recv, tot_sent, r_d, s_d, fmt);
			char	total_buf[128];
			snprintf(total_buf, 128, "%s [%5.2fs (%5lu/%5lu/%5lu/%5lu/%5lu)]", 
				__version__, 1.0*tm_elapsed.count()/1000000000.0, st.total_pkts, st.total_pkts-st.proc_pkts, st.undet_pkts, st.unmap_r_pkts, st.unmap_s_pkts);
			mvprintw(0, 0, "nettop %-*s", cmdline_len-6, total_buf);
			mvprintw(0, cmdline_len+1, "  Total %10.2f %10.2f  %-5s", r_d, s_d, fmt);
			refresh();
		}
	};

	char	curses_setup::BPS[] = "Byte/s",
		curses_setup::KBPS[] = "KiB/s ",
		curses_setup::MBPS[] = "MiB/s ",
		curses_setup::GBPS[] = "GiB/s ";

	struct stdin_exit : public utils::epoll_stdin {
		virtual bool on_data(const char* p, const size_t sz) const {
			for(size_t i = 0; i < sz; ++i) {
				switch(p[i]) {
				case 27: // ESC key
				case 'q':
					quit = true;
					break;
				case ' ':
				case 'p':
					paused = !paused;
					return true;	// do refresh after this!
					break;
				default:
					break;
				}
			}
			return false;
		}
	};

	struct auto_quit {
		auto_quit() {}
		~auto_quit() { quit = true; }
	};
}



int main(int argc, char *argv[]) {
	try {
		using namespace std::chrono;

		// setup signal functions
		std::signal(SIGINT, sign_onexit);
		std::signal(SIGTERM, sign_onexit);
		// parse settings and params
		nettop::parse_args(argc, argv, argv[0], __version__);

		nettop::packet_list		p_list;
		nettop::cap_mgr			c;
		nettop::local_addr_mgr		lam;
		nettop::async_log_list		log_list;
		nettop::name_res		nr(quit, nettop::settings::NO_RESOLVE);
		nettop::async_log		al(quit, nr, nettop::settings::ASYNC_LOG_FILE, log_list);
		// create cap thread
		std::thread			cap_th(&nettop::cap_mgr::async_cap, &c, std::ref(p_list), std::ref(quit));
		cap_th.detach();
		// init curses
		curses_setup			c_window(nr, nettop::settings::LIMIT_HOSTS_ROWS);
		system_clock::time_point	latest_time = std::chrono::system_clock::now();
		// initi epoll_stdin
		stdin_exit			ep_exit;
		// automatically set quit to true when
		// exiting this scope
		auto_quit	aq_;

		while(!quit) {
			// initialize all required structures and the processes too
			nettop::proc_mgr	p_mgr;
			nettop::proc_mgr::stats	mgr_st;
			nettop::ps_vec		p_vec;
			// wait for some time
			if(skip_sleep_time) {
				skip_sleep_time = false;
			} else {
				size_t	total_msec_slept = 0;
				while(!quit && !skip_sleep_time) {
					const size_t	sleep_interval = 250;
					if(ep_exit.do_io(sleep_interval))
						break;
					total_msec_slept += sleep_interval;
					if(nettop::settings::REFRESH_SECS <= total_msec_slept/1000)
						break;
				}
			}
			// bind to known processes
			const system_clock::time_point 	cur_time = std::chrono::system_clock::now();
			// bind to local list and stats
			std::list<nettop::packet_stats>	ps_list;
			p_list.swap(ps_list);
			mgr_st.total_pkts = p_list.total_pkts.exchange(0);
			// get new packets (for the real total counter, we are using an atomic type)
			// _mostly_ accurate
			if(!paused) {
				// bind to known processes
				p_mgr.bind_packets(ps_list, lam, p_vec, mgr_st, log_list);
				// sort
				sorted_p_vec	s_v;
				sort_filter_data(p_vec, s_v);
				// redraw now
				c_window.redraw(cur_time - latest_time, s_v, ps_list.size(), mgr_st);
			} else {
				c_window.draw_paused();
			}
			// set latest time
			latest_time = cur_time;
		}
	} catch(const std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
	} catch(...) {
		std::cerr << "Unknown exception" << std::endl;
	}
}

