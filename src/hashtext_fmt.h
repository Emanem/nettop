/*
    This file is part of linux-hunter.

    linux-hunter is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    linux-hunter is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with linux-hunter.  If not, see <https://www.gnu.org/licenses/>.
 * */

#ifndef _HASHTEXT_FMT_H_
#define _HASHTEXT_FMT_H_

#include <cstdint>

namespace ht_fmt {
	static_assert(sizeof(uint32_t) == sizeof(wchar_t), "Size of wchar_t is not uint32_t");

	// definitions for formats
	// losely based on ncurses
	const uint32_t	ATTR = 		0x80000000,
	      		ON_BIT = 	0x40000000,
			OFF_BIT =	0x00000000,
			COLOR_BIT =	0x01000000,
			BOLD_BIT =	0x02000000,
			REVERSE_BIT =	0x04000000,
			DIM_BIT =	0x08000000;

	const uint32_t	BOLD_ON = ATTR | ON_BIT | BOLD_BIT,
	      		BOLD_OFF = ATTR | OFF_BIT | BOLD_BIT,
			REVERSE_ON = ATTR | ON_BIT | REVERSE_BIT,
			REVERSE_OFF = ATTR | OFF_BIT | REVERSE_BIT,
			DIM_ON = ATTR | ON_BIT | DIM_BIT,
			DIM_OFF = ATTR | OFF_BIT | DIM_BIT,
			BLUE_ON = ATTR | ON_BIT | COLOR_BIT | 0x000000FF,
			BLUE_OFF = ATTR | OFF_BIT | COLOR_BIT | 0x000000FF,
			MAGENTA_ON = ATTR | ON_BIT | COLOR_BIT | 0x00FF00FF,
			MAGENTA_OFF = ATTR | OFF_BIT | COLOR_BIT | 0x00FF00FF,
			YELLOW_ON = ATTR | ON_BIT | COLOR_BIT | 0x0000FFFF,
			YELLOW_OFF = ATTR | OFF_BIT | COLOR_BIT | 0x0000FFFF,
			GREEN_ON = ATTR | ON_BIT | COLOR_BIT | 0x00FF0000,
			GREEN_OFF = ATTR | OFF_BIT | COLOR_BIT | 0x00FF0000;

	static_assert(!(((uint32_t)L'#') & ATTR), "Escape ATTR bit conflicts with '#' symbol");
}

#endif //_HASHTEXT_FMT_H_

