/*
 *   Copyright (c) 2021
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Canonical Ltd.
 */

#ifndef __AA_FILE_CACHE_H
#define __AA_FILE_CACHE_H

#include <set>
#include <string>

/* TODO: have includecache be a frontend for file cache, don't just
 * store name.
 */
class IncludeCache_t final {
public:
	std::set<std::string> cache;

	IncludeCache_t() = default;

	/* return true if in set */
	bool find(const char *name) {
		return cache.find(name) != cache.end();
	}

	bool insert(const char *name) {
		std::pair<std::set<std::string>::iterator,bool> res = cache.insert(name);
		if (res.second == false) {
			return false;
		}
		/* inserted */

		return true;
	}
};

#endif /* __AA_FILE_CACHE_H */
