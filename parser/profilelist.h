/*
 *   Copyright (c) 2025
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
 */
#ifndef __AA_PROFILELIST_H
#define __AA_PROFILELIST_H

#include <set>
#include <utility>

class Profile;

struct deref_profileptr_lt {
	bool operator()(Profile * const &lhs, Profile * const &rhs) const;
};

class ProfileList final {
public:
	std::set<Profile *, deref_profileptr_lt> list;

	typedef std::set<Profile *, deref_profileptr_lt>::iterator iterator;
	iterator begin() { return list.begin(); }
	iterator end() { return list.end(); }

	ProfileList() { };
	virtual ~ProfileList() { clear(); }
	virtual bool empty(void) { return list.empty(); }
	virtual std::pair<ProfileList::iterator,bool> insert(Profile *);
	virtual void erase(ProfileList::iterator pos);
	void clear(void);
	void dump(void);
	void dump_profile_names(bool children);
};

#endif /* __AA_PROFILELIST_H */
