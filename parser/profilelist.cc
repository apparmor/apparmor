#include <stdio.h>

#include "profilelist.h"
#include "profile.h"

bool deref_profileptr_lt::operator()(Profile * const &lhs, Profile * const &rhs) const
{
	return *lhs < *rhs;
};

std::pair<ProfileList::iterator,bool> ProfileList::insert(Profile *p)
{
	return list.insert(p);
}

void ProfileList::erase(ProfileList::iterator pos)
{
	list.erase(pos);
}

void ProfileList::clear(void)
{
	for(ProfileList::iterator i = list.begin(); i != list.end(); ) {
		ProfileList::iterator k = i++;
		delete *k;
		list.erase(k);
	}
}

void ProfileList::dump(void)
{
	for(ProfileList::iterator i = list.begin(); i != list.end(); i++) {
		(*i)->dump();
	}
}

void ProfileList::dump_profile_names(bool children)
{
	for (ProfileList::iterator i = list.begin(); i != list.end();i++) {
		(*i)->dump_name(true);
		printf("\n");
		if (children && !(*i)->hat_table.empty())
			(*i)->hat_table.dump_profile_names(children);
	}
}
