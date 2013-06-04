/* map between user/group IDs and names
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SHOULD_USERMAP_H__
#define __SHOULD_USERMAP_H__ 1

#include <sys/types.h>

/* translate between IDs and names; this is all collected in a
 * separate module because the thread-safe version of getpw* and
 * getgr* can be a bit awkward to use; moreover we are not really
 * interested in any of the other information which comes in the
 * passwd and group entries so we moved them out of sight.
 *
 * usermap_fromname and groupmap_fromname return the ID if the name
 * is found, otherwise the second (default) parameter.
 *
 * usermap_fromid and groupmap return 0 if the ID is not known,
 * 1 if known, and -1 if the buffer provided is too small.
 */

uid_t usermap_fromname(const char *, uid_t);
int usermap_fromid(uid_t, char *, int);

gid_t groupmap_fromname(const char *, gid_t);
int groupmap_fromid(gid_t, char *, int);

#endif /* __SHOULD_USERMAP_H__ */
