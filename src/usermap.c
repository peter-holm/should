/* map between user/group IDs and names
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

#include "site.h"
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "usermap.h"

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

uid_t usermap_fromname(const char * uname, uid_t uid) {
    char ubuffer[sysconf(_SC_GETPW_R_SIZE_MAX)];
    struct passwd pwd, * pwb;
    if (getpwnam_r(uname, &pwd, ubuffer,
		   sizeof(ubuffer), &pwb) < 0)
	return uid;
    return pwd.pw_uid;
}

int usermap_fromid(uid_t uid, char * uname, int usize) {
    char ubuffer[sysconf(_SC_GETPW_R_SIZE_MAX)];
    struct passwd pwd, * pwb;
    if (getpwuid_r(uid, &pwd, ubuffer,
		   sizeof(ubuffer), &pwb) < 0)
	return 0;
    if (strlen(pwd.pw_name) >= usize)
	return -1;
    strcpy(uname, pwd.pw_name);
    return 1;
}

gid_t groupmap_fromname(const char * gname, gid_t gid) {
    char gbuffer[sysconf(_SC_GETGR_R_SIZE_MAX)];
    struct group grp, * grb;
    if (getgrnam_r(gname, &grp, gbuffer,
		   sizeof(gbuffer), &grb) < 0)
	return gid;
    return grp.gr_gid;
}

int groupmap_fromid(gid_t gid, char * gname, int gsize) {
    char gbuffer[sysconf(_SC_GETGR_R_SIZE_MAX)];
    struct group grp, * grb;
    if (getgrgid_r(gid, &grp, gbuffer,
		   sizeof(gbuffer), &grb) < 0)
	return 0;
    if (strlen(grp.gr_name) >= gsize)
	return -1;
    strcpy(gname, grp.gr_name);
    return 1;
}

