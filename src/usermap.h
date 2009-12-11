#ifndef __SHOULD_USERMAP_H__
#define __SHOULD_USERMAP_H__ 1

/* map between user/group IDs and names
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

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
