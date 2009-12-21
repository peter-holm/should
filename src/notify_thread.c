/* should's notify thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>
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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "notify_thread.h"
#if NOTIFY != NOTIFY_NONE

#if NOTIFY == NOTIFY_INOTIFY
# if INOTIFY == SYS_INOTIFY
#  include <sys/inotify.h>
# else
#  include <inotify-nosys.h>
# endif
# define EVENT struct inotify_event
# define ADDWATCH(w) inotify_add_watch(inotify_fd, w, i_mask)
# define RMWATCH(w) inotify_rm_watch(inotify_fd, w)
#endif

#include <sys/poll.h>
#include <fcntl.h>
#if DIRENT_TYPE == DIRENT
#include <dirent.h>
#else
#include <sys/dirent.h>
#endif
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include "main_thread.h"
#include "config.h"
#include "error.h"
#include "mymalloc.h"

#if NOTIFY == NOTIFY_INOTIFY
#define CREATE_EVENT (IN_CREATE | IN_MOVED_TO)
#define DELETE_EVENT (IN_DELETE | IN_MOVED_FROM)
#define CHANGE_EVENT (IN_CLOSE_WRITE)
#define ATTRIB_EVENT (IN_ATTRIB)
#define RENAME_EVENT (IN_MOVED_FROM | IN_MOVED_TO)
#endif

#define MAXPATHCOM 256
#define NAME_LIMIT sizeof(char *)

/* used to store one queue allocation block */
typedef struct queue_block_s queue_block_t;
struct queue_block_s {
    queue_block_t * next;
    const char * read_pos;
    int read_bytes;
    int read_count;
    char * write_pos;
    int write_space;
    char event[0];
};

/* forward declatation, see below */

typedef struct watch_block_s watch_block_t;

/* used to store one watch */

struct notify_watch_s {
    notify_watch_t * sibling;
    notify_watch_t * parent;
    notify_watch_t * subdir[NAME_HASH];
    notify_watch_t * next_by_id;
    notify_watch_t * next_by_inode;
    const config_add_t * how;
    watch_block_t * block_ptr;
    ino_t inode;
    dev_t device;
    int forward;
    int watch_id;
    int locked;
    int name_length;
    int name_hash;
    char name[0];
};

/* used to store a block of watches */

struct watch_block_s {
    watch_block_t * next, * prev;
    int used;
    int unused;
    notify_watch_t w[0];
};

/* used to find watches by device and inode */

typedef struct watch_by_device_s watch_by_device_t;
struct watch_by_device_s {
    watch_by_device_t * next;
    dev_t device;
    notify_watch_t * w[WATCH_HASH];
};

/* used to cache a copy of the "how" (crossmount, exclude) information-
 * so we do not need to keep a pointer to configuration data which then
 * cannot be freed */

typedef struct how_cache_s how_cache_t;
struct how_cache_s {
    how_cache_t * next;
    config_add_t how;
};

static queue_block_t * first_block, * write_block, * read_block;
static int notify_queue_block, overflow, too_big;
static int event_count, watch_count, max_events, max_bytes;
static int queue_events, queue_bytes, queue_blocks;
static int notify_initial, watch_memory, watch_active;
static how_cache_t * how_cache = NULL;

#if NOTIFY == NOTIFY_INOTIFY
static int inotify_fd = -1;
static int i_mask = IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
		    IN_DELETE_SELF | IN_MOVED_FROM | IN_MOVED_TO |
		    IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED;
#endif

static watch_block_t * all_watches;
static notify_watch_t * id_to_watch[WATCH_HASH];
static watch_by_device_t * dev_to_watch = NULL;
static unsigned int notify_watch_block;

static pthread_mutex_t queue_lock, how_lock;
static pthread_cond_t queue_read_cond, queue_write_cond;

static notify_watch_t * root_watch;

static char * event_buffer;
static int buffer_size, buffer_extra;

/* used to store events in the queue */

typedef struct {
    notify_event_type_t event_type;
    int from_length;
    int to_length;
    int is_dir;
} queue_event_t;

/* determines how much space needs to be allocated to an event */

static int event_size(const queue_event_t * event) {
    int size = sizeof(queue_event_t);
    if (event->from_length > 0)
	size += event->from_length;
    if (event->to_length > 0)
	size += event->to_length;
#if USE_SHOULDBOX
    if (size < sizeof(queue_event_t)) {
	main_shouldbox++;
	error_report(error_shouldbox_less, "event_size",
		     "size", (int)sizeof(queue_event_t));
    }
#endif
    return size;
}

/* allocates a new block of events */

static const char * allocate_block(queue_block_t * after) {
    queue_block_t * new_block =
	mymalloc(sizeof(queue_block_t) + notify_queue_block);
    if (! new_block) return error_sys("allocate_block", "malloc");
    new_block->next = after ? after->next : first_block;
    new_block->read_pos = new_block->event;
    new_block->read_bytes = 0;
    new_block->read_count = 0;
    new_block->write_pos = new_block->event;
    new_block->write_space = notify_queue_block;
    if (after)
	after->next = new_block;
    else 
	first_block = new_block;
    queue_blocks++;
    return NULL;
}

/* deallocates queue */

static void deallocate_queue(void) {
    while (first_block) {
	queue_block_t * this = first_block;
	first_block = first_block->next;
	myfree(this);
    }
    pthread_cond_destroy(&queue_write_cond);
    pthread_cond_destroy(&queue_read_cond);
    pthread_mutex_destroy(&queue_lock);
    pthread_mutex_destroy(&how_lock);
}

/* initialise event queue */

static const char * initialise_queue(const config_data_t * cfg) {
    int code;
    notify_queue_block = config_intval(cfg, cfg_notify_queue_block);
    notify_initial = config_intval(cfg, cfg_notify_initial);
    code = pthread_mutex_init(&queue_lock, NULL);
    if (code)
	return error_sys_errno("initialise_queue", "pthread_mutex_init", code);
    code = pthread_mutex_init(&how_lock, NULL);
    if (code) {
	pthread_mutex_destroy(&queue_lock);
	return error_sys_errno("initialise_queue", "pthread_mutex_init", code);
    }
    code = pthread_cond_init(&queue_read_cond, NULL);
    if (code) {
	pthread_mutex_destroy(&how_lock);
	pthread_mutex_destroy(&queue_lock);
	return error_sys_errno("initialise_queue", "pthread_cond_init", code);
    }
    code = pthread_cond_init(&queue_write_cond, NULL);
    if (code) {
	pthread_cond_destroy(&queue_read_cond);
	pthread_mutex_destroy(&how_lock);
	pthread_mutex_destroy(&queue_lock);
	return error_sys_errno("initialise_queue", "pthread_cond_init", code);
    }
    first_block = NULL;
    queue_blocks = 0;
    while (queue_blocks < config_intval(cfg, cfg_notify_initial) ||
	   queue_blocks < 1)
    {
	const char * err = allocate_block(NULL);
	if (err) {
	    deallocate_queue();
	    return err;
	}
    }
    read_block = write_block = first_block;
    event_count = watch_count = watch_active = queue_bytes = queue_events =
	max_events = max_bytes = overflow = too_big = watch_memory = 0;
    return NULL;
}

/* allocates space for one watch block */

static watch_block_t * allocate_watch_block(int leave) {
    watch_block_t * b = mymalloc(sizeof(watch_block_t) +
				 notify_watch_block * sizeof(notify_watch_t));
    if (! b)
	return NULL;
    if (leave < notify_watch_block) {
	b->unused = leave;
	b->w[leave].forward = -1;
	b->w[leave].name_length = notify_watch_block - leave;
    } else {
	b->unused = -1;
    }
    b->used = -1;
    b->next = all_watches;
    b->prev = NULL;
    if (all_watches) all_watches->prev = b;
    all_watches = b;
    watch_memory += notify_watch_block * sizeof(notify_watch_t);
    return b;
}

/* simple hash function on names; it's not meant to be exciting */

static int name_hash(const char * name, int len) {
    int num = len, i;
    for (i = 0; i < len; i++) num += (unsigned char)name[i];
    return num % NAME_HASH;
}

/* make a copy of the how (exclude, crossmount) data so we don't need to
 * keep a reference to iive configuration */

static const config_add_t * copy_how(const config_add_t * how) {
    /* see if we already have one of them */
    how_cache_t * c;
    int code = pthread_mutex_lock(&how_lock);
    if (code) {
	errno = code;
	return NULL;
    }
    c = how_cache;
    while (c) {
	if (c->how.crossmount == how->crossmount) {
	    const config_acl_cond_t * cm = c->how.exclude, * hm = how->exclude;
	    while (cm && hm) {
		if (cm->data_index != hm->data_index) break;
		if (cm->how != hm->how) break;
		if (strcmp(cm->pattern, hm->pattern) != 0) break;
		cm = cm->next;
		hm = hm->next;
	    }
	    if (! cm && ! hm) {
		pthread_mutex_unlock(&how_lock);
		return &c->how;
	    }
	}
	c = c->next;
    }
    /* need to allocate a new one */
    c = mymalloc(sizeof(how_cache_t));
    if (! c) {
	int e = errno;
	pthread_mutex_unlock(&how_lock);
	errno = e;
	return NULL;
    }
    c->how.exclude = c->how.find = NULL;
    if (how->exclude) {
	c->how.exclude = config_copy_acl_cond(how->exclude);
	if (! c->how.exclude) {
	    int e = errno;
	    myfree(c);
	    pthread_mutex_unlock(&how_lock);
	    errno = e;
	    return NULL;
	}
    }
    c->how.crossmount = how->crossmount;
    c->next = how_cache;
    how_cache = c;
    pthread_mutex_unlock(&how_lock);
    return &c->how;
}

/* store watch in a block */

static inline notify_watch_t * store_watch(dev_t device, ino_t inode,
					   const char * name, int len,
					   notify_watch_t * parent,
					   watch_block_t * wb,
					   int offset,
					   const config_add_t * how,
					   watch_by_device_t * wdev)
{
    int hash = name_hash(name, len), j;
    watch_count++;
    wb->w[offset].name_hash = hash;
    wb->w[offset].name_length = len;
    wb->w[offset].watch_id = -1;
    wb->w[offset].device = device;
    wb->w[offset].inode = inode;
    wb->w[offset].block_ptr = wb;
    wb->w[offset].next_by_id = NULL;
    wb->w[offset].forward = wb->used;
    wb->w[offset].locked = 0;
    wb->used = offset;
    if (how) {
	wb->w[offset].how = copy_how(how);
	if (! wb->w[offset].how)
	    return NULL;
    } else {
	wb->w[offset].how = NULL;
    }
    if (parent) {
	wb->w[offset].sibling = parent->subdir[hash];
	parent->subdir[hash] = &wb->w[offset];
	wb->w[offset].parent = parent;
    } else {
	wb->w[offset].sibling = NULL;
	wb->w[offset].parent = NULL;
    }
    for (j = 0; j < NAME_HASH; j++)
	wb->w[offset].subdir[j] = NULL;
    strncpy(wb->w[offset].name, name, len);
    hash = inode % WATCH_HASH;
    wb->w[offset].next_by_inode = wdev->w[hash];
    wdev->w[hash] = &wb->w[offset];
    return &wb->w[offset];
}

/* number of blocks we need to allocate to a watch, based on the name length */

static int watch_size(int len) {
    return 1 + ((len + sizeof(notify_watch_t) - 1) / sizeof(notify_watch_t));
}

/* find watch given its dev/inode, optionally allocates space for it */

static notify_watch_t * find_watch_by_inode(dev_t device, ino_t inode,
					    const char * name,
					    notify_watch_t * parent,
					    const config_add_t * how)
{
    watch_by_device_t * wbdev = dev_to_watch;
    notify_watch_t * nw;
    watch_block_t * wb;
    int hash = inode % WATCH_HASH, len, blocks, j;
    while (wbdev && wbdev->device != device) wbdev = wbdev->next;
    if (! wbdev) {
	/* device not found, add it? */
	if (! name) return NULL;
	wbdev = mymalloc(sizeof(watch_by_device_t));
	if (! wbdev) return NULL;
	wbdev->device = device;
	wbdev->next = dev_to_watch;
	for (j = 0; j < WATCH_HASH; j++)
	    wbdev->w[j] = NULL;
	dev_to_watch = wbdev;
    }
    nw = wbdev->w[hash];
    while (nw) {
	if (nw->inode == inode)
	    return nw;
	nw = nw->next_by_inode;
    }
    /* inode not found */
    if (! name) return NULL;
    /* first look for something with the exact space */
    len = strlen(name);
    blocks = watch_size(len);
    if (blocks > notify_watch_block) {
	errno = ENAMETOOLONG;
	return NULL;
    }
    wb = all_watches;
    while (wb) {
	int u = wb->unused, p = -1;
	while (u >= 0) {
	    int nl = wb->w[u].name_length;
	    if (nl == blocks) {
		/* use this */
		if (p < 0)
		    wb->unused = wb->w[u].forward;
		else
		    wb->w[p].forward = wb->w[u].forward;
		return store_watch(device, inode, name, len,
				   parent, wb, u, how, wbdev);
	    }
	    p = u;
	    u = wb->w[u].forward;
	}
	wb = wb->next;
    }
    /* look for an unused area at least 2 blocks longer than we need, resize
     * it and use part of it (a * gap of a single block cannot be used, so
     * we need to leave at least 2 blocks after resizing) */
    wb = all_watches;
    while (wb) {
	int u = wb->unused;
	while (u >= 0) {
	    int nl = wb->w[u].name_length;
	    if (nl > blocks + 1) {
		/* resize this and use the end */
		wb->w[u].name_length -= blocks;
		u += wb->w[u].name_length;
		return store_watch(device, inode, name, len,
				   parent, wb, u, how, wbdev);
	    }
	    u = wb->w[u].forward;
	}
	wb = wb->next;
    }
    /* need to allocate a new block */
    wb = allocate_watch_block(blocks);
    if (! wb) return NULL;
    return store_watch(device, inode, name, len, parent, wb, 0, how, wbdev);
}

/* find watch given its kernel ID */

static notify_watch_t * find_watch_by_id(int watch_id) {
    int hash = watch_id % WATCH_HASH;
    notify_watch_t * nw = id_to_watch[hash];
    while (nw) {
	if (nw->watch_id == watch_id)
	    return nw;
	nw = nw->next_by_id;
    }
    /* not found */
    return NULL;
}

/* set watch ID on an existing watch: this is used when the watch becomes
 * active; note that we expect not to find it already stored */

static void set_watch_id(notify_watch_t * wp, int watch_id) {
    int hash = watch_id % WATCH_HASH;
    notify_watch_t * nw = id_to_watch[hash];
    while (nw) {
	if (nw->watch_id == watch_id) {
#if USE_SHOULDBOX
	    main_shouldbox++;
	    error_report(error_internal, "set_watch_id", "duplicate watch");
#endif
	    return;
	}
	nw = nw->next_by_id;
    }
    wp->next_by_id = id_to_watch[hash];
    wp->watch_id = watch_id;
    id_to_watch[hash] = wp;
    watch_active++;
    return;
}

/* calculate length of file name given watch and name */

static inline int store_length(notify_watch_t * wp, int len) {
    while (wp) {
	len += wp->name_length + 1;
	wp = wp->parent;
    }
    return len;
}

/* store a file name given watch and name */

static inline void store_name(notify_watch_t * wp, const char * name,
			      int nlen, char * buffer, int len, int nul)
{
    buffer[0] = 0;
    if (nul) buffer[len] = 0;
    if (name) {
	if (nlen > len) return;
	len -= nlen;
	strncpy(buffer + len, name, nlen);
    }
    while (wp) {
	if (name) {
	    if (len < 1) return;
	    len--;
	    buffer[len] = '/';
	}
	name = "";
	if (len < wp->name_length) return;
	len -= wp->name_length;
	strncpy(buffer + len, wp->name, wp->name_length);
	wp = wp->parent;
    }
}

/* queue event: called with queue lock held */

static void queue_event(notify_event_type_t type, int is_dir, int notify_max,
		        notify_watch_t * wfrom, const char * from,
		        notify_watch_t * wto, const char * to, int can_wait)
{
    queue_event_t event;
    int size, flen = from ? strlen(from) : -1, tlen = to ? strlen(to) : -1;
    char * dest;
    event.event_type = type;
    event.is_dir = is_dir;
    if (wfrom)
	event.from_length = store_length(wfrom, flen);
    else if (from)
	event.from_length = flen;
    else
	event.from_length = 0;
    if (wto)
	event.to_length = store_length(wto, tlen);
    else if (to)
	event.to_length = tlen;
    else
	event.to_length = 0;
    size = event_size(&event);
    if (size > notify_queue_block) {
	/* gosh, that's a big one */
	too_big++;
	event.event_type = notify_nospace;
	event.from_length = event.to_length = 0;
	wfrom = wto = NULL;
	from = to = NULL;
	size = event_size(&event);
#if USE_SHOULDBOX
	if (size > notify_queue_block) {
	    /* shouldn't happen(TM) */
	    main_shouldbox++;
	    error_report(error_buffer_tiny, size);
	    return;
	}
#endif
    }
    /* find a block with space */
    while (write_block->write_space < size) {
	queue_block_t * next = write_block->next;
	if (! next) next = first_block;
	if (next == read_block) {
	    const char * err;
	    /* we need to allocate more space, if we can */
	    if (queue_blocks >= notify_max) {
		/* nope, let's wait for a bit */
		error_report(error_queue_too_small);
		if (! can_wait) return;
		pthread_cond_wait(&queue_write_cond, &queue_lock);
		continue;
	    }
	    err = allocate_block(write_block);
	    if (err) {
		/* sigh */
		error_report(error_extending_queue, err);
		if (! can_wait) return;
		pthread_cond_wait(&queue_write_cond, &queue_lock);
		continue;
	    }
	    error_report(info_extending_buffer, queue_blocks);
	    /* we've got a whole new block to play with */
	    next = write_block->next;
	}
#if USE_SHOULDBOX
	if (! next) {
	    /* shouldn't happen(TM) */
	    main_shouldbox++;
	    error_report(error_internal,
			 "allocate_block", "did not allocate one");
	    return;
	}
	if (next->write_space < size) {
	    /* put 10p in the shouldbox and DO NOT save this */
	    main_shouldbox++;
	    error_report(error_shouldbox_less, "queue_event",
			 "write_space", next->write_space, size);
	    return;
	}
#endif
	write_block = next;
	break;
    }
    dest = write_block->write_pos;
    /* add event structure and names */
    memcpy(dest, &event, sizeof(event));
    dest += sizeof(event);
    if (wfrom)
	store_name(wfrom, from, flen, dest, event.from_length, 0);
    else if (from)
	strncpy(dest, from, event.from_length);
    dest += event.from_length;
    if (wto)
	store_name(wto, to, tlen, dest, event.to_length, 0);
    else if (to)
	strncpy(dest, to, event.to_length);
    dest += event.to_length;
    write_block->read_bytes += size;
    write_block->read_count++;
    write_block->write_space -= size;
    write_block->write_pos += size;
#if USE_SHOULDBOX
    if (write_block->write_pos != dest) {
	/* put 10p in the shouldbox */
	main_shouldbox++;
	error_report(error_shouldbox_noteq, "queue_event",
		     "write_pos", write_block->write_pos - write_block->event,
		     "dest", dest - write_block->event);
    }
#endif
    event_count++;
    queue_events++;
    queue_bytes += size;
    if (queue_events > max_events)
	max_events = queue_events;
    if (queue_bytes > max_bytes)
	max_bytes = queue_bytes;
}

/* remove watch from its parent */

static void orphan_watch(notify_watch_t * wp) {
    if (wp->parent) {
	/* find its previous sibling */
	notify_watch_t * s = wp->parent->subdir[wp->name_hash];
	if (s) {
	    if (s == wp) {
		wp->parent->subdir[wp->name_hash] = s->sibling;
	    } else {
		while (s->sibling && s->sibling != wp) s = s->sibling;
		if (s->sibling == wp)
		    s->sibling = wp->sibling;
	    }
	}
    }
    wp->parent = NULL;
    wp->sibling = NULL;
}

/* gives a watch a parent */

static void adopt_watch(notify_watch_t * parent, notify_watch_t * child) {
    child->sibling = parent->subdir[child->name_hash];
    parent->subdir[child->name_hash] = child;
    child->parent = parent;
}

/* removes watch id */

static void remove_watch_id(notify_watch_t * wp) {
    int hash = wp->watch_id % WATCH_HASH;
    notify_watch_t * rw = id_to_watch[hash], * prev = NULL;
    wp->watch_id = -1;
    while (rw && rw != wp) {
	prev = rw;
	rw = rw->next_by_id;
    }
    if (rw) {
	if (prev)
	    prev->next_by_id = rw->next_by_id;
	else
	    id_to_watch[hash] = rw->next_by_id;
    }
}

/* remove a watch from the inode index */

static void rm_inode(notify_watch_t * wp) {
    watch_by_device_t * wbdev = dev_to_watch, * wbprev = NULL;
    int hash;
    notify_watch_t * nw, * prev = NULL;
    while (wbdev && wbdev->device != wp->device) {
	wbprev = wbdev;
	wbdev = wbdev->next;
    }
    if (! wbdev) return;
    hash = wp->inode % WATCH_HASH;
    nw = wbdev->w[hash];
    while (nw) {
	if (nw->inode == wp->inode) {
	    if (prev) {
		prev->next_by_inode = nw->next_by_inode;
	    } else {
		wbdev->w[hash] = nw->next_by_inode;
		if (! wbdev->w[hash]) {
		    /* this device may be empty */
		    int j, ok = 1;
		    for (j = 0; j < WATCH_HASH; j++)
			if (wbdev->w[j]) ok = 0;
		    if (ok) {
			if (wbprev)
			    wbprev->next = wbdev->next;
			else
			    dev_to_watch = wbdev->next;
			myfree(wbdev);
		    }
		}
	    }
	    return;
	}
	prev = nw;
	nw = nw->next_by_inode;
    }
}

/* deallocates a watch and its descendents */

static void deallocate_watch(notify_watch_t * wp, int rmroot) {
    int i, p, ub[notify_watch_block], blocks;
    watch_block_t * wb;
    for (i = 0; i < NAME_HASH; i++)
	while (wp->subdir[i])
	    deallocate_watch(wp->subdir[i], rmroot);
    if (wp->locked && ! rmroot)
	return;
    orphan_watch(wp);
#if USE_SHOULDBOX
    if (watch_count < 1) {
	main_shouldbox++;
	error_report(error_shouldbox_int, "deallocate_watch",
		     "watch_count--", watch_count);
	return;
    }
#endif
    /* remove it from the inode index */
    rm_inode(wp);
    /* and mark the containing block free */
    wb = wp->block_ptr;
    i = wb->used;
    p = -1;
    while (i >= 0) {
	if (wp == &wb->w[i]) {
	    if (p < 0)
		wb->used = wp->forward;
	    else
		wb->w[p].forward = wp->forward;
	    break;
	}
	p = i;
	i = wb->w[i].forward;
    }
    /* mark this block as unused; we scan the unused list and make a list
     * of unused blocks, then create a new unused list from that and remove
     * any fragmentstion; it's only 32 elements per block anyway... */
    for (i = 0; i < notify_watch_block; i++)
	ub[i] = 0;
    blocks = watch_size(wp->name_length);
    p = wp - &wb->w[0];
    for (i = 0; i < blocks; i++)
	ub[p + i] = 1;
    p = wb->unused;
    while (p >= 0) {
	blocks = wb->w[p].name_length;
	for (i = 0; i < blocks; i++)
	    ub[p + i] = 1;
	p = wb->w[p].forward;
    }
    p = -1;
    for (i = 0; i < notify_watch_block; i++) {
	int j;
	if (! ub[i]) continue;
	for (j = i; j < notify_watch_block && ub[j]; j++) ;
	wb->w[i].forward = p;
	wb->w[i].name_length = j - i;
	p = i;
	i = j - 1;
    }
    wb->unused = p;
    /* if it is an active watch, remove it */
    if (wp->watch_id >= 0) {
	int watch_id = wp->watch_id;
	watch_active--;
	remove_watch_id(wp);
	RMWATCH(watch_id);
    }
    watch_count--;
}

static void deallocate_watch_blocks(void) {
    watch_block_t * wb = all_watches;
    while (wb) {
	watch_block_t * this = wb;
	wb = wb->next;
	if (this->used < 0) {
	    /* this block is not used, can be deleted */
	    if (this->prev)
		this->prev->next = this->next;
	    else
		all_watches = this->next;
	    if (this->next)
		this->next->prev = this->prev;
	    watch_memory -= notify_watch_block * sizeof(notify_watch_t);
	    myfree(this);
	}
    }
}

/* deallocate buffers and memory structures */

static void deallocate_buffers(void) {
    watch_block_t * wb;
    watch_by_device_t * wd;
    if (root_watch)
	deallocate_watch(root_watch, 1);
    wb = all_watches;
    while (wb) {
	int i;
	watch_block_t * this = wb;
	wb = wb->next;
	i = this->used;
	while (i >= 0) {
	    deallocate_watch(&this->w[i], 1);
	    i = this->w[i].forward;
	}
    }
    wd = dev_to_watch;
    while (wd) {
	watch_by_device_t * g = wd;
	wd = wd->next;
	myfree(g);
    }
    if (event_buffer)
	myfree(event_buffer);
#if NOTIFY == NOTIFY_INOTIFY
    if (inotify_fd >= 0) close(inotify_fd);
    inotify_fd = -1;
#endif
    deallocate_queue();
    deallocate_watch_blocks();
}

/* initialisation required before the notify thread starts;
 * returns NULL if OK, otherwise an error message */

const char * notify_init(void) {
    const config_data_t * cfg = config_get();
    struct stat sbuff;
    int i;
    const char * err = initialise_queue(cfg);
    if (err) {
	config_put(cfg);
	return err;
    }
    notify_watch_block = config_intval(cfg, cfg_notify_watch_block);
    /* in case we need to undo init midway */
    root_watch = NULL;
    event_buffer = NULL;
    dev_to_watch = NULL;
    for (i = 0; i < WATCH_HASH; i++)
	id_to_watch[i] = 0;
    how_cache = NULL;
#if NOTIFY == NOTIFY_INOTIFY
    inotify_fd = -1;
#endif
    /* allocate event buffer */
    buffer_size = config_intval(cfg, cfg_notify_buffer);
    buffer_extra = buffer_size + sizeof(EVENT) + NAME_MAX + 32;
    event_buffer = mymalloc(buffer_extra);
    if (! event_buffer) {
	err = error_sys("notify_init", "malloc");
	deallocate_buffers();
	config_put(cfg);
	return err;
    }
    /* set up inotify */
#if NOTIFY == NOTIFY_INOTIFY
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
	err = error_sys("notify_init", "inotify_init");
	deallocate_buffers();
	config_put(cfg);
	return err;
    }
    /* might as well mask out events we are going to ignore, if possible;
     * however, we always watch CREATE and DELETE_SELF because we need
     * them to update our watch list */
    i_mask = IN_DELETE_SELF | CREATE_EVENT |
	     IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED;
    if (config_intval(cfg, cfg_event_meta)) i_mask |= ATTRIB_EVENT;
    if (config_intval(cfg, cfg_event_data)) i_mask |= CHANGE_EVENT;
    if (config_intval(cfg, cfg_event_create)) i_mask |= CREATE_EVENT;
    if (config_intval(cfg, cfg_event_delete)) i_mask |= DELETE_EVENT;
    if (config_intval(cfg, cfg_event_rename)) i_mask |= RENAME_EVENT;
#endif
    config_put(cfg);
    /* set up root watch */
    if (stat("/", &sbuff) < 0) {
	/* OUCH! */
	err = error_sys("notify_init", "/");
	deallocate_buffers();
	return err;
    }
    root_watch =
	find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, "", NULL, NULL);
    if (! root_watch) {
	err = error_sys("notify_init", "/");
	deallocate_buffers();
	return err;
    }
    root_watch->locked = 1;
    return NULL;
}

/* queue a rename event */

#if NOTIFY != NOTIFY_NONE
static void rename_watch(EVENT * evp, notify_watch_t * evw,
			 EVENT * destp, notify_watch_t * destw)
{
    /* do we need to update our watch data? */
    int evlen = strlen(evp->name), evblocks, destblocks;
    int evh = name_hash(evp->name, evlen);
    notify_watch_t * evx;
#if USE_SHOULDBOX
    int destlen = strlen(destp->name);
    notify_watch_t * destx;
    int desth = name_hash(destp->name, destlen);
#endif
    // XXX if evw->how->exclude excludes the new name, remove the
    // XXX watch instead of renaming it
    /* find the watch being renamed */
    evx = evw->subdir[evh];
    while (evx) {
	if (evx->name_length == evlen &&
	    strncmp(evx->name, evp->name, evlen) == 0)
		break;
	evx = evx->sibling;
    }
#if USE_SHOULDBOX
    if (! evx) {
	/* shouldn't happen(TM) */
	main_shouldbox++;
	error_report(error_rename_unknown, evp->name);
	return;
    }
    /* we shouldn't(TM) find a watch for the destination, but if there is
     * one we get rid of it */
    destx = destw->subdir[desth];
    while (destx) {
	if (destx->name_length == destlen &&
	    strncmp(destx->name, destp->name, destlen) == 0)
	{
	    main_shouldbox++;
	    error_report(error_rename_exists, destp->name);
	    deallocate_watch(destx, 0);
	    break;
	}
	destx = destx->sibling;
    }
#endif
    evblocks = watch_size(evlen);
    destblocks = watch_size(destlen);
    if (evblocks != destblocks) {
	/* we'll need to allocate new space; to do this we first remove
	 * the watch from the inode index, then allocate it again (by
	 * inode) and finally deallocate the old watch; yes, it is
	 * messy, but directory renames are officially messy: see for
	 * example this comment in the Linux 2.6.30 kernel sources
	 * (fs/namei.c):
	 *     The worst of all namespace operations - renaming directory.
	 *     "Perverted" doesn't even start to describe it. Somebody in
	 *     UCB had a heck of a trip... */
	int watch_id = evx->watch_id;
	notify_watch_t * neww;
	rm_inode(evx);
	remove_watch_id(evx);
	orphan_watch(evx);
	neww = find_watch_by_inode(evx->device, evx->inode, destp->name,
				   destw, evx->how);
	if (! neww) {
	    RMWATCH(watch_id);
	    return;
	}
	set_watch_id(neww, watch_id);
	deallocate_watch(evx, 1);
    } else {
	/* easy case: just overwrite the name and change parent */
	if (evw != destw) {
	    orphan_watch(evx);
	    adopt_watch(destw, evx);
	}
	strncpy(evx->name, destp->name, destlen);
	evx->name_length = destlen;
    }
}
#endif

/* adds a directory watch; returns NULL, and sets errno, on error;
 * parent is an existing directory watch; name is relative to that
 * directory and must not contain directory separator characters;
 * the last parameter just tells us how this was added, as this will
 * be required when new directories are created inside this one;
 * must be called with the queue lock held */

static notify_watch_t * add(notify_watch_t * parent, const char * path,
			    const config_add_t * how)
{
    struct stat sbuff;
    notify_watch_t * wc;
    int wid, plen = path ? strlen(path) : -1;
    int namelen = store_length(parent, plen);
    char full_path[1 + namelen];
    store_name(parent, path, plen, full_path, namelen, 1);
    if (stat(full_path, &sbuff) < 0)
	return NULL;
    wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, path, parent, how);
    if (! wc)
	return NULL;
    if (wc->watch_id >= 0)
	return wc;
    wid = ADDWATCH(full_path);
    if (wid < 0)
	return NULL;
    set_watch_id(wc, wid);
    return wc;
}

static void watch_new_dir(notify_watch_t * evw, const char * name) {
    int addit = 1;
    /* check if we do want to add this one */
    if (addit && evw->how) {
	int len = strlen(name);
	int pathlen = store_length(evw, len);
	char path[pathlen + 1];
	store_name(evw, name, len, path, pathlen, 1);
	if (! evw->how->crossmount) {
	    /* check parent and subdir on same device */
	    struct stat sp;
	    addit = 0;
	    if (stat(path, &sp) >= 0) {
		struct stat sc;
		char sv = path[pathlen - len];
		path[pathlen - len] = 0;
		if (stat(path, &sc) >= 0)
		    addit = sp.st_dev == sc.st_dev;
		path[pathlen - len] = sv;
	    }
	}
	if (addit && evw->how->exclude) {
	    /* check the name against the exclude list */
	    const char * data[cfg_dacl_COUNT];
	    data[cfg_dacl_name] = name;
	    data[cfg_dacl_path] = path;
	    if (config_check_acl_cond(evw->how->exclude, 0,
				      data, cfg_dacl_COUNT))
		addit = 0;
	}
    }
    if (addit) {
	notify_watch_t * added = add(evw, name, evw->how);
	if (! added)
	    error_report(error_add_watch, errno, name);
    }
}

/* removes a directory watch; returns 1 if found, 0 if not found,
 * -1 if found but has children; parent and name are the same as
 * notify_add(); must be called with the queue lock held */

static int remove_watch(notify_watch_t * parent, const char * path, int recurse)
{
    int namelen = strlen(path), hash = name_hash(path, namelen);
    notify_watch_t * wp;
    wp = parent->subdir[hash];
    while (wp) {
	if (wp->name_length == namelen &&
	    strncmp(wp->name, path, namelen) == 0)
	{
	    if (! recurse) {
		int i;
		for (i = 0; i < NAME_HASH; i++)
		    if (wp->subdir[i])
			return -1;
	    }
	    deallocate_watch(wp, 0);
	    return 1;
	}
	wp = wp->sibling;
    }
    return 0;
}

/* run notify thread; returns NULL on normal termination,
 * or an error message */

const char * notify_thread(void) {
    int ov;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    while (main_running) {
	config_filter_t filter[cfg_event_COUNT];
	const config_data_t * cfg;
	int buffer_start = 0, buffer_end = 0, errcode, i, skip_should;
	int notify_max;
#if NOTIFY == NOTIFY_INOTIFY
	struct pollfd pfd;
	pfd.fd = inotify_fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, POLL_TIME) < 1)
	    continue;
	/* read some data from the kernel */
	buffer_end = read(inotify_fd, event_buffer, buffer_size);
	if (buffer_end < 0)
	    return error_sys("notify_thread", "read");
	if (buffer_end == 0)
	    return "notify_thread: read: unexpected end of file";
#endif
	cfg = config_get();
	for (i = 0; i < cfg_event_COUNT; i++)
	    filter[i] = config_intval(cfg, i);
	skip_should = config_intval(cfg, cfg_flags) & config_flag_skip_should;
	notify_max = config_intval(cfg, cfg_notify_max);
	config_put(cfg);
	/* lock queue */
	errcode = pthread_mutex_lock(&queue_lock);
	if (errcode)
	    return error_sys_errno("notify_thread", "pthread_mutex_lock",
				   errcode);
	/* process all these events */
	while (buffer_start < buffer_end /* && main_running */) {
	    EVENT * evp;
	    notify_watch_t * evw;
	    notify_event_type_t evtype;
	    int is_dir;
	    config_filter_t filter_mask, filter_data;
	    /* get next event */
	    evp = (void *)&event_buffer[buffer_start];
#if NOTIFY == NOTIFY_INOTIFY
	    buffer_start += sizeof(EVENT) + evp->len;
#endif
	    /* handle all nameless events */
#if NOTIFY == NOTIFY_INOTIFY
	    if (evp->mask & IN_Q_OVERFLOW) {
		queue_event(notify_overflow, 0, notify_max,
			    NULL, NULL, NULL, NULL, 1);
		overflow++;
		continue;
	    }
#endif
	    evw = find_watch_by_id(evp->wd);
	    if (! evw) continue;
#if NOTIFY == NOTIFY_INOTIFY
	    is_dir = evp->mask & IN_ISDIR;
	    if (evp->mask & (IN_UNMOUNT | IN_DELETE_SELF | IN_IGNORED)) {
		/* kernel automatically removes the watch; we need to free our
		 * data structures */
		if (evw->watch_id >= 0)
		    remove_watch_id(evw);
		deallocate_watch(evw, 1);
		continue;
	    }
#endif
	    /* skip should's temporary files, if required; in the special
	     * case of the final rename (".should.XXXXXX" -> realname)
	     * this will skip the MOVED_FROM but not the MOVED_TO, which
	     * will automatically become a "create" event; such event will
	     * then be optimised away if the copy was from one of our
	     * clients */
	    if (skip_should &&
		! is_dir &&
		strncmp(evp->name, ".should.", 8) == 0 &&
		strlen(evp->name) == 14)
		    continue;
	    /* prepare the event filter */
	    filter_mask = is_dir ? config_file_dir : ~config_file_dir;
	    /* if it is a rename, see if it is followed by the other half */
#if NOTIFY == NOTIFY_INOTIFY
	    if (evp->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
		if (buffer_start >= buffer_end) {
		    /* try reading more... */
		    pfd.fd = inotify_fd;
		    pfd.events = POLLIN;
		    if (poll(&pfd, 1, 10) > 0) {
			int nread = read(inotify_fd,
					 event_buffer + buffer_end,
					 buffer_extra - buffer_end);
			if (nread > 0)
			    buffer_end += nread;
		    }
		}
		if (buffer_start < buffer_end) {
		    EVENT * destp = (void *)&event_buffer[buffer_start];
		    if (destp->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
			if (destp->cookie == evp->cookie) {
			    /* this is a rename event... */
			    notify_watch_t * destw =
				find_watch_by_id(destp->wd);
			    if (destw) {
				buffer_start += sizeof(EVENT) + destp->len;
				/* make sure the rename is from evp to destp */
				if (evp->mask & IN_MOVED_TO) {
				    EVENT * swp;
				    notify_watch_t * sww;
				    swp = destp; destp = evp; evp = swp;
				    sww = destw; destw = evw; evw = sww;
				}
				if (filter[cfg_event_rename] & filter_mask)
				    queue_event(notify_rename, is_dir,
						notify_max, evw, evp->name,
						destw, destp->name, 1);
				if (is_dir)
				    rename_watch(evp, evw, destp, destw);
				continue;
			    }
			}
		    }
		}
	    }
#endif
	    /* not a rename event, or from/to is not watched */
	    if (evp->mask & CREATE_EVENT) {
		evtype = notify_create;
		filter_data = cfg_event_create;
		if (is_dir)
		    watch_new_dir(evw, evp->name);
	    } else if (evp->mask & DELETE_EVENT) {
		evtype = notify_delete;
		filter_data = cfg_event_delete;
		if (is_dir)
		    remove_watch(evw, evp->name, 1);
	    } else if (evp->mask & CHANGE_EVENT) {
		evtype = notify_change_data;
		filter_data = cfg_event_data;
	    } else if (evp->mask & ATTRIB_EVENT) {
		evtype = notify_change_meta;
		filter_data = cfg_event_meta;
	    } else {
#if USE_SHOULDBOX
		/* shouldn't happen(TM) */
		main_shouldbox++;
		error_report(error_shouldbox_int, "notify_thread",
			     "evp->mask", evp->mask);
#endif
		continue;
	    }
#if NOTIFY == NOTIFY_INOTIFY
	    if (filter[filter_data] & filter_mask)
		queue_event(evtype, is_dir, notify_max,
			    evw, evp->len > 0 ? evp->name : NULL,
			    NULL, NULL, 1);
#endif
	}
	/* if reader is waiting for data, let them know */
	pthread_cond_signal(&queue_read_cond);
	/* periodic cleanup */
	deallocate_watch_blocks();
	/* unlock queue */
	pthread_mutex_unlock(&queue_lock);
    }
    return NULL;
}

/* cleanup required after the notify thread terminates */

void notify_exit(void) {
    /* destroy inotify */
#if NOTIFY == NOTIFY_INOTIFY
    if (inotify_fd >= 0) close(inotify_fd);
    inotify_fd = -1;
#endif
    /* wait for queue to become empty */
    while (main_running && queue_bytes > 0) {
	int code = pthread_mutex_lock(&queue_lock);
	if (code) {
	    error_report(error_lock, "notify_exit", code);
	    pthread_mutex_unlock(&queue_lock);
	    break;
	}
	if (queue_bytes> 0)
	    pthread_cond_wait(&queue_write_cond, &queue_lock);
	pthread_mutex_unlock(&queue_lock);
    }
    deallocate_buffers();
    while (how_cache) {
	how_cache_t * this = how_cache;
	how_cache = this->next;
	config_free_acl_cond(this->how.exclude);
	myfree(this);
    }
}

/* look up a directory by name and return the corresponding watch, if
 * found; if not found, return NULL if addit is NULL, otherwise it will
 * try to add it: returns NULL if that is not possible; the value
 * of addit is the same as for notify_add; this function must be called
 * with the queue lock held */

static notify_watch_t * find_bypath(const char * path,
				    const config_add_t * addit)
{
    const config_data_t * cfg = config_get();
    struct stat sbuff;
    notify_watch_t * wc;
    int olddir, pathdir, e, p = -1;
    int notify_max = config_intval(cfg, cfg_notify_max), com = 0;
    dev_t dev[MAXPATHCOM];
    ino_t ino[MAXPATHCOM];
    config_put(cfg);
    pathdir = open(path, O_RDONLY);
    if (pathdir < 0)
	return NULL;
    if (fstat(pathdir, &sbuff) < 0) {
	e = errno;
	close(pathdir);
	errno = e;
	return NULL;
    }
    if (! S_ISDIR(sbuff.st_mode)) {
	close(pathdir);
	errno = ENOTDIR;
	return NULL;
    }
    wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, NULL, NULL, addit);
    if (wc) {
	if (addit && wc->watch_id < 0) {
	    int wid;
	    queue_event(notify_add_tree, 1, notify_max,
			NULL, path, NULL, NULL, 1);
	    pthread_cond_signal(&queue_read_cond);
	    wid = ADDWATCH(path);
	    if (wid < 0) {
		int e = errno;
		close(pathdir);
		errno = e;
		return NULL;
	    }
	    set_watch_id(wc, wid);
	}
	close(pathdir);
	return wc;
    }
    if (! addit) {
	close(pathdir);
	errno = ENOENT;
	return NULL;
    }
    /* here we need to add all watches from the root to whatever directory
     * corresponds to (sbuff.st_dev, sbuff.st_ino), which may not be what
     * it looks like from path due to symlink following etc; so we save
     * the current working directory, use chdir("..") as much as necessary
     * to get to the root, then restore the working directory; or so we
     * hope */
    olddir = open(".", O_RDONLY);
    if (olddir < 0) {
	e = errno;
	close(pathdir);
	errno = e;
	return NULL;
    }
    if (fchdir(pathdir) < 0) {
	e = errno;
	close(pathdir);
	if (fchdir(olddir) < 0)
	    perror("WARNING: cannot change back to original dir");
	close(olddir);
	errno = e;
	return NULL;
    }
    while (1) {
	if (com >= MAXPATHCOM) {
	    errno = ENAMETOOLONG;
	    goto error;
	}
	dev[com] = sbuff.st_dev;
	ino[com] = sbuff.st_ino;
	com++;
	p = open("..", O_RDONLY);
	if (p < 0)
	    goto error;
	if (fstat(p, &sbuff) < 0)
	    goto error;
	wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, NULL, NULL, addit);
	if (wc) {
	    /* we found one we already know about */
	    while (com > 0) {
		int namelen = store_length(wc, 0), found = 0, wid;
		char name[namelen + NAME_MAX + 2];
		DIR * D;
		struct dirent * E;
		store_name(wc, "", 0, name, namelen, 1);
		D = opendir(name);
		if (! D)
		    goto error;
		name[namelen] = '/';
		while ((E = readdir(D)) != NULL) {
		    int len = strlen(E->d_name);
		    if (len > NAME_MAX) continue;
		    if (E->d_name[0] == '.') {
			if (len == 1) continue;
			if (len == 2 && E->d_name[1] == '.') continue;
		    }
		    strcpy(name + namelen + 1, E->d_name);
		    if (stat(name, &sbuff) < 0)
			continue;
		    if (sbuff.st_ino != ino[com - 1])
			continue;
		    if (sbuff.st_dev != dev[com - 1])
			continue;
		    /* found it... */
		    wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino,
					     E->d_name, wc, addit);
		    if (! wc) {
			e = errno;
			closedir(D);
			errno = e;
			goto error;
		    }
		    found = 1;
		    break;
		}
		closedir(D);
		if (! found) {
		    errno = EINVAL;
		    goto error;
		}
		com--;
		if (com > 0)
		    continue;
		if (fchdir(olddir) < 0)
		    perror("WARNING: cannot change back to original dir");
		close(olddir);
		close(pathdir);
		olddir = pathdir = -1;
		queue_event(notify_add_tree, 1, notify_max,
			    NULL, path, NULL, NULL, 1);
		pthread_cond_signal(&queue_read_cond);
		wid = ADDWATCH(path);
		if (wid < 0)
		    return NULL;
		set_watch_id(wc, wid);
		return wc;
	    }
	    errno = EINVAL;
	    goto error;
	}
	if (dev[com] == sbuff.st_dev && ino[com] == sbuff.st_ino) {
	    /* something must have changed while we weren't looking... */
	    errno = EINVAL;
	    goto error;
	}
	if (fchdir(p) < 0)
	    goto error;
	close(p);
	p = -1;
    }
    /* we only get here if there's an error */
error:
    e = errno;
    if (p >= 0) close(p);
    if (olddir >= 0 && fchdir(olddir) < 0)
	perror("WARNING: cannot change back to original dir");
    if (pathdir >= 0) close(pathdir);
    if (olddir >= 0) close(olddir);
    errno = e;
    return NULL;
}

/* look up a directory by name and return the corresponding watch, if
 * found; if not found, return NULL if addit is NULL, otherwise it will
 * try to add it: returns NULL if that is not possible; the value
 * of addit is the same as for notify_add; the returned watch is left in
 * a "locked" state and cannot be removed until the caller calls
 * notify_unlock_watch() */

notify_watch_t * notify_find_bypath(const char * path,
				    const config_add_t * addit)
{
    int errcode;
    notify_watch_t * wc;
    /* lock queue - this is so we lock all watch structures */
    errcode = pthread_mutex_lock(&queue_lock);
    if (errcode) {
	errno = errcode;
	return NULL;
    }
    wc = find_bypath(path, addit);
    if (wc) {
	notify_watch_t * pv = wc;
	while (pv) {
	    pv->locked++;
	    pv = pv->parent;
	}
    }
    errcode = errno;
    pthread_mutex_unlock(&queue_lock);
    errno = errcode;
    return wc;
}

void notify_unlock_watch(notify_watch_t * wc) {
    int errcode;
    errcode = pthread_mutex_lock(&queue_lock);
    if (errcode)
	return;
    while (wc) {
	if (wc->locked > 0) wc->locked--;
	wc = wc->parent;
    }
    pthread_mutex_unlock(&queue_lock);
}

/* remove a watch and all its subdirectories */

const char * notify_remove_under(const char * path) {
    int errcode;
    notify_watch_t * wp;
    /* lock queue - this also locka all watch structures */
    errcode = pthread_mutex_lock(&queue_lock);
    if (errcode)
	return "Error locking watch structure";
    wp = find_bypath(path, 0);
    if (! wp) {
	pthread_mutex_unlock(&queue_lock);
	return "No such tree";
    }
    deallocate_watch(wp, 0);
    pthread_mutex_unlock(&queue_lock);
    return NULL;
}

/* adds a directory watch; returns NULL, and sets errno, on error;
 * parent is an existing directory watch; name is relative to that
 * directory and must not contain directory separator characters;
 * the last parameter just tells us how this was added, as this will
 * be required when new directories are created inside this one */

notify_watch_t * notify_add(notify_watch_t * parent, const char * path,
			    const config_add_t * how)
{
    int errcode, wid;
    notify_watch_t * wc;
    if (path[0] == '.' && ! path[1]) {
	errno = EINVAL;
	return NULL;
    }
    if (path[0] == '.' && path[1] == '.' && ! path[2]) {
	errno = EINVAL;
	return NULL;
    }
    for (wid = 0; path[wid]; wid++) {
	if (path[wid] == '/') {
	    errno = EINVAL;
	    return NULL;
	}
    }
    /* lock queue - this also locks the watch structure */
    errcode = pthread_mutex_lock(&queue_lock);
    if (errcode) {
	errno = errcode;
	return NULL;
    }
    wc = add(parent, path, how);
    errcode = errno;
    pthread_mutex_unlock(&queue_lock);
    errno = errcode;
    return wc;
}

/* returns root watch */

notify_watch_t * notify_root(void) {
    return root_watch;
}

/* returns current queue status */

#if NOTIFY == NOTIFY_INOTIFY
static int get_proc(const char * name) {
    FILE * proc;
    int rv = -1;
    proc = fopen(name, "r");
    if (! proc) return -1;
    if (fscanf(proc, "%d", &rv) < 1)
	rv = -1;
    fclose(proc);
    return rv;
}
#endif

void notify_status(notify_status_t * status) {
    const config_data_t * cfg = config_get();
    status->queue_max = config_intval(cfg, cfg_notify_max) * notify_queue_block;
    config_put(cfg);
    status->queue_bytes = queue_bytes;
    status->queue_min = notify_initial * notify_queue_block;
    status->queue_cur = queue_blocks * notify_queue_block;
    status->queue_events = queue_events;
    status->max_bytes = max_bytes;
    status->max_events = max_events;
    status->overflow = overflow;
    status->too_big = too_big;
    status->watches = watch_active;
    status->watchmem = watch_memory;
    status->events = event_count;
#if NOTIFY == NOTIFY_INOTIFY
    status->kernel_max_watches =
	get_proc("/proc/sys/fs/inotify/max_user_watches");
    status->kernel_max_events =
	get_proc("/proc/sys/fs/inotify/max_queued_events");
#else
    status->kernel_max_watches = -1;
    status->kernel_max_events = -1;
#endif
}

/* returns next pending event; returns:
 * 0  if the notify thread terminated
 * 1  if data is available (size will be adjusted to show how much buffer
 *    was used)
 * -3 if the buffer is too small (size will be adjusted to show how much
 *    space is required)
 * -2 if no data available after blocking milliseconds
 * -1 if an error occurred (code will be in errno) */

int notify_get(notify_event_t * nev, int blocking, char * buffer, int * bsz) {
    int code, qsz, nsz, retval = 1;
    struct timespec maxspec;
    long long maxwait;
    queue_event_t qev;
    struct stat sbuff;
    const char * statit = "";
    /* easy case: no longer running and queue empty */
    if (! main_running && queue_bytes < 1)
	return 0;
    /* lock the queue */
    code = pthread_mutex_lock(&queue_lock);
    if (code) {
	errno = code;
	return -1;
    }
    /* blocking delay applies from now */
    clock_gettime(CLOCK_REALTIME, &maxspec);
    maxwait = (long long)maxspec.tv_sec * 1000 +
	      (long long)maxspec.tv_nsec / 1000000 +
	      blocking;
    maxspec.tv_sec = maxwait / 1000;
    maxspec.tv_nsec = 1000000 * (maxwait % 1000);
    while (queue_bytes < 1) {
	struct timespec nowspec;
	long long now;
	/* no longer running: unlock the queue and return EOF */
	if (! main_running) {
	    pthread_mutex_unlock(&queue_lock);
	    return 0;
	}
	clock_gettime(CLOCK_REALTIME, &nowspec);
	now = (long long)nowspec.tv_sec * 1000 +
	      (long long)nowspec.tv_nsec / 1000000;
	if (now >= maxwait) {
	    /* don't wait */
	    pthread_mutex_unlock(&queue_lock);
	    return -2;
	}
	/* wait for a signal from a writer, then try again */
	pthread_cond_timedwait(&queue_read_cond, &queue_lock, &maxspec);
    }
    /* if the block is empty, and the write pointer is elsewhere, we
     * skip to the next block after resetting this one */
    if (read_block->read_bytes < 1 && read_block != write_block) {
	read_block->read_pos = read_block->event;
	read_block->read_bytes = 0;
	read_block->read_count = 0;
	read_block->write_pos = read_block->event;
	read_block->write_space = notify_queue_block;
	read_block = read_block->next;
	if (! read_block) read_block = first_block;
    }
    /* get queued event and do some sanity checks */
    memcpy(&qev, read_block->read_pos, sizeof(queue_event_t));
    qsz = sizeof(queue_event_t);
    nsz = 0;
    if (qev.from_length > 0) {
	qsz += qev.from_length;
	nsz += 1 + qev.from_length;
    }
    if (qev.to_length > 0) {
	qsz += qev.to_length;
	nsz += 1 + qev.to_length;
    }
    if (nsz >= *bsz) {
	*bsz = nsz;
	pthread_mutex_unlock(&queue_lock);
	return -3;
    }
#if USE_SHOULDBOX
    if (read_block->read_count < 1) {
	main_shouldbox++;
	error_report(error_shouldbox_int, "notify_get",
		     "read_count--", read_block->read_count);
	read_block->read_count = 1;
    }
    if (queue_events < 1) {
	main_shouldbox++;
	error_report(error_shouldbox_int, "notify_get",
		     "queue_events--", queue_events);
	queue_events = 1;
    }
    if (read_block->read_bytes < qsz) {
	main_shouldbox++;
	error_report(error_shouldbox_less, "notify_get",
		     "read_bytes", read_block->read_bytes, qsz);
	read_block->read_bytes = 0;
	errno = EINVAL;
	retval = -1;
	goto out;
    }
    if (queue_bytes < qsz) {
	main_shouldbox++;
	error_report(error_shouldbox_less, "notify_get",
		     "queue_bytes", queue_bytes, qsz);
	queue_bytes = 0;
	errno = EINVAL;
	retval = -1;
	goto out;
    }
#endif
    /* prepare return value */
    nev->event_type = qev.event_type;
    nev->from_length = qev.from_length;
    qsz = sizeof(queue_event_t);
    if (qev.from_length > 0) {
	nev->from_name = buffer;
	nev->from_length = qev.from_length;
	strncpy(buffer, read_block->read_pos + qsz, qev.from_length);
	buffer += qev.from_length;
	*buffer++ = 0;
	qsz += qev.from_length;
    } else {
	nev->from_name = NULL;
    }
    nev->to_length = qev.to_length;
    if (qev.to_length > 0) {
	nev->to_name = buffer;
	nev->to_length = qev.to_length;
	strncpy(buffer, read_block->read_pos + qsz, qev.to_length);
	buffer += qev.to_length;
	*buffer++ = 0;
	qsz += qev.to_length;
    } else {
	nev->to_name = NULL;
    }
    nev->file_type =
	qev.is_dir ? notify_filetype_dir : notify_filetype_unknown;
    nev->stat_valid = 0;
    switch (qev.event_type) {
	case notify_add_tree :
	    nev->file_mtime = time(NULL);
	    break;
	case notify_change_meta :
	case notify_change_data :
	case notify_create :
	    statit = nev->from_name;
	fill_stat:
	    if (lstat(statit, &sbuff) >= 0) {
		nev->stat_valid = 1;
		nev->file_type = notify_filetype(sbuff.st_mode);
		nev->file_mode = sbuff.st_mode & 07777;
		nev->file_user = sbuff.st_uid;
		nev->file_group = sbuff.st_gid;
		nev->file_size = sbuff.st_size;
		nev->file_mtime = sbuff.st_mtime;
		nev->file_device = sbuff.st_rdev;
		if (S_ISLNK(sbuff.st_mode)) {
		    int used;
		    if (nsz + sbuff.st_size + 1 > *bsz) {
			*bsz = nsz;
			pthread_mutex_unlock(&queue_lock);
			return -3;
		    }
		    used = readlink(nev->from_name, buffer, *bsz - nsz - 1);
		    nsz += used + 1;
		    buffer[used] = 0;
		    nev->to_name = buffer;
		    nev->to_length = used;
		}
	    }
	    break;
	case notify_rename :
	    statit = nev->to_name;
	    goto fill_stat;
	case notify_delete :
	case notify_overflow :
	case notify_nospace :
	    break;
    }
    *bsz = nsz;
    /* skip to next event */
    read_block->read_count--;
    queue_events--;
    read_block->read_bytes -= qsz;
    queue_bytes -= qsz;
    read_block->read_pos += qsz;
#if USE_SHOULDBOX
    if (read_block->read_pos > read_block->event + notify_queue_block) {
	main_shouldbox++;
	error_report(error_shouldbox_more, "notify_get", "read_pos",
		     (int)(read_block->read_pos - read_block->event),
		     notify_queue_block);
    }
out:
#endif
    /* if the block is empty, and the write pointer is elsewhere, we
     * skip to the next block after resetting this one */
    if (read_block->read_bytes < 1 && read_block != write_block) {
	read_block->read_pos = read_block->event;
	read_block->read_bytes = 0;
	read_block->read_count = 0;
	read_block->write_pos = read_block->event;
	read_block->write_space = notify_queue_block;
	read_block = read_block->next;
	if (! read_block) read_block = first_block;
    }
    /* have they just created a directory? */
    if (nev->stat_valid &&
	nev->file_type == notify_filetype_dir &&
	nev->event_type == notify_create)
    {
	/* scan this directory and generate synthetic events for
	 * everything already in it */
	notify_watch_t * wp;
	DIR * D;
	wp = find_bypath(nev->from_name, NULL);
	D = opendir(nev->from_name);
	if (wp && D) {
	    int slen = strlen(nev->from_name);
	    char sname[slen + NAME_MAX + 2];
	    struct dirent * E;
	    const config_data_t * cfg = config_get();
	    config_filter_t filter = config_intval(cfg, cfg_event_create);
	    config_filter_t filter_mask;
	    int notify_max = config_intval(cfg, cfg_notify_max);
	    config_put(cfg);
	    strcpy(sname, nev->from_name);
	    sname[slen++] = '/';
	    while ((E = readdir(D)) != NULL) {
		int len = strlen(E->d_name), is_dir;
		struct stat ebuff;
		if (E->d_name[0] == '.') {
		    if (len == 1) continue;
		    if (len == 2 && E->d_name[1] == '.') continue;
		}
		if (len > NAME_MAX) continue;
		strcpy(sname + slen, E->d_name);
		if (lstat(sname, &ebuff) < 0) continue;
		is_dir = S_ISDIR(ebuff.st_mode);
		filter_mask = is_dir ? config_file_dir : ~config_file_dir;
		if (! (filter & filter_mask)) continue;
		/* don't wait if there isn't space, but try to queue this */
		queue_event(notify_create, S_ISDIR(ebuff.st_mode), notify_max,
			    wp, E->d_name, NULL, NULL, 0);
		if (is_dir)
		    watch_new_dir(wp, E->d_name);
	    }
	}
	if (D)
	    closedir(D);
    }
    /* somebody may be waiting for space */
    pthread_cond_signal(&queue_write_cond);
    /* unlock the queue and return data */
    pthread_mutex_unlock(&queue_lock);
    return retval;
}

/* executes a callback once for each active watch */

int notify_forall_watches(int (*cb)(const char *, void *), void * P) {
    int hash, errcode;
    /* lock queue - this also locks the watch structure */
    errcode = pthread_mutex_lock(&queue_lock);
    if (errcode)
	return 0;
    for (hash = 0; hash < WATCH_HASH; hash++) {
	const notify_watch_t * wl = id_to_watch[hash];
	while (wl) {
	    int nl = store_length(wl->parent, wl->name_length);
	    char wname[nl + 1];
	    store_name(wl->parent, wl->name, wl->name_length, wname, nl, 1);
	    if (! cb(wname, P)) {
		int e = errno;
		pthread_mutex_unlock(&queue_lock);
		errno = e;
		return 0;
	    }
	    wl = wl->next_by_id;
	}
    }
    pthread_mutex_unlock(&queue_lock);
    return 1;
}
#endif /* NOTIFY != NOTIFY_NONE */

/* convert a mode_t to a notify_filetype_t */

notify_filetype_t notify_filetype(mode_t mode) {
    if (S_ISREG(mode))
	return notify_filetype_regular;
    if (S_ISDIR(mode))
	return notify_filetype_dir;
    if (S_ISCHR(mode))
	return notify_filetype_device_char;
    if (S_ISBLK(mode))
	return notify_filetype_device_block;
    if (S_ISFIFO(mode))
	return notify_filetype_fifo;
    if (S_ISLNK(mode))
	return notify_filetype_symlink;
    if (S_ISSOCK(mode))
	return notify_filetype_socket;
    return notify_filetype_unknown;
}

