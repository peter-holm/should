/* should's notify thread
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

#include "site.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#if USE_SYSINOTIFY
#include <sys/inotify.h>
#else
#include "inotify-nosys.h"
#endif
#include <sys/poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include "notify_thread.h"
#include "main_thread.h"
#include "config.h"
#include "error.h"
#include "mymalloc.h"

#define I_MASK IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | \
	       IN_DELETE_SELF | /* IN_MOVE_SELF | */ IN_MOVED_FROM | \
	       IN_MOVED_TO /* | IN_DONT_FOLLOW | IN_ONLYDIR */ | \
	       IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED

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
    notify_watch_t * next_name, * prev_name;
    notify_watch_t * parent;
    notify_watch_t * subdir[NAME_HASH];
    watch_block_t * block_ptr;
    int valid;
    int name_hash;
    int watch_id;
    dev_t device;
    ino_t inode;
    int name_length;
    union {
	char name_short[NAME_LIMIT];
	char * name_long;
    };
};

/* used to store a block of watches */

struct watch_block_s {
    watch_block_t * next, * prev;
    unsigned int block_num;
    notify_watch_t w[0];
};

/* used to find watches by ID */

typedef struct watch_by_id_s watch_by_id_t;
struct watch_by_id_s {
    watch_by_id_t * next, * prev;
    unsigned int block_num;
    notify_watch_t * w[0];
};

/* used to store watch names */

typedef union {
    struct {
	short int length;
	short int next_free;
    };
    char name[0];
} free_name_t;

typedef struct name_block_s name_block_t;
struct name_block_s {
    name_block_t * next_name;
    int free;
    union {
	free_name_t f_names[0];
	char c_names[0];
    };
};

static queue_block_t * first_block, * write_block, * read_block;
static int notify_queue_block, notify_max, overflow, too_big;
static int event_count, watch_count, max_events, max_bytes;
static int queue_events, queue_bytes, queue_blocks, inotify_fd;
static int notify_initial, watch_memory, watch_active, name_block;

static watch_block_t * watches_by_inode;
static watch_by_id_t * watches_by_id;
static unsigned int notify_watch_block;

static pthread_mutex_t queue_lock;
static pthread_cond_t queue_read_cond, queue_write_cond;

static notify_watch_t ** watch_by_id, * root_watch;

static char * event_buffer;
static int buffer_size, buffer_extra;

static name_block_t * first_name;

/* used to store events in the queue */

typedef struct {
    notify_event_type_t event_type;
    int from_length;
    int to_length;
    int is_dir;
} queue_event_t;

/* watch name */

static inline const char * watch_dir_name(notify_watch_t * nw) {
    return nw->name_length < NAME_LIMIT
	? nw->name_short
	: nw->name_long;
}

/* allocates space for watch name and returns it */

static char * allocate_watch_name(notify_watch_t * nw, int len) {
    int lblocks;
    name_block_t * b;
    if (len < NAME_LIMIT)
	return nw->name_short;
    /* do we have a block with space? */
    lblocks = (len + sizeof(free_name_t) - 1) / sizeof(free_name_t);
    if (lblocks > name_block) {
	errno = ENAMETOOLONG;
	return NULL;
    }
    b = first_name;
    while (b) {
	int f = b->free, pf = -1;
	while (f >= 0) {
	    if (b->f_names[f].length == lblocks) {
		/* use this block */
		if (pf >= 0)
		    b->f_names[pf].next_free = b->f_names[f].next_free;
		else
		    b->free = b->f_names[f].next_free;
		nw->name_long = b->f_names[f].name;
		return b->f_names[f].name;
	    }
	    if (b->f_names[f].length > lblocks) {
		/* use the end of this block */
		b->f_names[f].length -= lblocks;
		f += b->f_names[f].length;
		nw->name_long = b->f_names[f].name;
		return b->f_names[f].name;
	    }
	    pf = f;
	    f = b->f_names[f].next_free;
	}
	b = b->next_name;
    }
    /* no block found, allocate a new one */
    b = mymalloc(sizeof(name_block_t) + name_block * sizeof(free_name_t));
    if (! b) return NULL;
    b->next_name = first_name;
    first_name = b;
    watch_memory += sizeof(name_block_t) + name_block * sizeof(free_name_t);
    if (lblocks == name_block) {
	b->free = -1;
    } else {
	b->free = lblocks;
	b->f_names[lblocks].length = name_block - lblocks;
	b->f_names[lblocks].next_free = -1;
    }
    nw->name_long = b->c_names;
    return b->c_names;
}

/* free space for watch name */

static inline void free_watch_name(notify_watch_t * nw) {
    int lblocks;
    name_block_t * b, * c = NULL;
    if (nw->name_length < NAME_LIMIT)
	return;
    lblocks = (nw->name_length + sizeof(free_name_t) - 1) / sizeof(free_name_t);
#if USE_SHOULDBOX
    if (lblocks > name_block) {
	/* log this in the shouldbox */
	error_report(error_shouldbox_more, "free_watch_name",
		     "lblocks", lblocks, name_block);
	main_shouldbox++;
	return;
    }
#endif
    b = first_name;
    while (b) {
	if (nw->name_long >= b->c_names) {
	    int f = nw->name_long - b->c_names;
	    if (f < name_block * sizeof(free_name_t)) {
#if USE_SHOULDBOX
		if (f % sizeof(free_name_t)) {
		    /* log this in the shouldbox */
		    error_report(error_shouldbox_mod, "free_watch_name",
				 "f", f, (int)sizeof(free_name_t),
				 (int)(f % sizeof(free_name_t)));
		    main_shouldbox++;
		    return;
		}
#endif
		f /= sizeof(free_name_t);
		/* add this to b's free list */
		if (f > 0) {
		    /* see if we can extend a previous block */
		    int p = b->free;
		    while (p >= 0) {
			if (p + b->f_names[p].length == f) {
			    b->f_names[p].length += lblocks;
			    f = p;
			    lblocks = b->f_names[0].length;
			    break;
			}
			p = b->f_names[p].next_free;
		    }
		} else {
		    b->f_names[f].length = lblocks;
		    b->f_names[f].next_free = b->free;
		    b->free = f;
		}
		if (f + lblocks < name_block) {
		    /* see if we can join with next block */
		    int q = b->free, r = -1, e = f + lblocks;
		    while (q >= 0) {
			if (e == q) {
			    b->f_names[f].length += b->f_names[q].length;
			    if (r >= 0)
				b->f_names[r].next_free = b->f_names[q].next_free;
			    else
				b->free = b->f_names[q].next_free;
			    break;
			}
			r = q;
			q = b->f_names[q].next_free;
		    }
		}
		if (f == 0 && lblocks == name_block) {
		    /* this whole block can be freed */
		    if (c)
			c->next_name = b->next_name;
		    else
			first_name = b->next_name;
		    myfree(b);
		    watch_memory -=
			sizeof(name_block_t) + name_block * sizeof(free_name_t);
		}
		return;
	    }
	}
	c = b;
	b = b->next_name;
    }
#if USE_SHOULDBOX
    /* not found? log it in the shouldbox! */
    error_report(error_shouldbox_notfound, "free_watch_name", "nw");
    main_shouldbox++;
#endif
    return;
}


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
    while (first_name) {
	name_block_t * this = first_name;
	first_name = first_name->next_name;
	myfree(this);
    }
    pthread_cond_destroy(&queue_write_cond);
    pthread_cond_destroy(&queue_read_cond);
    pthread_mutex_destroy(&queue_lock);
}

/* initialise event queue */

static const char * initialise_queue(const config_t * cfg) {
    int code;
    name_block = 1 + cfg->notify_name_block / sizeof(free_name_t);
    notify_queue_block = cfg->notify_queue_block;
    notify_max = cfg->notify_max;
    notify_initial = cfg->notify_initial;
    code = pthread_mutex_init(&queue_lock, NULL);
    if (code)
	return error_sys_errno("initialise_queue", "pthread_mutex_init", code);
    code = pthread_cond_init(&queue_read_cond, NULL);
    if (code) {
	pthread_mutex_destroy(&queue_lock);
	return error_sys_errno("initialise_queue", "pthread_cond_init", code);
    }
    code = pthread_cond_init(&queue_write_cond, NULL);
    if (code) {
	pthread_cond_destroy(&queue_read_cond);
	pthread_mutex_destroy(&queue_lock);
	return error_sys_errno("initialise_queue", "pthread_cond_init", code);
    }
    first_block = NULL;
    queue_blocks = 0;
    while (queue_blocks < cfg->notify_initial || queue_blocks < 1) {
	const char * err = allocate_block(NULL);
	if (err) {
	    deallocate_queue();
	    return err;
	}
    }
    read_block = write_block = first_block;
    event_count = watch_count = watch_active = queue_bytes = queue_events =
	max_events = max_bytes = overflow = too_big = watch_memory = 0;
    first_name = NULL;
    return NULL;
}

/* allocates space for one watch block */

static watch_block_t * allocate_watch_block(int block) {
    int i;
    watch_block_t * b = mymalloc(sizeof(watch_block_t) +
				 notify_watch_block * sizeof(notify_watch_t));
    if (! b)
	return NULL;
    for (i = 0; i < notify_watch_block; i++) {
	b->w[i].valid = 0;
	b->w[i].block_ptr = b;
    }
    b->block_num = block;
    b->next = watches_by_inode;
    b->prev = NULL;
    if (watches_by_inode) watches_by_inode->prev = b;
    watches_by_inode = b;
    watch_memory += notify_watch_block * sizeof(notify_watch_t);
    return b;
}

/* simple hash function on names; it's not meant to be exciting */

static int name_hash(const char * name) {
    int num = 0, len = 0;
    while (name[len] && len < sizeof(int)) len++;
    memcpy(&num, name, len);
    return num % NAME_HASH;
}

/* store watch in a block */

static inline notify_watch_t * store_watch(dev_t device,
					   ino_t inode,
					   const char * name,
					   notify_watch_t * parent,
					   watch_block_t * wb,
					   int offset)
{
    int hash = name_hash(name), len = strlen(name), j;
    char * wname = allocate_watch_name(&wb->w[offset], len);
    if (! wname) return NULL;
    watch_count++;
    wb->w[offset].valid = 1;
    wb->w[offset].name_hash = hash;
    wb->w[offset].name_length = len;
    wb->w[offset].watch_id = -1;
    wb->w[offset].device = device;
    wb->w[offset].inode = inode;
    if (parent) {
	wb->w[offset].next_name = parent->subdir[hash];
	if (parent->subdir[hash])
	    parent->subdir[hash]->prev_name = &wb->w[offset];
	parent->subdir[hash] = &wb->w[offset];
	wb->w[offset].parent = parent;
    } else {
	wb->w[offset].next_name = NULL;
	wb->w[offset].parent = NULL;
    }
    wb->w[offset].prev_name = NULL;
    for (j = 0; j < NAME_HASH; j++)
	wb->w[offset].subdir[j] = NULL;
    strncpy(wname, name, len);
    return &wb->w[offset];
}

/* find watch given its dev/inode, optionally allocates space for it */

static notify_watch_t * find_watch_by_inode(dev_t device,
					    ino_t inode,
					    const char * name,
					    notify_watch_t * parent)
{
    unsigned int id = (unsigned int)device + (unsigned int)inode;
    unsigned int block = id / notify_watch_block;
    unsigned int offset = id % notify_watch_block;
    watch_block_t * wb;
    wb = watches_by_inode;
    while (wb) {
	if (wb->block_num == block) {
	    if (wb->w[offset].valid) {
		if (wb->w[offset].device == device &&
		    wb->w[offset].inode == inode)
			return &wb->w[offset];
	    } else if (name) {
		/* we can allocate it here */
		return store_watch(device, inode, name, parent, wb, offset);
	    }
	}
	wb = wb->next;
    }
    /* not found */
    if (! name) return NULL;
    wb = allocate_watch_block(block);
    if (! wb) return NULL;
    return store_watch(device, inode, name, parent, wb, offset);
}

/* find watch given its kernel ID */

static notify_watch_t * find_watch_by_id(int watch_id) {
    unsigned int block = (unsigned int)watch_id / notify_watch_block;
    unsigned int offset = (unsigned int)watch_id % notify_watch_block;
    watch_by_id_t * wi;
    wi = watches_by_id;
    while (wi) {
	if (wi->block_num == block) {
	    if (wi->w[offset])
		return wi->w[offset];
	    return NULL;
	}
	wi = wi->next;
    }
    /* not found */
    return NULL;
}

/* allocates space for one watch-by-id block */

static watch_by_id_t * allocate_watch_by_id(int block) {
    int i;
    watch_by_id_t * b =
	mymalloc(sizeof(watch_by_id_t) +
		 notify_watch_block * sizeof(notify_watch_t *));
    if (! b)
	return NULL;
    b->block_num = block;
    for (i = 0; i < notify_watch_block; i++)
	b->w[i] = NULL;
    b->next = watches_by_id;
    b->prev = NULL;
    if (watches_by_id) watches_by_id->prev = b;
    watches_by_id = b;
    return b;
}

/* set watch ID on an existing watch: this is used when the watch becomes
 * active; note that we expect not to find it already stored */

static int set_watch_id(notify_watch_t * wp, int watch_id) {
    unsigned int block = (unsigned int)watch_id / notify_watch_block;
    unsigned int offset = (unsigned int)watch_id % notify_watch_block;
    watch_by_id_t * wi;
    wi = watches_by_id;
    while (wi) {
	if (wi->block_num == block) {
	    if (wi->w[offset]) {
	    /* shouldn't happen(TM) */
#if USE_SHOULDBOX
		main_shouldbox++;
		error_report(error_internal, "set_watch_id",
			     "duplicate watch");
#endif
		return 1;
	    }
	    wi->w[offset] = wp;
	    wp->watch_id = watch_id;
	    watch_active++;
	    return 1;
	}
	wi = wi->next;
    }
    /* need to create new block */
    wi = allocate_watch_by_id(block);
    if (! wi) return 0;
    wi->w[offset] = wp;
    wp->watch_id = watch_id;
    watch_active++;
    return 1;
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
	strncpy(buffer + len, watch_dir_name(wp), wp->name_length);
	wp = wp->parent;
    }
}

/* queue event: called with queue lock held */

static void queue_event(notify_event_type_t type, int is_dir,
			notify_watch_t * wfrom, const char * from,
			notify_watch_t * wto, const char * to)
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
		pthread_cond_wait(&queue_write_cond, &queue_lock);
		continue;
	    }
	    err = allocate_block(write_block);
	    if (err) {
		/* sigh */
		error_report(error_extending_queue, err);
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
    if (wp->next_name)
	wp->next_name->prev_name = wp->prev_name;
    if (wp->prev_name)
	wp->prev_name->next_name = wp->next_name;
    else if (wp->parent)
	wp->parent->subdir[wp->name_hash] = wp->next_name;
    wp->parent = NULL;
    wp->next_name = NULL;
    wp->prev_name = NULL;
}

/* gives a watch a parent */

static void adopt_watch(notify_watch_t * parent, notify_watch_t * child) {
    child->next_name = parent->subdir[child->name_hash];
    if (parent->subdir[child->name_hash])
	parent->subdir[child->name_hash]->prev_name = child;
    parent->subdir[child->name_hash] = child;
    child->prev_name = NULL;
    child->parent = parent;
}

/* removes watch id and if appropriate deallocate watch block */

static void remove_watch_id(notify_watch_t * wp) {
    watch_by_id_t * wi;
    unsigned int wid = wp->watch_id;
    unsigned int block = wid / notify_watch_block;
    unsigned int offset = wid % notify_watch_block;
    wp->watch_id = -1;
    wi = watches_by_id;
    while (wi) {
	if (wi->block_num == block) {
	    wi->w[offset] = NULL;
	    return;
	}
	wi = wi->next;
    }
}

/* deallocates a watch and its descendents */

static void deallocate_watch(notify_watch_t * wp, int rmroot) {
    int i;
#if USE_SHOULDBOX
    if (! wp->valid) {
	main_shouldbox++;
	error_report(error_shouldbox_int, "deallocate_watch",
		     "wp->valid", wp->valid);
	return;
    }
#endif
    free_watch_name(wp);
    for (i = 0; i < NAME_HASH; i++)
	while (wp->subdir[i])
	    deallocate_watch(wp->subdir[i], rmroot);
    if (wp == root_watch && ! rmroot)
	return;
    wp->valid = 0;
    orphan_watch(wp);
#if USE_SHOULDBOX
    if (watch_count < 1) {
	main_shouldbox++;
	error_report(error_shouldbox_int, "deallocate_watch",
		     "watch_count--", watch_count);
	return;
    }
    if (wp->block_ptr) {
	unsigned int id = (unsigned int)wp->inode + (unsigned int)wp->device;
	int offset = id % notify_watch_block;
	watch_block_t * b = wp->block_ptr;
	if (&b->w[offset] != wp) {
	    error_report(error_shouldbox_misptr,
			 "deallocate_watch", "wp->block_ptr");
	    return;
	}
    } else {
	error_report(error_shouldbox_null,
		     "deallocate_watch", "wp->block_ptr");
	return;
    }
#endif
    /* we must do this AFTER going through the subdirs, otherwise another
     * thread may notice the watch has been removed and call deallocate_watch
     * with the same watch, leading to a race condition; it is safe here:
     * by the time the other thread makes the call, there is nothing to
     * recurse on, and wp->watch_id is negative */
    if (wp->watch_id >= 0) {
	int watch_id = wp->watch_id;
	watch_active--;
	remove_watch_id(wp);
	inotify_rm_watch(inotify_fd, watch_id);
    }
    watch_count--;
}

static void deallocate_watch_blocks(void) {
    watch_block_t * wb = watches_by_inode;
    watch_by_id_t * wi = watches_by_id;
    while (wb) {
	int i, valid;
	watch_block_t * this = wb;
	wb = wb->next;
	for (i = valid = 0; i < notify_watch_block; i++)
	    if (this->w[i].valid)
		valid++;
	if (valid == 0) {
	    /* this block is not used, can be deleted */
	    if (this->prev)
		this->prev->next = this->next;
	    else
		watches_by_inode = this->next;
	    if (this->next)
		this->next->prev = this->prev;
	    watch_memory -= notify_watch_block * sizeof(notify_watch_t);
	    myfree(this);
	}
    }
    while (wi) {
	watch_by_id_t * this = wi;
	int i, valid;
	wi = wi->next;
	for (i = valid = 0; i < notify_watch_block; i++)
	    if (this->w[i])
		valid++;
	if (valid == 0) {
	    /* this block is not used, can be deleted */
	    if (this->prev)
		this->prev->next = this->next;
	    else
		watches_by_id = this->next;
	    if (this->next)
		this->next->prev = this->prev;
	    myfree(this);
	}
    }
}

/* deallocate buffers and memory structures */

static void deallocate_buffers(void) {
    watch_block_t * wb;
    watch_by_id_t * wi;
    if (root_watch)
	deallocate_watch(root_watch, 1);
    wb = watches_by_inode;
    while (wb) {
	int i;
	watch_block_t * this = wb;
	wb = wb->next;
	for (i = 0; i < notify_watch_block; i++)
	    if (this->w[i].valid)
		deallocate_watch(&this->w[i], 1);
    }
    wb = watches_by_inode;
    while (wb) {
	watch_block_t * g = wb;
	wb = wb->next;
	myfree(g);
    }
    wi = watches_by_id;
    while (wi) {
	watch_by_id_t * g = wi;
	wi = wi->next;
	myfree(g);
    }
    if (event_buffer)
	myfree(event_buffer);
    if (inotify_fd >= 0)
	close(inotify_fd);
    deallocate_queue();
}

/* initialisation required before the notify thread starts;
 * returns NULL if OK, otherwise an error message */

const char * notify_init(const config_t * cfg) {
    struct stat sbuff;
    const char * err = initialise_queue(cfg);
    if (err) return err;
    notify_watch_block = cfg->notify_watch_block;
    /* in case we need to undo init midway */
    root_watch = NULL;
    watch_by_id = NULL;
    event_buffer = NULL;
    watches_by_inode = NULL;
    watches_by_id = NULL;
    inotify_fd = -1;
    /* allocate event buffer */
    buffer_size = cfg->notify_buffer;
    buffer_extra = buffer_size + sizeof(struct inotify_event) + NAME_MAX + 32;
    event_buffer = mymalloc(buffer_extra);
    if (! event_buffer) {
	err = error_sys("notify_init", "malloc");
	deallocate_buffers();
	return err;
    }
    /* set up inotify */
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
	err = error_sys("notify_init", "inotify_init");
	deallocate_buffers();
	return err;
    }
    /* set up root watch */
    if (stat("/", &sbuff) < 0) {
	/* OUCH! */
	err = error_sys("notify_init", "/");
	deallocate_buffers();
    }
    root_watch =
	find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, "", NULL);
    if (! root_watch) {
	err = error_sys("notify_init", "/");
	deallocate_buffers();
    }
    return NULL;
}

/* queue a rename event */

static void rename_event(struct inotify_event * evp, notify_watch_t * evw,
			 struct inotify_event * destp, notify_watch_t * destw,
			 int is_dir)
{
    int dlen, namelen;
    char * wname;
    /* make sure the rename is from evp to destp */
    if (evp->mask & IN_MOVED_TO) {
	struct inotify_event * swp;
	notify_watch_t * sww;
	swp = destp; destp = evp; evp = swp;
	sww = destw; destw = evw; evw = sww;
    }
    queue_event(notify_rename, is_dir, evw, evp->name, destw, destp->name);
    /* do we need to update our watch data? */
    if (evp->mask & IN_ISDIR) {
	int evh = name_hash(evp->name);
	notify_watch_t * evx;
#if USE_SHOULDBOX
	notify_watch_t * destx;
	int desth = name_hash(destp->name);
#endif
	/* find the watch being renamed */
	evx = evw->subdir[evh];
	namelen = strlen(evp->name);
	while (evx) {
	    if (evx->name_length == namelen &&
		strncmp(watch_dir_name(evx), evp->name, namelen) == 0)
		    break;
	    evx = evx->next_name;
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
	namelen = strlen(destp->name);
	while (destx) {
	    if (destx->name_length == namelen &&
		strncmp(watch_dir_name(destx), destp->name, namelen) == 0)
	    {
		main_shouldbox++;
		error_report(error_rename_exists, destp->name);
		deallocate_watch(destx, 0);
		break;
	    }
	    destx = destx->next_name;
	}
#endif
	/* change parent and name */
	if (evw != destw) {
	    orphan_watch(evx);
	    adopt_watch(destw, evx);
	}
	dlen = strlen(destp->name);
	free_watch_name(evx);
	wname = allocate_watch_name(evx, dlen);
	if (wname)
	    strncpy(wname, destp->name, dlen);
	evx->name_length = dlen;
    }
}

/* run notify thread; returns NULL on normal termination,
 * or an error message */

const char * notify_thread(void) {
    int ov;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ov);
    while (main_running) {
	int buffer_start = 0, buffer_end = 0, errcode;
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
	/* lock queue */
	errcode = pthread_mutex_lock(&queue_lock);
	if (errcode)
	    return error_sys_errno("notify_thread", "pthread_mutex_lock",
				   errcode);
	/* process all these events */
	while (buffer_start < buffer_end && main_running) {
	    struct inotify_event * evp;
	    notify_watch_t * evw;
	    notify_event_type_t evtype;
	    int is_dir;
	    /* get next event */
	    evp = (void *)&event_buffer[buffer_start];
	    buffer_start += sizeof(struct inotify_event) + evp->len;
	    /* handle all nameless events */
	    if (evp->mask & IN_Q_OVERFLOW) {
		queue_event(notify_overflow, 0, NULL, NULL, NULL, NULL);
		overflow++;
		continue;
	    }
	    evw = find_watch_by_id(evp->wd);
	    if (! evw) continue;
	    is_dir = evp->mask & IN_ISDIR;
	    if (evp->mask & (IN_UNMOUNT | IN_DELETE_SELF | IN_IGNORED)) {
		/* kernel automatically removes the watch; we need to free our
		 * data structures */
		if (evw->valid) {
		    evw->watch_id = -1;
		    deallocate_watch(evw, 0);
		}
		continue;
	    }
	    /* if it is a rename, see if it is followed by the other half */
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
		    struct inotify_event * destp =
			(void *)&event_buffer[buffer_start];
		    if (destp->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
			if (destp->cookie == evp->cookie) {
			    /* this is a rename event... */
			    notify_watch_t * destw =
				find_watch_by_id(destp->wd);
			    if (destw) {
				buffer_start +=
				    sizeof(struct inotify_event) + destp->len;
				rename_event(evp, evw, destp, destw, is_dir);
				continue;
			    }
			}
		    }
		}
	    }
	    /* not a rename event, or from/to is not watched */
	    if (evp->mask & (IN_CREATE | IN_MOVED_TO)) {
		evtype = notify_create;
		if (evp->mask & IN_ISDIR) {
		    notify_watch_t * added = notify_add(evw, evp->name);
		    if (! added)
			error_report(error_add_watch, errno, evp->name);
		    // XXX scan this directory and add synthetic events for all entries
		}
	    } else if (evp->mask & (IN_DELETE | IN_MOVED_FROM)) {
		evtype = notify_delete;
		if (evp->mask & IN_ISDIR)
		    notify_remove(evw, evp->name, 1);
	    } else if (evp->mask & IN_CLOSE_WRITE) {
		evtype = notify_change_data;
	    } else if (evp->mask & IN_ATTRIB) {
		evtype = notify_change_meta;
	    } else {
#if USE_SHOULDBOX
		/* shouldn't happen(TM) */
		main_shouldbox++;
		error_report(error_shouldbox_int, "notify_thread",
			     "evp->mask", evp->mask);
#endif
		continue;
	    }
	    queue_event(evtype, is_dir, evw,
			evp->len > 0 ? evp->name : NULL,
			NULL, NULL);
	}
	/* if reader is waiting for data, let them know */
	pthread_cond_signal(&queue_read_cond);
	/* unlock queue */
	pthread_mutex_unlock(&queue_lock);
	/* periodic cleanup */
	deallocate_watch_blocks();
    }
    return NULL;
}

/* cleanup required after the notify thread terminates */

void notify_exit(void) {
    /* destroy inotify */
    close(inotify_fd);
    inotify_fd = -1;
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
}

/* look up a directory by name and return the corresponding watch, if
 * found; if not found, return NULL if addit is 0, otherwise it will
 * try to add it: returns NULL if that is not possible. */

notify_watch_t * notify_find_bypath(const char * path, int addit) {
    struct stat sbuff;
    notify_watch_t * wc;
    int olddir, pathdir, e, p = -1;
    dev_t dev[MAXPATHCOM];
    ino_t ino[MAXPATHCOM];
    int com = 0;
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
    wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, NULL, NULL);
    if (wc) {
	if (addit && wc->watch_id < 0) {
	    int wid, errcode;
	    errcode = pthread_mutex_lock(&queue_lock);
	    if (errcode) {
		errno = errcode;
		return NULL;
	    }
	    queue_event(notify_add_tree, 1, NULL, path, NULL, NULL);
	    pthread_cond_signal(&queue_read_cond);
	    pthread_mutex_unlock(&queue_lock);
	    wid = inotify_add_watch(inotify_fd, path, I_MASK);
	    if (wid < 0)
		return NULL;
	    if (! set_watch_id(wc, wid)) {
		int e = errno;
		inotify_rm_watch(inotify_fd, wid);
		errno = e;
		return NULL;
	    }
	}
	return wc;
    }
    if (! addit) {
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
	fchdir(olddir);
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
	wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, NULL, NULL);
	if (wc) {
	    /* we found one we already know about */
	    while (com > 0) {
		int namelen = store_length(wc, 0), found = 0, wid, errcode;
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
		    strcpy(name + namelen + 1, E->d_name);
		    if (stat(name, &sbuff) < 0)
			continue;
		    if (sbuff.st_ino != ino[com - 1])
			continue;
		    if (sbuff.st_dev != dev[com - 1])
			continue;
		    /* found it... */
		    wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, E->d_name, wc);
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
		fchdir(olddir);
		close(olddir);
		close(pathdir);
		errcode = pthread_mutex_lock(&queue_lock);
		if (errcode) {
		    errno = errcode;
		    goto error;
		}
		queue_event(notify_add_tree, 1, NULL, path, NULL, NULL);
		pthread_cond_signal(&queue_read_cond);
		pthread_mutex_unlock(&queue_lock);
		wid = inotify_add_watch(inotify_fd, path, I_MASK);
		if (wid < 0)
		    return NULL;
		if (! set_watch_id(wc, wid)) {
		    int e = errno;
		    inotify_rm_watch(inotify_fd, wid);
		    errno = e;
		    return NULL;
		}
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
    }
    /* we only get here if there's an error */
error:
    e = errno;
    if (p >= 0) close(p);
    fchdir(olddir);
    close(pathdir);
    close(olddir);
    errno = e;
    return NULL;
}

/* remove a watch and all its subdirectories */

void notify_remove_under(notify_watch_t * wp) {
    deallocate_watch(wp, 0);
}

/* adds a directory watch; returns NULL, and sets errno, on error;
 * parent is an existing directory watch; name is relative to that
 * directory and must not contain directory separator characters */

notify_watch_t * notify_add(notify_watch_t * parent, const char * path) {
    struct stat sbuff;
    notify_watch_t * wc;
    int wid, plen = path ? strlen(path) : -1;
    int namelen = store_length(parent, plen);
    char full_path[1 + namelen];
    store_name(parent, path, plen, full_path, namelen, 1);
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
    if (stat(full_path, &sbuff) < 0)
	return NULL;
    wc = find_watch_by_inode(sbuff.st_dev, sbuff.st_ino, path, parent);
    if (! wc)
	return NULL;
    if (wc->watch_id >= 0)
	return wc;
    wid = inotify_add_watch(inotify_fd, full_path, I_MASK);
    if (wid < 0)
	return NULL;
    if (! set_watch_id(wc, wid)) {
	int e = errno;
	inotify_rm_watch(inotify_fd, wid);
	errno = e;
	return NULL;
    }
    return wc;
}

/* removes a directory watch; returns 1 if found, 0 if not found,
 * -1 if found but has children; takes the same arguments as notify_add() */

int notify_remove(notify_watch_t * parent, const char * path, int recurse) {
    int hash = name_hash(path), namelen = strlen(path);
    notify_watch_t * wp = parent->subdir[hash];
    while (wp) {
	if (wp->name_length == namelen &&
	    strncmp(watch_dir_name(wp), path, namelen) == 0)
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
	wp = wp->next_name;
    }
    return 0;
}

/* returns root watch */

notify_watch_t * notify_root(void) {
    return root_watch;
}

/* returns current queue status */

static int get_proc(const char * name) {
    FILE * proc;
    int rv = -1;
    proc = fopen(name, "r");
    if (! proc) return -1;
    fscanf(proc, "%d", &rv);
    fclose(proc);
    return rv;
}

void notify_status(notify_status_t * status) {
    status->queue_bytes = queue_bytes;
    status->queue_min = notify_initial * notify_queue_block;
    status->queue_max = notify_max * notify_queue_block;
    status->queue_cur = queue_blocks * notify_queue_block;
    status->queue_events = queue_events;
    status->max_bytes = max_bytes;
    status->max_events = max_events;
    status->overflow = overflow;
    status->too_big = too_big;
    status->watches = watch_active;
    status->watchmem = watch_memory;
    status->events = event_count;
    status->kernel_max_watches =
	get_proc("/proc/sys/fs/inotify/max_user_watches");
    status->kernel_max_events =
	get_proc("/proc/sys/fs/inotify/max_queued_events");
}

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
    const char * statit;
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
		if (S_ISDIR(sbuff.st_mode) && qev.event_type == notify_create) {
		    // XXX scan this directory and generate synthetic events for all contents
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
#endif
    /* if the block is empty, and the write pointer is elsewhere, we
     * skip to the next block after resetting this one */
#if USE_SHOULDBOX
out:
#endif
    if (read_block->read_bytes < 1 && read_block != write_block) {
	read_block->read_pos = read_block->event;
	read_block->read_bytes = 0;
	read_block->read_count = 0;
	read_block->write_pos = read_block->event;
	read_block->write_space = notify_queue_block;
	read_block = read_block->next;
	if (! read_block) read_block = first_block;
    }
    /* somebody may be waiting for space */
    pthread_cond_signal(&queue_write_cond);
    /* unlock the queue and return data */
    pthread_mutex_unlock(&queue_lock);
    return retval;
}

/* executes a callback once for each active watch */

int notify_forall_watches(int (*cb)(const char *, void *), void * P) {
    watch_block_t * wb = watches_by_inode;
    while (wb) {
	int offset;
	for (offset = 0; offset < notify_watch_block; offset++) {
	    if (wb->w[offset].valid && wb->w[offset].watch_id >= 0) {
		int nl = store_length(wb->w[offset].parent,
				      wb->w[offset].name_length);
		char wname[nl + 1];
		store_name(wb->w[offset].parent, watch_dir_name(&wb->w[offset]),
			   wb->w[offset].name_length, wname, nl, 1);
		if (! cb(wname, P))
		    return 0;
	    }
	}
	wb = wb->next;
    }
    return 1;
}

