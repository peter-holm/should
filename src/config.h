/* data structure used to hold configuration information
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

#ifndef __SHOULD_CONFIG_H__
#define __SHOULD_CONFIG_H__ 1

/* forward declarations -- may be used by config-package.h */

typedef struct config_acl_cond_s config_acl_cond_t;
typedef struct config_acl_s config_acl_t;
typedef struct config_strlist_s config_strlist_t;
typedef struct config_unit_s config_unit_t;

/* read package-dependent definitions; the configuration system is meant to
 * be reusable on different packages */

#include "config-package.h"
#include "error.h"

/* generic ACL mechanism */

struct config_acl_cond_s {
    config_acl_cond_t * next;
    enum {
	cfg_acl_exact,          /* like strcmp() */
	cfg_acl_icase,          /* like strcasecmp() */
	cfg_acl_glob,           /* like a shell glob */
	cfg_acl_iglob,          /* like a shell glob, ignoring case */
	cfg_acl_ip4range,       /* for IPv4 data only: match range */
	cfg_acl_ip6range,       /* for IPv6 data only: match range */
	cfg_acl_function,       /* call func(PATTERN, DATA, ALL_DATA, DSIZE) */
	cfg_acl_call_or,        /* any subcondition returns true */
	cfg_acl_call_and        /* all subconditions return true */
    } how;
    int data_index;             /* index into the data supplied to match */
    int negate;                 /* negate result */
    /* which of the union element is used depends on the value of "how";
     * if "pattern" is used, its size will extend this structure */
    union {
	int (*func)(const char *, const char *, const char *[], int);
	config_acl_cond_t * subcond;
    };
    char pattern[0];
};

struct config_acl_s {
    config_acl_t * next;
    config_acl_cond_t * cond;
    int result;
};

/* list of strings */

struct config_strlist_s {
    config_strlist_t * next;
    void * privdata;
    void (*freepriv)(void *);
    void * (*duppriv)(const void *);
    int datalen;
    char data[0];
};

/* define units, for configuration elements which use name + unit */

struct config_unit_s {
    int multiply;
    const char * name_singular;
    const char * name_plural;
};

/* predefined units */

extern const config_unit_t config_intervals[], config_sizes[];

/* the configuration data */

typedef struct config_data_s config_data_t;

/* obtain configuration data from command-line arguments; returns 0 on
 * error, 1 on success */

int config_init(int argc, char *argv[]);

/* obtain a read-only copy of the current configuration; this is guaranteed
 * not to change even if the configuration gets updated; however a second
 * call to config_get may return different data */

const config_data_t * config_get(void);

/* obtain values */

int config_intval(const config_data_t *, config_int_names_t);

int config_intarr_len(const config_data_t *, config_intarr_names_t);
const int * config_intarr_data(const config_data_t *, config_intarr_names_t);

int config_strlen(const config_data_t *, config_str_names_t);
const char * config_strval(const config_data_t *, config_str_names_t);

char * const * config_strarr(const config_data_t *, config_strarr_names_t);
int config_strarr_len(const config_data_t *, config_strarr_names_t);

const config_strlist_t * config_strlist(const config_data_t *,
					config_strlist_names_t);

const config_acl_t * config_aclval(const config_data_t *, config_acl_names_t);

/* stop using a read-only copy of the configuration */

void config_put(const config_data_t *);

/* makes a copy of the configuration which will allow updates; returns an
 * error message, or NULL if OK */

const char * config_start_update(void);

/* updates the configuration; this only works if config_update has been
 * called and also the update is valid; returns an error message or NULL
 * if the update succeeded */

const char * config_do_update(const char *);

/* commits the configuration update; the next call to config_get() will
 * get the new configuration; returns and error message or NULL if OK */

const char * config_commit_update(void);

/* cancels the update */

void config_cancel_update(void);

/* free configuration data */

void config_free(void);

/* filehandle to the current copy file, if it has been opened by config_init */

extern FILE * config_copy_file;

/* start of variable part of copy file, if it has been opened by config_init */

extern long config_copy_start;

/* print current configuration to a file */

void config_print(int (*)(void *, const char *), void *);

/* parse a number + unit and returns a plain number */

int config_parse_unit(const config_unit_t[], const char *);

/* the opposite of the above */

const char * config_print_unit(const config_unit_t[], int);

/* stores copy data to a small configuration file, suitable for loading
 * by the copy thread */

int config_store_copy(int fnum, int fpos, const char * user, const char * pass);

/* used by the store thread to change its error dest to syslog; to be
 * called during initialisation only. Not thread-safe */

const char * config_change_error_dest(error_message_t, const char *);

/* check an ACL */

int config_check_acl(const config_acl_t * acl,
		     const char *data[], int datasize, int notfound);

/* check an ACL condition; if is_and is nonzero, all the element must
 * return true; if is_and is zero, the first which matches decides whether
 * the result is true (if it is not negated) or false (if it is negated) */

int config_check_acl_cond(const config_acl_cond_t * cond, int is_and,
			  const char *data[], int datasize);

/* copies an ACL / condition (deep copy) */

config_acl_cond_t * config_copy_acl_cond(const config_acl_cond_t * cond);
config_acl_t * config_copy_acl(const config_acl_t * acl);

/* frees a condition */

void config_free_acl_cond(config_acl_cond_t * cond);

/* user-editable error message data */

const char * config_error_message(const config_data_t *, error_message_t);
error_dest_t config_error_destination(const config_data_t *, error_message_t);
int config_error_facility(const config_data_t *, error_message_t);

#endif /* __SHOULD_CONFIG_H__ */
