/* local definitions (this file may be automatically generated in future)
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

#ifndef __SHOULD_SITE_H__
#define __SHOULD_SITE_H__ 1

/* maximum line length when reading a configuration file */

#define CONFIG_LINESIZE 8192

/* maximum block size for file data copy */

#define DATA_BLOCKSIZE 262144

/* used to hash the directory names; make this a prime */

#define NAME_HASH 31

/* use a "should box"? Some error conditions cannot be detected without this */

#define USE_SHOULDBOX 1

/* time to wait for events before rechecking if the program is terminating;
 * unit: milliseconds */

#define POLL_TIME 5000

/* time to wait if another thread hasn't terminated yet; unit: milliseconds */

#define WAIT_TIME 100

/* location of system-wide configuration file */

#define SYSTEM_CONFIG "/etc/should.conf"

/* name of user configuration file (relative to home directory) */

#define USER_CONFIG ".should.conf"

/* location of control socket, when the program runs as root */

#define ROOT_SOCKET_DIR "/var/run"

/* location of log file, if used, when the program runs as root */

#define ROOT_LOGFILE_DIR "/var/log"

/* program to use to send email; must behave like /bin/mail */

#define MAILER "/usr/sbin/sendmail"

/* location of event dir, if used, when the program runs as root */

#define ROOT_EVENTDIR_DIR "/var/log"

#include "configure.h"

#endif /* __SHOULD_SITE_H__ */
