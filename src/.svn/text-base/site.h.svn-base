#ifndef __SHOULD_SITE_H__
#define __SHOULD_SITE_H__ 1

/* local definitions (this file may be automatically generated in future)
 *
 * this file is part of SHOULD
 *
 * Copyright (c) 2008, 2009 Claudio Calvelli <should@intercal.org.uk>
 * 
 * Licenced under the terms of the GPL v3. See file COPYING in the
 * distribution for further details.
 */

/* maximum line length when reading a configuration file */

#define CONFIG_LINESIZE 1024

/* maximum block size for file data copy */

#define DATA_BLOCKSIZE 1048576

/* used to hash the directory names; make this a prime */

#define NAME_HASH 31

/* use a "should box"? Some error conditions cannot be detected without this */

#define USE_SHOULDBOX 1

/* time to wait for events before rechecking if the program is terminating;
 * unit: milliseconds */

#define POLL_TIME 5000

/* time to wait if another thread hasn't terminated yet; unit: milliseconds */

#define WAIT_TIME 100

/* location of system-wide configuration, file */

#define SYSTEM_CONFIG "/etc/should.conf"

/* location, relative to the user's home directory, of configuration file */

#define USER_CONFIG ".should.conf"

/* location of control socket, when the program runs as root */

#define ROOT_SOCKET "/var/run/should.socket"

/* location, relative to the user's home directory, of control socket, when
 * the program runs as non-root user */

#define USER_SOCKET ".should.socket"

/* location of log file, if used, when the program runs as root */

#define ROOT_LOGFILE "/var/log/should.log"

/* location, relative to the user's home directory, of log file, when the
 * program runs as non-root user */

#define USER_LOGFILE ".should.log"

/* program to use to send email; must behave like /bin/mail */

#define MAILER "/bin/mail"

/* location of event dir, if used, when the program runs as root */

#define ROOT_EVENTDIR "/var/log/should.events"

/* location, relative to the user's home directory, of event dir, when the
 * program runs as non-root user */

#define USER_EVENTDIR ".should.events"

/* link to zlib */

#define USE_ZLIB 1

/* link to bzlib */

#define USE_BZLIB 1

#endif /* __SHOULD_SITE_H__ */
