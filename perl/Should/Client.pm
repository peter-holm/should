# Perl client to interface to a running "should" server

# This file is part of SHOULD

# Copyright (c) 2008, 2009 Claudio Calvelli <should@shouldbox.co.uk>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING in the distribution).
# If not, see <http://www.gnu.org/licenses/>.

=head1 NAME

Should::Client - Interface to a running should server

=head1 SYNOPSIS

    use Should::Client;

    my $should = Should::Client->new(
	'localhost',          # host name
	12345,                # TCP port
	'myself',             # user
	'mysecret',           # password
    );

    $should->getfile('/path/to/remote', '/path/to/local');

=head1 DESCRIPTION

C<Should::Client> provides a Perl interface to a running C<should> server
via TCP. The server must have been started using the C<listen> option for
this to work.

Replication event handling is currently not supported, however all other
commands are implemented. This allows to obtain directory listing, file
data, server status. It also allows to add or remove watches, as well as
obtaining the current watch list.

=cut

# TODO - replication event handling

package Should::Client;

use strict;
use Carp;
use IO::Socket;
use IO::Socket::INET;
my $ipclass;
BEGIN {
    # use IPv6 if possible, fall back to IPv4 if not
    $ipclass = 'IO::Socket::INET';
    eval {
	require IO::Socket::INET6;
	$ipclass = 'IO::Socket::INET6';
    };
}
use IO::Socket::UNIX;
use POSIX qw(EINVAL EPERM);
use Socket qw(SOL_SOCKET SO_PASSCRED SCM_CREDENTIALS);
use Digest::MD5;
use Time::Local 'timegm';

our $VERSION = '1.0.-6';

my %compression = (
    null => sub { $_[0] },
);

eval {
    # if supported, add "gzip" compression
    require Compress::Zlib;
    $compression{gzip} = sub { Compress::Zlib::uncompress($_[0]) };
};

eval {
    # if supported, add "bzip2" compression
    require Compress::Bzip2;
    $compression{bzip2} = sub { Compress::Bzip2::memBunzip($_[0]) };
};

=head1 CONSTRUCTORS

=over 4

=item new(HOST, PORT, USERNAME, PASSWORD)

Opens a TCP connection to the server and authenticates using the given
credentials. If successful, returns an object reference which can be
used with the methods described below. On failure, it calls C<die>
with an appropriate message.

That connection will be over IPv6 if possible, falling back to
IPv4 if necessary.

=item new(SOCKET)

Opens a connection via Unix-domain sockets. Only works if L<Socket::MsgHdr>
is installed.

=back

=cut

sub new {
    @_ == 2 || @_ == 5
	or croak "Usage: Should::Client->new(HOST, PORT, USER, PASSWORD)\n"
	       . "   or: Should::Client->new(SOCKET)";
    my ($class, $fh, $id);
    if (@_ == 5) {
	my ($host, $port, $user, $pass);
	($class, $host, $port, $user, $pass) = @_;
	$fh = $ipclass->new(
	    PeerHost => $host,
	    PeerPort => $port,
	    Proto    => 'tcp',
	    Type     => SOCK_STREAM,
	) or die "$host\:$port\: $!\n";
	autoflush $fh 1;
	local $/ = "\012";
	my $challenge = <$fh>;
	$challenge =~ s/\012$//;
	$challenge =~ s/\015$//;
	defined $challenge
	    and $challenge =~ s/^SHOULD\s+\[([[:xdigit:]]+)\].*$/$1/
		or die "Invalid reply received from server: $challenge\n";
	$challenge =~ s/([[:xdigit:]]{2})/chr(hex $1)/ge;
	my $md5 = Digest::MD5->new();
	defined $user and $md5->add($user);
	$md5->add($challenge);
	defined $pass and $md5->add($pass);
	my $response = $md5->hexdigest;
	local $\ = '';
	print $fh "$user $response\015\012";
	my $ok = <$fh>;
	defined $ok or die "No reply from server\n";
	$ok =~ s/\012$//;
	$ok =~ s/\015$//;
	$ok ne '' or die "No reply from server\n";
	$ok =~ /^OK/ or die "Server replied $ok\n";
	$id = "$host\:$port";
    } else {
	eval { require Socket::MsgHdr };
	$@ and croak "Connection to should via socket not supported: install Socket::MsgHdr to enable";
	my ($socket);
	($class, $socket) = @_;
	$fh = IO::Socket::UNIX->new(Peer => $socket,
				    Type => SOCK_STREAM,
	) or die "$socket\: $!\n";
	autoflush $fh 1;
	setsockopt($fh, SOL_SOCKET, SO_PASSCRED, 1);
	my $ucred = pack('iii', $$, $<, $();
	my $auxdata = Socket::MsgHdr->new();
	$auxdata->cmsghdr(SOL_SOCKET, SCM_CREDENTIALS, $ucred);
	Socket::MsgHdr::sendmsg($fh, $auxdata)
	    or die "sendmsg: $!\n";
	$id = $socket;
	local $\ = '';
	# no idea why, if I don't output a blank line the server will
	# be waiting forever for one; however, the C client doesn't
	# do anything like that, and the server isn't actually waiting
	# for this...
	print $fh "\015\012";
    }
    bless {
	fh    => $fh,
	id    => $id,
	gdir  => 0,
    }, $class;
}

sub _command {
    my $should = shift;
    my $cmd = shift;
    my $fh = $should->{fh};
    my $data = '';
    for my $item (@_) {
	$cmd =~ s/%/length($item)/e;
	$data .= $item;
    }
    local $\ = '';
    print $fh "$cmd\015\012$data";
    local $/ = "\012";
    my $reply = <$fh>;
    defined $reply or die "No reply received from server\n";
    $reply =~ s/\012$//;
    $reply =~ s/\015$//;
    $reply ne '' or die "No reply received from server\n";
    $reply =~ s/^OK\s*// or die "Server returned: $reply\n";
    $reply;
}

=head1 METHODS

=over 4

=item close

Closes connection. If this method is not called explicitely, this will
be done by the object's destructor.

=cut

sub close {
    @_ == 1 or croak "Usage: SHOULD->close";
    my ($should) = @_;
    $should->{fh} or return $should;
    eval { $should->_command("QUIT"); };
    my $fh = $should->{fh};
    close $fh;
    $should->{fh} = undef;
    $should;
}

sub _getstat {
    my ($should, $reply, $translate, $has_ent) = @_;
    $reply =~ s/^(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+//
	or die "Invalid data received from client: $reply\n";
    my ($type, $dev, $ino, $mode) = ($1, $2, $3, oct($4));
    $type >= 0 && $type <= 7
	or die "Invalid file type code: $type\n";
    $type = substr("fdcbplsu", $type, 1);
    my $uname = undef;
    if ($translate) {
	$reply =~ s/^(\S+)\s+//
	    or die "Invalid username received from client: $reply\n";
	$uname = $1;
    }
    $reply =~ s/^(\d+)\s+//
	or die "Invalid uid received from client: $reply\n";
    my $uid = $1;
    my $gname = undef;
    if ($translate) {
	$reply =~ s/^(\S+)\s+//
	    or die "Invalid group received from client: $reply\n";
	$gname = $1;
    }
    $reply =~ s/^(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)//
	or die "Invalid gid received from client: $reply\n";
    my ($gid, $size, $mtime, $ctime, $major, $minor, $tlen) =
	($1, $2, $3, $4, $5, $6, $7);
    if ($mtime =~ /^(\d+)-(\d+)-(\d+):(\d+):(\d+):(\d+)/) {
	$mtime = timegm($6, $5, $4, $3, $2 - 1, $1);
    } else {
	die "Invalid mtime: $mtime\n";
    }
    if ($ctime =~ /^(\d+)-(\d+)-(\d+):(\d+):(\d+):(\d+)/) {
	$ctime = timegm($6, $5, $4, $3, $2 - 1, $1);
    } else {
	die "Invalid ctime: $ctime\n";
    }
    my @ent = ();
    if ($has_ent) {
	$reply =~ s/^\s+(\d+)//
	    or die "Invalid namelen received from client: $reply\n";
	my $entlen = $tlen;
	$tlen = $1;
	my $entname;
	my $fh = $should->{fh};
	read $fh, $entname, $entlen;
	@ent = ($entname);
    }
    my $target = undef;
    if ($tlen > 0) {
	my $fh = $should->{fh};
	read $fh, $target, $tlen;
    }
    ($type, $dev, $ino, $mode, $uname, $uid, $gname, $gid,
     $major, $minor, $size, $mtime, $ctime, $target, @ent);
}

=item stat(PATH [, TRANSLATE]

Asks the server to perform an C<lstat> on the given path, and returns
the result. If C<TRANSLATE> is present and true, user and group IDs
are translated to names on the server side. If absent or false, such
translation is not performed.

If there are communication error, or the C<lstat> call fails on the
server, this method calls C<die> with an appropriate message. Otherwise
it returns a true value in a scalar context and the following list
in an array context:

=over 4

=item 0

file type: 'f' for regular files, 'd' for directories, 'l' for symbolic
links, 'b' for block devices, 'c' for character devices, 'p' for named
pipes (fifos), 's' for sockets and 'u' for unrecognised file types.

=item 1

device number where the file resides: note that this number is only meaningful
to the server, but can be used to determine if a file is in the same filesystem
as another file.

=item 2

inode number: this is only meaningful to the server, but together with the
device number it uniquely identifies the file, at least until the filesystem
is unmounted, and can be used to determine if two files are hard links to
each other.

=item 3

permissions: a 12 bit number containing the file access permissions.

=item 4

user name: this field is undefined if C<TRANSLATE> was absent or false,
and is a single question mark if the user ID could not be translated to
a name.

=item 5

user ID

=item 6

group name: this field is undefined if C<TRANSLATE> was absent or false,
and is a single question mark if the group ID could not be translated to
a name.

=item 7

group ID

=item 8

major: if the file is a block or character device, the major device number,
otherwise 0.

=item 9

minor: if the file is a block or character device, the minor device number,
otherwise 0.

=item 10

size: file size, in bytes.

=item 11

mtime: file modification time

=item 12

ctime: inode change time

=item 13

target: if the file is a symbolic link, the link's target, otherwise undefined.

=back

=cut

sub stat {
    @_ == 2 || @_ == 3
	or croak "Usage: SHOULD->stat(PATH [, TRANSLATE])";
    my ($should, $path, $translate) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $translate = $translate ? 1 : 0;
    my $reply = $should->_command("STAT % $translate", $path);
    wantarray or return 1;
    $should->_getstat($reply, $translate, 0);
}

=item statfs(PATH)

Asks the server to determine filesystem status for the filesystem
containing C<PATH>. If the call fails, produces an exception using
C<die>. Otherwise it returns the following list:

=over 4

=item 0

blocksize: the filesystem block size; all other sizes are in terms of this.

=item 1

total: the total size of the filesystem, in blocks.

=item 2

free: the number of free blocks.

=item 3

avail: the number of blocks available to non-root users.

=item 4

files: the total number of inodes.

=item 5

ffree: the number of free inodes.

=back

=cut

sub statfs {
    @_ == 2 or croak "Usage: SHOULD->statfs(PATH)";
    my ($should, $path) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    my $reply = $should->_command("STATFS %", $path);
    wantarray or return 1;
    $reply =~ s/(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)//
	or die "Invalid data received from client: $reply";
    my ($blocksize, $blocktotal, $blockfree, $blockavail, $files, $ffree) =
	($1, $2, $3, $4, $5, $6);
    ($blocksize, $blocktotal, $blockfree, $blockavail, $files, $ffree);
}

=item opendir(PATH [, TRANSLATE])

Open the directory C<PATH> on the server and prepares to send the contents.
While this operation is in progress, any methods except C<readdir> and
C<closedir> will fail.

If C<TRANSLATE> is present and true, the server will translate user and
group IDs to names when sending the results. If absent or false, no such
translation will happen.

=cut

sub opendir {
    @_ == 2 || @_ == 3
	or croak "Usage: SHOULD->opendir(PATH [, TRANSLATE])";
    my ($should, $path, $translate) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $translate = $translate ? 1 : 0;
    my $reply = $should->_command("GETDIR % $translate", $path);
    $should->{gdir} = 1;
    $should->{gtran} = $translate;
    $should;
}

=item closedir

Terminates a directory scan. If required, waits for the server to finish
sending the data. This will fail if C<opendir> has not been previously
called to start the directory scan.

=cut

sub closedir {
    @_ == 1 or croak "Usage: SHOULD->closedir";
    my ($should) = @_;
    $should->{gdir} or croak "No GETDIR operation in progress";
    while ($should->{gdir} == 1) {
	$should->readdir();
    }
    $should->{gdir} = 0;
    $should;
}

=item readdir

Waits for the next directory entry from the server and returns a list with
the file name and the result of calling C<lstat> on it. The list will have
the same elements as the one returned by the C<stat> method, with the addition
of the file name at the end (after C<target>).

Returns an empty list at the end of the directory scan, and generates an
exception in case of error.

This method will fail if C<opendir> has not been previously called to
start the directory scan.

=cut

sub readdir {
    @_ == 1 or croak "Usage: SHOULD->closedir";
    my ($should) = @_;
    $should->{gdir} or croak "No GETDIR operation in progress";
    $should->{gdir} != 1 and return ();
    my $fh = $should->{fh};
    local $/ = "\012";
    my $reply = <$fh>;
    if (! defined $reply) {
	$should->{gdir} = 2;
	die "readdir: $!\n";
    }
    $reply =~ s/\012$//;
    $reply =~ s/\015$//;
    if ($reply eq '.') {
	$should->{gdir} = 2;
	return ();
    }
    $should->_getstat($reply, $should->{gtran}, 1);
}

=item getfile(REMOTE, LOCAL)

Asks the server to send the data from file C<REMOTE> and stores it in
local file C<LOCAL>. The file is created using default permissions,
and the caller is responsible for changing owner, group and access
permissions if required: the server's permissions can be obtained
by calling the C<stat> method.

=cut

sub getfile {
    @_ >= 3 && @_ % 2 == 1
	or croak "Usage: SHOULD->getfile(PATH, LOCALPATH)";
    my $should = shift;
    my $path = shift;
    my $localpath = shift;
    $should->{gdir} and croak "GETDIR operation in progress";
    my $compress = undef;
    while (@_) {
	my $key = shift;
	my $value = shift;
	if (lc($key) eq 'bwlimit') {
	    $should->_command("BWLIMIT $value");
	    next;
	}
	if (lc($key) eq 'compress') {
	    $value = lc($value);
	    exists $compression{$value}
		or die "Unknown compression type $value\n";
	    $should->_command("COMPRESS $value");
	    $compress = $value;
	    next;
	}
    }
    $should->_command("OPEN %", $path);
    my $ofh;
    open($ofh, '>', $localpath) or die "$localpath: $!\n";
    my $start = 0;
    my $size = 1048576;
    my $fh = $should->{fh};
    local $\ = '';
    while (1) {
	my $reply = $should->_command("DATA $start $size");
	my $block = '';
	if ($reply =~ /^(\d+)\s+(\d+)/) {
	    my $cblock;
	    $1 == 0 and last;
	    read $fh, $cblock, $1;
	    $block = $compression{$compress}($cblock);
	    defined $block or die "Error uncompressing block\n";
	} elsif ($reply =~ /^(\d+)/) {
	    $1 == 0 and last;
	    read $fh, $block, $1;
	} else {
	    die "Server returned: $reply\n";
	}
	print $ofh($block) or die "$localpath: $!\n";
	$start += length $block;
    }
    CORE::close($ofh) or die "$localpath: $!\n";
    $should->_command("CLOSEFILE");
    $should;
}

=item closelog

Asks the server to close its logfiles. This can be called after log rotation
to make sure the server is no longer writing to the old log files. The files
will be automatically reopened when there is something to write to them.

=cut

sub closelog {
    @_ == 1 or croak "Usage: SHOULD->closelog";
    my ($should) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $should->_command("CLOSELOG");
    $should;
}

=item purge(DAYS)

Asks the server to delete any replication event files older than the specified
number of days. Replication clients which are more than C<DAYS> out of date
will find that their next request fails, and will resort to a full sync.

=cut

sub purge {
    @_ == 2 or croak "Usage: SHOULD->purge(DAYS)";
    my ($should, $days) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $should->_command("PURGE $days");
    $should;
}

=item add(PATH, KEY => VALUE, ...)

Asks the server to add a watch, rooted at C<PATH>. Additional parameters
can be specified as C<KEY> and C<VALUE> pairs:

=over 4

=item CROSS

If the C<VALUE> is true, the watch will use the full subtree rooted at C<PATH>.
If it is false, the watch will only use subdirectories in the same filesystem
as C<PATH>, i.e. it will not cross filesystem boundaries.

=item EXCL_NAME_EXACT

Excludes any subdirectories whose name corresponds to C<VALUE> exactly.

=item EXCL_PATH_EXACT

Excludes any subdirectories whose full path corresponds to C<VALUE> exactly.

=item EXCL_NAME_CASE

Excludes any subdirectories whose name corresponds to C<VALUE> exactly,
however the comparison ignores case.

=item EXCL_PATH_CASE

Excludes any subdirectories whose full path corresponds to C<VALUE> exactly,
however the comparison ignores case.

=item EXCL_NAME_GLOB

Excludes any subdirectories whose name matches C<VALUE>, which is interpreted
as a shell-style "glob" pattern.

=item EXCL_PATH_GLOB

Excludes any subdirectories whose full path matches C<VALUE>, which is interpreted
as a shell-style "glob" pattern.

=item EXCL_NAME_IGLOB

Excludes any subdirectories whose name matches C<VALUE>, which is interpreted
as a shell-style "glob" pattern, ignoring case during comparisons.

=item EXCL_PATH_IGLOB

Excludes any subdirectories whose full path matches C<VALUE>, which is interpreted
as a shell-style "glob" pattern, ignoring case during comparisons.

=item FIND_NAME_EXACT

=item FIND_PATH_EXACT

=item FIND_NAME_CASE

=item FIND_PATH_CASE

=item FIND_NAME_GLOB

=item FIND_PATH_GLOB

=item FIND_NAME_IGLOB

=item FIND_PATH_IGLOB

Instruct the server to perform a number of add operations. First the values
specified by these keys are used to locate subdirectories within C<PATH>.
Then for each matching subdirectory, an C<add> with just the C<CROSS> and
C<EXCL_*> options is performed, rooted at that subdirectory.

These keys interpret their C<VALUE>s in the same way as the corresponding
C<EXCL> keys.

Returns the number of watches added.

=back

=cut

sub add {
    @_ >= 2 && @_ % 2 == 0
	or croak "Usage: SHOULD->add(PATH, KEY => VALUE, ...)";
    my $should = shift;
    my $path = shift;
    my $cross = 0;
    my @etc = ();
    while (@_) {
	my $key = shift;
	my $value = shift;
	if (lc($key) eq 'cross') {
	    $cross = $value;
	    next;
	}
	if ($key =~ /^(excl|find)_(name|path)_(exact|case|glob|iglob)$/i) {
	    my $cmd = uc($1);
	    my $which = uc($2);
	    my $mode = uc($3);
	    push @etc, [ "$cmd $which $mode %", $value ];
	}
	die "Invalid attribute: $key\n";
    }
    $should->_command("ADD %", $path);
    for my $cmd (@etc) {
	$should->_command(@$cmd);
    }
    my $reply = $should->_command($cross ? "CROSS" : "NOCROSS");
    $reply =~ /^\s*(\d+)/ and return $1;
    return 0;
}

=item remove(PATH)

Asks the server to remove any watches found inside the directory tree
rooted at C<PATH>.

=cut

sub remove {
    @_ == 2 or croak "Usage: SHOULD->remove(WATCH)";
    my ($should, $watch) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $should->_command("REMOVE %", $watch);
    $should;
}

=item stop

Asks the server to terminate execution. This also calls the C<close>
method automatically.

=cut

sub stop {
    @_ == 1 or croak "Usage: SHOULD->stop";
    my ($should) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    eval { $should->_command("STOP"); };
    my $fh = $should->{fh};
    CORE::close($fh);
    $should->{fh} = undef;
    $should;
}

sub _getitems {
    my ($should, $iname) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $should->_command($iname);
    my $fh = $should->{fh};
    my @wlist = ();
    local $/ = "\012";
    while (1) {
	my $reply = <$fh>;
	defined $reply or last;
	$reply =~ s/\012$//;
	$reply =~ s/\015$//;
	$reply =~ /^(\d+)/ or last;
	$1 == 0 and last;
	read $fh, $reply, $1;
	push @wlist, $reply;
    }
    @wlist;
}

=item watches

Returns the list of directories currently watched

=cut

sub watches {
    @_ == 1 or croak "Usage: SHOULD->watches";
    my ($should) = @_;
    $should->_getitems("WATCHES");
}

=item status

Returns the server's status, as a hash. The keys and values are described in
the C<should> documentation, but the following are currently defined:

=over 4

=item clients

number of client connections received

=item events

number of events recorded since server startup

=item file_current

current event log file

=item file_earliest

earliest available event log file

=item file_pos

number of bytes in current event log file

=item kernel_max_watches

the maximum number of watches per user

=item kernel_max_events

the kernel's event queue size

=item max_bytes

maximum number of bytes used for queued events, since server startup

=item max_events

maximum number of events in queue, since server startup

=item memory

number of bytes or memory allocated dynamically

=item overflow

number of times the queue overflowed

=item pid

the server's Process ID

=item queue_bytes

number of bytes of memory used by event queue

=item queue_cur

number of bytes currently allocated to event queues

=item queue_events

events currently waiting to be stored to log file

=item queue_max

maximum queue size, in bytes

=item queue_min

minimum queue size, in bytes

=item running

the time (seconds.milli) the server has been running

=item shouldbox

the number of "shouldn't happen" errors

=item systime

system CPU time (seconds.milli) used by the server

=item too_big

number of events too big to store in the queue

=item usertime

user CPU time (seconds.milli) used by the server

=item version

server version

=item watches

number of directories being watched

=item watchmem

number of bytes of memory used for watches

=back

=cut

sub status {
    @_ == 1 or croak "Usage: SHOULD->status";
    my ($should) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $should->_command("STATUS");
    my $fh = $should->{fh};
    local $/ = "\012";
    my %wlist = ();
    while (1) {
	my $reply = <$fh>;
	defined $reply or last;
	$reply =~ s/\012$//;
	$reply =~ s/\015$//;
	$reply eq '.' and last;
	$reply =~ s/^(\S+)\s*:\s*//
	    or die "Invalid reply from server: $reply\n";
	$wlist{$1} = $reply;
    }
    %wlist;
}

sub _getlist {
    my ($should, $lname) = @_;
    $should->{gdir} and croak "GETDIR operation in progress";
    $should->_command($lname);
    my $fh = $should->{fh};
    my @wlist = ();
    local $/ = "\012";
    while (1) {
	my $reply = <$fh>;
	defined $reply or last;
	$reply =~ s/\012$//;
	$reply =~ s/\015$//;
	$reply eq '__END__' and last;
	push @wlist, $reply;
    }
    @wlist;
}

=item listcompress

The name of the compression methods supported by the server. These
will be things like C<null> (no compression), C<gzip> or C<bzip2>.
Returns a list with one method per element.

=cut

sub listcompress {
    @_ == 1 or croak "Usage: SHOULD->listcompress";
    my ($should) = @_;
    $should->_getlist("LISTCOMPRESS");
}

=item config

The server's configuration file, amended to match the current state.
Returns a list, with one line of the file per element.

=cut

sub config {
    @_ == 1 or croak "Usage: SHOULD->config";
    my ($should) = @_;
    $should->_getlist("CONFIG");
}

DESTROY {
    my ($should) = @_;
    $should->close;
}

=back

=head1 SEE ALSO

L<should(1)>

=head1 AUTHOR

Claudio Calvelli <should@shouldbox.co.uk>

=head1 COPYRIGHT

Copyright (c) 2008,2009 Claudio Calvelli <should@shouldbox.co.uk>.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (see the file COPYING in the distribution).
If not, see <http://www.gnu.org/licenses/>.

=cut

1;
