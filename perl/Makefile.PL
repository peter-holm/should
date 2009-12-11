#!/usr/bin/perl

eval 'exec perl -S $0 ${1+"$@"}'
    if 0;

# Create Makefile for Should::Client

# This file is part of SHOULD

# Copyright (c) 2009 Claudio Calvelli <should@shouldbox.co.uk>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING in the distribution).
# If not, see <http://www.gnu.org/licenses/>.

use vars qw($VERSION);

( $VERSION ) = '$Revision: 1.0 $ ' =~ /\$Revision:\s+([^\s]+)/;

use ExtUtils::MakeMaker;

WriteMakefile(NAME => 'Should',
	      PMLIBDIRS => [qw(Should)],
	      VERSION => $VERSION);

