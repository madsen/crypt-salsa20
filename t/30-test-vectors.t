#! /usr/bin/perl
#---------------------------------------------------------------------
# 30-test-vectors.t
#
# Copyright 2013 Christopher J. Madsen
#
# This program is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See either the
# GNU General Public License or the Artistic License for more details.
#
# Run test vectors for the full Salsa20 20-round implementation
#---------------------------------------------------------------------

use strict;
use warnings;
use 5.008;

use Test::More 0.88;            # done_testing

use t::Vectors;

plan tests => 960;

test_vectors(20);

done_testing;
