#! /usr/bin/perl
#---------------------------------------------------------------------

use Test::More tests => 1;

BEGIN {
    use_ok('Crypt::Salsa20');
}

diag("Testing Crypt::Salsa20 $Crypt::Salsa20::VERSION");
