#---------------------------------------------------------------------
package Crypt::Salsa20;
#
# Copyright 2013 Christopher J. Madsen
#
# Author: Christopher J. Madsen <perl@cjmweb.net>
# Created: 14 Jul 2013
#
# This program is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See either the
# GNU General Public License or the Artistic License for more details.
#
# ABSTRACT: Encrypt data with the Salsa20 cipher
#---------------------------------------------------------------------

use 5.008;
use strict;
use warnings;

our $VERSION = '0.01';
# This file is part of {{$dist}} {{$dist_version}} ({{$date}})

#=====================================================================
sub LIMIT () { 2**32 }  # Salsa20 uses 32-bit unsigned integer arithmetic
sub BLOCKSIZE () { 64 } # 64 bytes = 512 bits

sub new
{
  # State variables for our closures:
  my (
    $input0,$input1,$input2,$input3,$input4,$input5,$input6,$input7,$input8,
    $input9,$input10,$input11,$input12,$input13,$input14,$input15,
    $x,$x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,
    $cryptblock,$loops,
  );

  my $self = {
    set_key => sub {
      my $key = shift;
      if (32 == length $key) {
        $input0  = 0x61707865;# SIGMA constants
        $input5  = 0x3320646e;
        $input10 = 0x79622d32;
        $input15 = 0x6b206574;
      } elsif (16 == length $key) {
        $key .= $key;
        $input0  = 0x61707865; # TAU constants
        $input5  = 0x3120646e;
        $input10 = 0x79622d36;
        $input15 = 0x6b206574;
      } else {
        croak("Invalid key length " . length($key) .
              " (must be 16 or 32 bytes)");
      }
      ($input1,$input2,$input3,$input4,$input11,$input12,$input13,$input14)
          = unpack('V8', $key);
      $cryptblock = '';
    }, # end set_key
    set_iv => sub {
      ($input6, $input7) = unpack('V2', shift); # IV
      $input8 = $input9 = 0;                   # block number
      $cryptblock = '';
    }, # end set_iv
    reset_counter => sub {
      $input8 = $input9 = 0;                   # block number
    }, # end reset_counter
    crypt => sub {
      my $text = shift;
      my $pos  = length $cryptblock;

      # If we have stream bytes left over from the previous call, use them:
      if ($pos) {
        if ($pos >= length($text)) {
          $text ^= substr($cryptblock, 0, length($text), '');
          return $text;
        }
        substr($text, 0, length $cryptblock) ^= $cryptblock;
      }

      # Calculate the stopping point.  As long as $pos < $lastPos,
      # another iteration will be required.
      my $lastPos = length($text) - BLOCKSIZE;

      # Generate new cryptblocks and use them:
      for (;;) {
        # BEGIN generated code from tools/algorithm.pl
        $x0 = $input0;
        $x1 = $input1;
        $x2 = $input2;
        $x3 = $input3;
        $x4 = $input4;
        $x5 = $input5;
        $x6 = $input6;
        $x7 = $input7;
        $x8 = $input8;
        $x9 = $input9;
        $x10 = $input10;
        $x11 = $input11;
        $x12 = $input12;
        $x13 = $input13;
        $x14 = $input14;
        $x15 = $input15;
        for (1 .. $loops) {
          $x = ($x0 + $x12) % LIMIT;
          $x4 = $x4 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x4 + $x0) % LIMIT;
          $x8 = $x8 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x8 + $x4) % LIMIT;
          $x12 = $x12 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x12 + $x8) % LIMIT;
          $x0 = $x0 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x5 + $x1) % LIMIT;
          $x9 = $x9 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x9 + $x5) % LIMIT;
          $x13 = $x13 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x13 + $x9) % LIMIT;
          $x1 = $x1 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x1 + $x13) % LIMIT;
          $x5 = $x5 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x10 + $x6) % LIMIT;
          $x14 = $x14 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x14 + $x10) % LIMIT;
          $x2 = $x2 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x2 + $x14) % LIMIT;
          $x6 = $x6 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x6 + $x2) % LIMIT;
          $x10 = $x10 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x15 + $x11) % LIMIT;
          $x3 = $x3 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x3 + $x15) % LIMIT;
          $x7 = $x7 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x7 + $x3) % LIMIT;
          $x11 = $x11 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x11 + $x7) % LIMIT;
          $x15 = $x15 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x0 + $x3) % LIMIT;
          $x1 = $x1 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x1 + $x0) % LIMIT;
          $x2 = $x2 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x2 + $x1) % LIMIT;
          $x3 = $x3 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x3 + $x2) % LIMIT;
          $x0 = $x0 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x5 + $x4) % LIMIT;
          $x6 = $x6 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x6 + $x5) % LIMIT;
          $x7 = $x7 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x7 + $x6) % LIMIT;
          $x4 = $x4 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x4 + $x7) % LIMIT;
          $x5 = $x5 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x10 + $x9) % LIMIT;
          $x11 = $x11 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x11 + $x10) % LIMIT;
          $x8 = $x8 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x8 + $x11) % LIMIT;
          $x9 = $x9 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x9 + $x8) % LIMIT;
          $x10 = $x10 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
          $x = ($x15 + $x14) % LIMIT;
          $x12 = $x12 ^ ((($x << 7) | ($x >> (32 - 7))) & 0xffffffff);
          $x = ($x12 + $x15) % LIMIT;
          $x13 = $x13 ^ ((($x << 9) | ($x >> (32 - 9))) & 0xffffffff);
          $x = ($x13 + $x12) % LIMIT;
          $x14 = $x14 ^ ((($x << 13) | ($x >> (32 - 13))) & 0xffffffff);
          $x = ($x14 + $x13) % LIMIT;
          $x15 = $x15 ^ ((($x << 18) | ($x >> (32 - 18))) & 0xffffffff);
        }
        $cryptblock = pack('V16',
          ($x0 + $input0) % LIMIT,
          ($x1 + $input1) % LIMIT,
          ($x2 + $input2) % LIMIT,
          ($x3 + $input3) % LIMIT,
          ($x4 + $input4) % LIMIT,
          ($x5 + $input5) % LIMIT,
          ($x6 + $input6) % LIMIT,
          ($x7 + $input7) % LIMIT,
          ($x8 + $input8) % LIMIT,
          ($x9 + $input9) % LIMIT,
          ($x10 + $input10) % LIMIT,
          ($x11 + $input11) % LIMIT,
          ($x12 + $input12) % LIMIT,
          ($x13 + $input13) % LIMIT,
          ($x14 + $input14) % LIMIT,
          ($x15 + $input15) % LIMIT,
        );
        # END generated code from tools/algorithm.pl

        # Increment the block counter:
        if (++$input8 == LIMIT) {
          $input8 = 0;
          ++$input9;
        }

        # XOR the text with the new $cryptblock
        if ($pos < $lastPos) {
          substr($text, $pos, BLOCKSIZE) ^= $cryptblock;
          $pos += BLOCKSIZE;
        } else { # this is the last $cryptblock
          substr($text, $pos) ^= substr($cryptblock, 0, length($text)-$pos, '');
          return $text
        }
      } # end forever
    }, # end crypt
  };

  my ($class, %args) = @_;

  bless $self, $class;

  $self->key($args{-key});
  $self->iv($args{-iv}) if defined $args{-iv};

  $loops = ($args{-rounds} || 20) >> 1;

  $self;
} # end new

#---------------------------------------------------------------------
sub key
{
  my $self = shift;

  if (@_) {
    $self->{set_key}->( $self->{key} = shift );
  }

  $self->{key};
} # end key

#---------------------------------------------------------------------
sub iv
{
  my $self = shift;

  if (@_) {
    $self->{set_iv}->( $self->{iv} = shift );
  }

  $self->{iv};
} # end iv

#---------------------------------------------------------------------
sub start { &{ shift->{reset_counter} } }

#---------------------------------------------------------------------
sub crypt { &{ shift->{crypt} } } # pass our @_ along

sub encrypt
{
  my $self = shift;

  &{ $self->{reset_counter} };
  &{ $self->{crypt} };
}

*decrypt = \&encrypt; # In Salsa20, encryption & decryption are the same

#---------------------------------------------------------------------
sub finish { '' }               # for Crypt::CBC compatibility

#---------------------------------------------------------------------
sub stream {
  shift->{crypt};
}

#=====================================================================
# Package Return Value:

1;

__END__

=head1 SYNOPSIS

  use Crypt::Salsa20;
