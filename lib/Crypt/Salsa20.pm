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

=method new

  $salsa20 = Crypt::Salsa20->new(-key => $key, ...);

This constructs a new Crypt::Salsa20 object, with attributes supplied
as S<C<< key => value >>> pairs.  The only required attribute at
construction time is the key (but you must supply an IV before
encrypting or decrypting).

=cut

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
    cipher_rounds => sub {
      $loops = shift >> 1 if @_;
      $loops << 1;
    }, # end cipher_rounds
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
          $x4 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x4 + $x0) % LIMIT;
          $x8 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x8 + $x4) % LIMIT;
          $x12 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x12 + $x8) % LIMIT;
          $x0 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x5 + $x1) % LIMIT;
          $x9 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x9 + $x5) % LIMIT;
          $x13 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x13 + $x9) % LIMIT;
          $x1 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x1 + $x13) % LIMIT;
          $x5 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x10 + $x6) % LIMIT;
          $x14 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x14 + $x10) % LIMIT;
          $x2 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x2 + $x14) % LIMIT;
          $x6 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x6 + $x2) % LIMIT;
          $x10 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x15 + $x11) % LIMIT;
          $x3 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x3 + $x15) % LIMIT;
          $x7 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x7 + $x3) % LIMIT;
          $x11 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x11 + $x7) % LIMIT;
          $x15 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x0 + $x3) % LIMIT;
          $x1 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x1 + $x0) % LIMIT;
          $x2 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x2 + $x1) % LIMIT;
          $x3 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x3 + $x2) % LIMIT;
          $x0 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x5 + $x4) % LIMIT;
          $x6 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x6 + $x5) % LIMIT;
          $x7 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x7 + $x6) % LIMIT;
          $x4 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x4 + $x7) % LIMIT;
          $x5 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x10 + $x9) % LIMIT;
          $x11 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x11 + $x10) % LIMIT;
          $x8 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x8 + $x11) % LIMIT;
          $x9 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x9 + $x8) % LIMIT;
          $x10 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
          $x = ($x15 + $x14) % LIMIT;
          $x12 ^= (($x << 7) | ($x >> (32 - 7))) & 0xffffffff;
          $x = ($x12 + $x15) % LIMIT;
          $x13 ^= (($x << 9) | ($x >> (32 - 9))) & 0xffffffff;
          $x = ($x13 + $x12) % LIMIT;
          $x14 ^= (($x << 13) | ($x >> (32 - 13))) & 0xffffffff;
          $x = ($x14 + $x13) % LIMIT;
          $x15 ^= (($x << 18) | ($x >> (32 - 18))) & 0xffffffff;
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

=head1 ATTRIBUTES

Each attribute has a method of the same name.  Calling the method with
no parameter returns the current value of the attribute.  Calling it
with a parameter sets the attribute to that value (and returns the new
value).


=attr key

The encryption key is a 16 or 32 byte string (128 or 256 bits), with
32 bytes being the recommended size.  It's always interpreted as raw
bytes; if you want to use a pasword hashing function, you have to
supply your own.  Setting the key does not change the IV or reset the
block counter.

=cut

sub key
{
  my $self = shift;

  if (@_) {
    $self->{set_key}->( $self->{key} = shift );
  }

  $self->{key};
} # end key
#---------------------------------------------------------------------

=attr iv

The nonce (IV) is an 8 byte string (64 bits).  The nonce does not need
to be kept secret, but you must never encrypt two different messages
with the same key and nonce, or you have catastrophically weakened the
security of the cipher.  You must supply an IV before encrypting or
decrypting, but you can omit it from the constructor and call the
C<iv> method instead.  Setting the IV does not change the key, but it
does reset the block counter.

=cut

sub iv
{
  my $self = shift;

  if (@_) {
    $self->{set_iv}->( $self->{iv} = shift );
  }

  $self->{iv};
} # end iv

=attr rounds

The number of cipher rounds to use.  The default is 20, which is the
standard Salsa20 cipher.  The standard variants are 8 or 12 rounds
(Salsa20/8 or Salsa20/12), but any even integer will work.

=cut

sub rounds { &{ shift->{cipher_rounds} } }

#---------------------------------------------------------------------

=method start

  $salsa20->start;

Resets the internal block counter, starting the keystream over at the
beginning.  You should also change the IV, because using the same key
and IV is a security breach.

For compatibility with the Crypt::CBC method of the same name, you can
pass a parameter (e.g. C<'decrypting'> or C<'encrypting'>), but it is
ignored.  With Salsa20, encryption and decryption are the same operation,
so there's no need to indicate which one you want.

This method is primarily for Crypt::CBC compatibility.  Since with
Salsa20 you don't need to specify whether you're encrypting or
decrypting, and the C<iv> method also does everything C<start> does,
you don't really need to call this method.

=cut

sub start { &{ shift->{reset_counter} } }

#---------------------------------------------------------------------

=method crypt

  $ciphertext = $salsa20->crypt($plaintext);
  $plaintext  = $salsa20->crypt($ciphertext);

Encrypts or decrypts the provided string.

Because encryption & decryption are the same operation, it is not
necessary to call C<start> before calling C<crypt>, but you do need to
have set the IV, either by passing it to the constructor or calling
the C<iv> method.

=cut

sub crypt { &{ shift->{crypt} } } # pass our @_ along

=method encrypt

  $ciphertext = $salsa20->encrypt($plaintext);

Equivalent to calling C<start> and then C<crypt>.

=method decrypt

  $plaintext = $salsa20->decrypt($ciphertext);

Equivalent to calling C<start> and then C<crypt> (the same as C<encrypt>).

=cut

sub encrypt
{
  my $self = shift;

  &{ $self->{reset_counter} };
  &{ $self->{crypt} };
}

*decrypt = \&encrypt; # In Salsa20, encryption & decryption are the same

#---------------------------------------------------------------------

=method finish

  $remaining_ciphertext = $salsa20->finish;

This method exists solely for Crypt::CBC compatibility.  It always
returns the empty string.

=cut

sub finish { '' }               # for Crypt::CBC compatibility

#---------------------------------------------------------------------

=method cryptor

  $cryptor = $salsa20->cryptor;
  $ciphertext = $cryptor->($plaintext);
  $plaintext  = $cryptor->($ciphertext);

This method is the most efficient way to use Crypt::Salsa20 if you are
encrypting multiple chunks.  It returns a coderef that encrypts or
decrypts the text you pass it.  C<< $cryptor->($text) >> is equivalent
to C<< $salsa20->crypt($text) >>, just faster.

The cryptor remains tied to the original object.  Changing the key or
IV affects it.  But it is not necessary to save a reference to the
original object if you don't plan to call any other methods.

=cut

sub cryptor { shift->{crypt} }

#=====================================================================
# Package Return Value:

1;

__END__

=head1 SYNOPSIS

  use Crypt::Salsa20;

  my $salsa20 = Crypt::Salsa20->new(-key => $key, -iv => $nonce);
  my $cryptor = $salsa20->cryptor;
  my $ciphertext = $cryptor->($plaintext);

  # Or use Crypt::CBC-like API:
  my $ciphertext = $salsa20->encrypt('plaintext');
  my $plaintext  = $salsa20->decrypt($plaintext);


=head1 DESCRIPTION

Crypt::Salsa20 implements D. J. Bernstein's Salsa20 stream cipher
(a.k.a. Snuffle 2005) in Perl.  For more information on Salsa20,
see his page at L<http://cr.yp.to/snuffle.html>.

Salsa20 takes a 256 bit (or 128 bit) key and a 64 bit nonce (a.k.a. an
IV or message number) and uses them to generate a stream of up to
2**70 bytes of pseudo-random data.  That stream is XORed with your
message.  Because of that, encryption and decryption are the same
operation.

It is critical that you never use the same nonce and key to encrypt
two different messages.  Because the keystream is completely
determined by the key and nonce, reusing them means that you can
cancel out the keystream by XORing the two ciphertexts together:

  ciphertext1          ^ ciphertext2
  keystream ^ message1 ^ keystream ^ message2
  message1  ^ message2 ^ keystream ^ keystream
  message1  ^ message2 ^           0
  message1  ^ message2


=head2 Crypt::Salsa20 vs. Crypt::CBC

The API is similar to that of the L<Crypt::CBC> module, but there are
some differences:

=over

=item 1.

There is no C<-literal_key> option.  The key is I<always> interpreted
as raw bytes (and must be either 16 or 32 bytes long).  If you want to
use a pasword hashing function, you have to supply your own.

=item 2.

Crypt::Salsa20 doesn't use any sort of header, trailer, padding, or
any other metadata.  If you need to transmit the nonce as part of your
message, you'll need to do it manually.

=item 3.

Since encryption and decryption are the same operation with Salsa20,
the C<start> method does not require a parameter, and it is not
necessary to call it at all.

=item 4.

The C<finish> method is available, but unnecessary.  In Crypt::Salsa20
it does nothing and always returns the empty string.

=back

=for Pod::Coverage
BLOCKSIZE
LIMIT

=for Pod::Loom-sort_attr
key

=for Pod::Loom-sort_method
new
start
crypt
finish
encrypt
decrypt
cryptor
