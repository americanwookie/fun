#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap::Easy  ();
use Sys::Statistics::Linux::NetStats ();
use Digest::MD5 ();
use Time::HiRes ();
use JSON::XS;

#Settings
my $dev = 'eth0';

#Ensure we're not buffered
open(STDIN, '<', '/dev/null');
open(STDERR, '>', '/dev/null');
select STDOUT;
$| = 1;

#Timers for rate calculation
my $start;
my $lxs = Sys::Statistics::Linux::NetStats->new();
$lxs->init;

#Initialize pcap
$Net::Pcap::Easy::MIN_SNAPLEN = 128;
my $npe = Net::Pcap::Easy->new(
    dev              => $dev,
    filter           => join( ' ', @ARGV ),
    packets_per_loop => 1,
    bytes_to_capture => 128,
    promiscuous      => 0, # true or false
    tcp_callback     => sub {
      my ( $npe, $ether, $ip, $tcp, $header ) = @_;
      $start = [ Time::HiRes::gettimeofday ] if( !$start );
      if( Time::HiRes::tv_interval( $start ) >= 1 ) {
        my $stats = $lxs->get;
        print JSON::XS::encode_json( { '_rates' => { map( +( $_ => useful_units( $stats->{$dev}->{$_}, 'pps' ) ), qw( txpcks rxpcks ) ),
                                                     map( +( $_ => useful_units( $stats->{$dev}->{$_}, 'bps' ) ), qw( txbyt rxbyt ) ) } } )."\n";
        $start = [ Time::HiRes::gettimeofday ];
      }
      print JSON::XS::encode_json( { map( +( $_ => $ip->{$_}  ), qw( dest_ip proto src_ip tos ttl ) ),
                                     map( +( $_ => $tcp->{$_} ), qw( src_port dest_port winsize urg ) ),
                                     'i_flags'   => sprintf( '%03b', $ip->{'flags'} ),
                                     't_flags'   => sprintf( '%09b', $tcp->{'flags'} ),
                                     'i_options' => Digest::MD5::md5_hex( $ip->{'options'} ),
                                     't_options' => Digest::MD5::md5_hex( $tcp->{'options'} ) } )."\n";
    }
);

#Setup iterator
while(1) {
  $npe->loop;
}

sub useful_units {
  my $val = shift;
  my $type = shift;

  my %base = ( 'bps' => 1024,
               'pps' => 1000 );

  my @prefix = ( '',
                 'k',
                 'm',
                 'g',
                 't' );

  return "$val $type" if( !exists( $base{$type} ) );

  my $multiple = 0;
  while( $val > 1 ) {
    $val /= $base{$type};
    $multiple++;
  }
  $val *= $base{$type};
  $multiple--;

  return sprintf('%.02f %s%s', $val, $prefix[$multiple], $type);
}
