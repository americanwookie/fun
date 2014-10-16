#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap::Easy  ();

$Net::Pcap::Easy::MIN_SNAPLEN = 128;

my $debug = 0;

my $npe = Net::Pcap::Easy->new(
    dev              => 'eth0',
    filter           => 'port 22',
    packets_per_loop => 10,
    bytes_to_capture => 128,
    timeout_in_ms    => 0, # 0ms means forever
    promiscuous      => 0, # true or false
    tcp_callback     => \&handle_tcp,
);

my %attribs;
my $count;
my %both = map { $_ => 1 } qw( options flags );

while( $npe->loop ) {
  #Do some output
  print "Looks like I've got a count of $count\n";
  #Reset
  $count = 0;
  %attribs = ();
}

sub handle_tcp {
  my ($npe, $ether, $ip, $tcp, $header ) = @_;

  #Go through IP attributes
  foreach my $attrib ( qw( flags tos ttl proto src_ip dest_ip options ) ) {
    if( exists( $both{$attrib} ) ) {
      $attribs{"ether-$attrib"}->{$ip->{$attrib}}++;
    } else {
      $attribs{$attrib}->{$ip->{$attrib}}++;
    }
  }

  #Go through the TCP attributes
  foreach my $attrib ( qw( src_port dest_port flags winsize urg options ) ) {
    if( exists( $both{$attrib} ) ) {
      $attribs{"tcp-$attrib"}->{$ip->{$attrib}}++;
    } else {
      $attribs{$attrib}->{$tcp->{$attrib}}++;
    }
  }
  $count++;
}
