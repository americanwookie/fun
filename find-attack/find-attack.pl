#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap::Easy  ();

#Net::Pcap::Easy setup
$Net::Pcap::Easy::MIN_SNAPLEN = 128;
my $npe = Net::Pcap::Easy->new(
    dev              => 'eth0',
    filter           => join( ' ', @_ ),
    packets_per_loop => 1000,
    bytes_to_capture => 128,
    timeout_in_ms    => 0, # 0ms means forever
    promiscuous      => 0, # true or false
    tcp_callback     => \&handle_tcp,
);

#Looping vars
my %attribs;
my $count;

while( $npe->loop ) {
  #
  #Crunch input from NPE
  #
  #TODO set width
  my $width = 80;

  #Find the longest 
  my $longest = 0;
  foreach my $attrib ( keys( %attribs ) ) {
    next if( scalar( keys( %{$attribs{$attrib}} ) ) == 1 );

    foreach my $val ( keys( %{$attribs{$attrib}} ) ) {
      my $length = length( $val );
      $length = length( '(none)' ) if( !$length );
      $longest = $length if( $length > $longest );
    }
  }
  $longest = ( ( $width / 2 ) - 3 ) if( $longest >  ( ( $width / 2 ) - 3 ) );
  my $bar_width = $width - $longest - 3;

  #Do some output
  foreach my $attrib ( keys( %attribs ) ) {
    next if( scalar( keys( %{$attribs{$attrib}} ) ) == 1 );
    print $attrib."\n";
    foreach my $val ( sort { $attribs{$attrib}->{$b} <=> $attribs{$attrib}->{$a} }
                      keys( %{$attribs{$attrib}} ) ) {
      printf( "  %-${longest}s %s\n",
              $val?$val:'(none)',
              make_hash( $attribs{$attrib}->{$val}, $count, $bar_width ),
            );
    }
  }

} continue {
  $count = 0;
  %attribs = ();
}

sub make_hash {
  my $part  = shift;
  my $total = shift;
  my $width = shift;

  #On the right hand side, we'll leave five spaces for percent, e.g.
  #[==- ] 100%
  #And the square brackets take another 2
  my $bar_width = $width - 7;
  my $equal_width = sprintf( '%.5f', 100 / $bar_width );
  my $dash_width = $equal_width / 2;
  #Try to correct for floating rounding silliness further down (gee, it'd
  # be nice if I could avoid icky floats)
  $dash_width += 0.0001;

  my $percent = $part / $total;
  $percent *= 100;
  my $bars = $percent;
  my $str = '';
  #Is there enough for one =?
  if( ( $bars / $equal_width ) > 1 ) {
    #Add whole = for the nuber of whole numbers
    $str .= '=' x int( $bars / $equal_width );
    #Subtract the equivalent number of percentage points from $bars
    $bars -= ( int( $bars / $equal_width ) * $equal_width );
  }

  #Is there enough left for an -?
  if( $bars > $dash_width ) {
    #Throw it on there. We're done calculating.
    $str .= '-';
  }

  return sprintf( "[%-${bar_width}s] %3d%%", $str, $percent );
}

sub handle_tcp {
  my ($npe, $ether, $ip, $tcp, $header ) = @_;

  #Go through IP attributes
  foreach my $attrib ( qw( flags tos ttl proto src_ip dest_ip options ) ) {
    if(   exists( $ip->{$attrib} )
       && exists( $tcp->{$attrib} ) ) {
      $attribs{"ether-$attrib"}->{$ip->{$attrib}}++;
    } else {
      $attribs{$attrib}->{$ip->{$attrib}}++;
    }
  }

  #Go through the TCP attributes
  #Skipping options TODO fix
  foreach my $attrib ( qw( src_port dest_port flags winsize urg ) ) {
    if(   exists( $ip->{$attrib} )
       && exists( $tcp->{$attrib} ) ) {
      $attribs{"tcp-$attrib"}->{$tcp->{$attrib}}++;
    } else {
      $attribs{$attrib}->{$tcp->{$attrib}}++;
    }
  }
  $count++;
}
