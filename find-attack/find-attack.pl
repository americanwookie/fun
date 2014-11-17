#!/usr/bin/perl

use strict;
use warnings;
use lib './lib';
use Carp qw( cluck );
use Time::HiRes ();
use POSIX ':sys_wait_h';
use JSON::XS;
use Fcntl;
use Curses::Tabbed;

#Settings
my $tail_tool = './tail-tcpdump.pl';
my @tail_args = '';
my $buffer_len = 100;

#Logging
open( STDERR, '>', 'find-attack.log' );

#Setup child
pipe( my $read, my $write );
my $child;
unless( $child = fork() ) {
  #Clean up your fds
  close( $read );
  close( STDOUT );
  open(STDOUT, '>&', $write);
  close( $write );

  exec( $tail_tool, @tail_args );
}
close($write);
my $flags = '';
fcntl( $read, F_GETFL, $flags ) or die "Can't get flags: $!";
#print "Flags are $flags\n";
$flags = O_NONBLOCK; #TODO get help, this should be a |=
fcntl( $read, F_SETFL, $flags ) or die "Can't set O_NOBLOCK: $!";

my $window = Curses::Tabbed->new( 'callregularly'   => \&callregularly,
                         'change_maintext' => \&change_maintext );

#Looping vars
my @buffer;
my $overread_buffer = '';
my $debug = 1;

$window->loop;
kill($child);
exit(0);

#Callbacks
sub callregularly {
  debug("callregularly called");

  #Read new data
  load_data();
}

sub change_maintext {
  my $requested = shift;
  debug( "Updating screen to ".$requested );
  my ( $data, $count ) = get_stats( $requested );
  my $width = $window->get_width;

  #Find the longest 
  my $longest = 0;
  foreach my $val ( keys( %{$data} ) ) {
    my $length = length( $val );
    $length = length( '(none)' ) if( !$val );
    $longest = $length if( $length > $longest );
  }
  $longest = ( ( $width / 2 ) - 3 ) if( $longest >  ( ( $width / 2 ) - 3 ) );
  my $bar_width = $width - $longest - 3;

  #Do some output
  my $body = '';
  foreach my $val ( sort { $data->{$b} <=> $data->{$a} }
                    keys( %{$data} ) ) {
    $body .= sprintf( "  %-${longest}s %s\n",
                      $val?$val:'(none)',
                      make_hash( $data->{$val}, $count, $bar_width ),
                    );
  }
  return "$requested\n$body";
}

#Non-classifiable subs
sub load_data { #Consider making this sub only do reading from child. Maybe arithmetic should only happen when a new pane is loaded?
  debug("Loading new data from child");
  my @rates = ();

  #Let's see if our child has given us anything . . .
  my $new = 0;
  my $started = [ Time::HiRes::gettimeofday ];
  if(   eof( $read )
     || waitpid( $child, WNOHANG ) > 0 ) {
    debug("EOF reached, bailing");
    $window->die( 'Our information gathering pipe closed. Exiting.' );
  }
  while( sysread( $read, my $buf, 4096 ) ) {
    my @lines = split(/\n/, $buf);
    $lines[0] = $overread_buffer . $lines[0];
    $overread_buffer = '';
    if( $buf !~ /\n$/g ) {
      $overread_buffer = pop( @lines );
    }

    #Decode it and shove it on buffer
    foreach my $line ( @lines ) {
      my $data;
      eval {
        $data = JSON::XS::decode_json( $line );
      };
      if(   $data
         && ref($data) eq 'HASH' ) {
        my @keys = keys( %{$data} );
        if(   scalar @keys == 1
           && $keys[0] =~ /^_/ ) {
          if( $keys[0] eq '_rates' ) {
            @rates = ();
            foreach my $rate ( keys( %{$data->{$keys[0]}} ) ) {
              push( @rates, "$rate: $data->{$keys[0]}->{$rate}" );
            }
          } else {
            debug("Unknown control packet $keys[0] received");
          }
        } else {
          $new++;
          push( @buffer, $data );
        }
      } else {
        debug("Warning: JSON decoding error");
      }
    }

    #Trim the buffer
    shift( @buffer ) while( scalar @buffer > $buffer_len );
    if ( Time::HiRes::tv_interval( $started ) > 0.2 ) {
      debug("I've been in this loop too long. Bailing");
      last;
    }
  }
  debug( "Added $new packets to buffer" );

  #Update the UI
  if(  !$window->top
     && @buffer ) {
    $window->top( keys( %{$buffer[0]} ) );
  }
  if( @rates ) {
    $window->bottom( 'Press q to exit', 
                     sort( @rates ) );
  }
}

sub get_stats {
  my $wanted = shift;

  my %stats = ();
  foreach my $p ( @buffer ) {
    if( exists( $p->{$wanted} ) ) {
      $stats{$p->{$wanted}}++;
    }
  }
  return ( \%stats, scalar @buffer );
}

sub debug {
  my $msg = shift;
  my ( undef, $microseconds) = Time::HiRes::gettimeofday;
  if( $debug ) {
    warn localtime()." $microseconds ".$msg;
    #cluck( localtime()." ".$msg );
  }
}

#Help with drawing subs (should be purely functional)
sub make_hash {
  my $part       = shift;
  my $total      = shift;
  my $hash_width = shift;

  #On the right hand side, we'll leave five spaces for percent, e.g.
  #[==- ] 100%
  #And the square brackets take another 2
  my $bar_width = $hash_width - 7;
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
