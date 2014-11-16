#!/usr/bin/perl

use strict;
use warnings;
use Carp qw( cluck );
use Net::Pcap::Easy  ();
use Sys::Statistics::Linux::NetStats ();
use Digest::MD5 ();
use Time::HiRes ();
use POSIX ':sys_wait_h';
use Curses::UI;
use JSON::XS;
use Fcntl;
use lib './lib';

#Logging
open( STDERR, '>', 'find-attack.log' );

#Setup libpcap child
pipe( my $read, my $write );
my $child;
unless( $child = fork() ) {
  #Clean up your fds
  close( $read );
  close( STDIN );
  close( STDOUT );
  close( STDERR );
  select $write;
  $| = 1;

  #Timers for rate calculation
  my $start;
  my $lxs = Sys::Statistics::Linux::NetStats->new();
  $lxs->init;

  #Initialize pcap
  $Net::Pcap::Easy::MIN_SNAPLEN = 128;
  my $npe = Net::Pcap::Easy->new(
      dev              => 'eth0',
      filter           => join( ' ', @ARGV ),
      packets_per_loop => 1,
      bytes_to_capture => 128,
      timeout_in_ms    => 0, # 0ms means forever
      promiscuous      => 0, # true or false
      tcp_callback     => sub {
        my ( $npe, $ether, $ip, $tcp, $header ) = @_;
        $start = [ Time::HiRes::gettimeofday ] if( !$start );
        if( Time::HiRes::tv_interval( $start ) >= 1 ) {
          my $stats = $lxs->get;
          print {$write} JSON::XS::encode_json( { '_rates' => $stats } )."\n";
           $start = [ Time::HiRes::gettimeofday ];
        }
        print {$write} JSON::XS::encode_json( { map( +( $_ => $ip->{$_}  ), qw( dest_ip proto src_ip tos ttl ) ),
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
  exit;
}
close($write);
my $flags = '';
fcntl( $read, F_GETFL, $flags ) or die "Can't get flags: $!";
#print "Flags are $flags\n";
$flags = O_NONBLOCK; #TODO get help, this should be a |=
fcntl( $read, F_SETFL, $flags ) or die "Can't set O_NOBLOCK: $!";

#Curses::UI setup
my $cui = new Curses::UI( -color_support => 1 );

#Looping vars
my %attribs;
my @buffer;
my $buffer_len = 100;
my $overread_buffer = '';
my $count;
my $focus = 'topmenu';
my $oldmenu = '';
my $debug = 1;

#First make your menu bars
my $topmenu = $cui->add( 'topmenu','Menubar',
                         -menu => [ { -label    => 'find-attack.pl alpha',
                                      -noexpand => 1, #WARNING this option is not upstream
                                    } ]
                       );
my $bottommenu = $cui->add( 'bottommenu', 'Menubar',
                             -menu => [ { -label => 'Presss q to exit',
                                          -value => \&exit_dialog } ],
                             -y    => $cui->height-1, #WARNING: This option is not upstream
                          );

#Setup our initial window
my $win1 = $cui->add( 'win1', 'Window',
                      -border => 1,
                      -y      => 1,
                      -height => $cui->height-2,
                      -bfg    => 'red',
                    );
my $maintext = $win1->add( "initial", "TextViewer",
                           -text   => "Loading initial data, please wait . . .",
                           -vscrollbar => 1,
                           -height => $cui->height-2,
                         );

#Hotkeys
sub exit_dialog()
{
    $cui->dialog(
        -message   => "Do you really want to quit?",
        -title     => "Are you sure???",
        -buttons   => ['yes', 'no'],
    ) && &exit_cleanly();
}
sub cycle_focus() {
  if( $focus eq 'topmenu' ) {
    $maintext->focus();
    $focus = 'maintext';
  } elsif( $focus eq 'maintext' ) {
    $topmenu->focus();
    $focus = 'topmenu';
  }
}
$cui->set_binding(sub {$topmenu->focus()}, "\cX");
$cui->set_binding( \&update_maintext, 'u' );
$cui->set_binding( \&cycle_focus, "\t");
$cui->set_binding( \&exit_dialog , "q");

#Initial display
$topmenu->focus();
$cui->set_timer( 'body_loop', \&update_body );
$cui->mainloop;

sub update_body {
  $cui->disable_timer('body_loop');
  debug("update_body called");
  #
  #Prepare the body
  #
  update_attribs();
  if(   $maintext->text() =~ /^Loading initial data/
     && keys( %attribs ) ) {
    debug( "Telling the user sample is loaded" );
    $maintext->text( 'Sample is loaded. Please choose an option from the top menu.' );
  }
 
  #Set the menu options
  if( $oldmenu ne join( '', keys( %attribs ) ) ) {
    $cui->delete('topmenu');
    my @menus;
    foreach my $attrib ( keys %attribs ) {
      push( @menus, { -label    => $attrib,
                      -noexpand => 1, #WARNING this option is not upstream
                    } );
    }
    debug( "Adding new topmenu" );
    $topmenu = $cui->add( 'topmenu','Menubar',
                          -onchange => sub { update_maintext(); }, #WARNING this option is not upstream".
                          -menu     => \@menus
                        );
    $oldmenu = join( '', keys( %attribs ) );
    $topmenu->focus();
    debug( "Calling for draw" );
    $cui->draw();
  }
  $cui->enable_timer('body_loop');
}

sub make_hash {
  my $part  = shift;
  my $total = shift;
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

sub update_attribs {
  debug("Rebuilding attribs from buffer");
  %attribs = ();

  #Let's see if our child has given us anything . . .
  my $new = 0;
  my $started = [ Time::HiRes::gettimeofday ];
  if(   eof( $read )
     || waitpid( $child, WNOHANG ) > 0 ) {
    debug("EOF reached, bailing");
    $cui->dialog(
        -message   => 'Our information gathering pipe closed. Exiting.',
        -title     => 'Error',
        -buttons   => ['ok'],
    );
    &exit_cleanly();
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
        $new++;
        push( @buffer, $data );
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
  $cui->delete('bottommenu');
  my $bottommenu = $cui->add( 'bottommenu', 'Menubar',
                               -menu => [ { -label => 'Presss q to exit ('.(scalar @buffer).')',
                                            -value => \&exit_dialog } ],
                               -y    => $cui->height-1, #WARNING: This option is not upstream
                            );

  #Generate statistics
  foreach my $p ( @buffer ) {
    foreach my $attrib ( keys( %{$p} ) ) {
      if( $attrib =~ /^_/ ) {
        debug("Got a rate packet: ".JSON::XS::encode_json( $p->{$attrib} ) );
        next;
      }
      $attribs{$attrib}->{$p->{$attrib}}++;
    }
  }

  $count = scalar @buffer;
}

sub build_body {
  my $data = shift;
  my $width = get_width();

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
  return $body;
}

sub update_maintext {
  my $selected = $topmenu->selected();
  debug( "Updating screen to ".$selected );
  update_attribs();
  $maintext->text( "$selected\n".build_body( $attribs{$selected} ) );
  $cui->draw();
}

sub get_width {
  my $width = $cui->width-5;
  $width-- if( $width % 2 );
  return $width;
}

sub debug {
  my $msg = shift;
  my ( undef, $microseconds) = Time::HiRes::gettimeofday;
  if( $debug ) {
    warn localtime()." $microseconds ".$msg;
    #cluck( localtime()." ".$msg );
  }
}

sub exit_cleanly {
  kill($child);
  exit(0);
}
