#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap::Easy  ();
use Curses::UI;
use lib './lib';

#Logging
open( STDERR, '>', 'find-attack.log' );

#Net::Pcap::Easy setup
$Net::Pcap::Easy::MIN_SNAPLEN = 128;
my $npe = Net::Pcap::Easy->new(
    dev              => 'eth0',
    filter           => join( ' ', @_ ),
    packets_per_loop => 1, #TODO: When this number get big, interactivity goes to crap.
    timeout_in_ms    => 100,
    bytes_to_capture => 128,
    timeout_in_ms    => 0, # 0ms means forever
    promiscuous      => 0, # true or false
    tcp_callback     => \&handle_tcp,
);

#Curses::UI setup
my $cui = new Curses::UI( -color_support => 1 );

#Looping vars
my %attribs;
my @buffer;
my $buffer_len = 10;
my $count;
my $focus = 'topmenu';
my $display = '';
my $oldmenu = '';

#First make your menu bars
my $topmenu = $cui->add( 'topmenu','Menubar',
                         -fg   => 'blue',
                         -menu => [ { -label    => 'find-attack.pl alpha',
                                      -noexpand => 1, #WARNING this option is not upstream
                                    } ]
                       );
my $bottommenu = $cui->add( 'bottommenu', 'Menubar',
                             -menu => [ { -label => 'Presss ctrl+q to exit',
                                          -value => \&exit_dialog } ],
                             -fg   => "blue",
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
    my $return = $cui->dialog(
        -message   => "Do you really want to quit?",
        -title     => "Are you sure???",
        -buttons   => ['yes', 'no'],

    );
    exit(0) if $return;
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
$cui->set_binding( \&update_attribs, 'u' );
$cui->set_binding( \&cycle_focus, "\t");
$cui->set_binding( \&exit_dialog , "\cQ");

#Initial display
$topmenu->focus();
$cui->do_one_event();
$cui->set_timer( 'npe_loop', sub { $npe->loop; } );
$cui->set_timer( 'body_loop', \&update_body );
$cui->mainloop;

sub update_body {
  #Figure out your width
  my $width = $cui->width-5;
  $width-- if( $width % 2 );

  #
  #Prepare the body
  #
  update_attribs() if( !keys( %attribs ) );
  my $body = 'Sample is loaded. Please choose an option from the top menu.';
  if( exists( $attribs{$display} ) ) {
    #Find the longest 
    my $longest = 0;
    foreach my $val ( keys( %{$attribs{$display}} ) ) {
      my $length = length( $val );
      $length = length( '(none)' ) if( !$length );
      $longest = $length if( $length > $longest );
    }
    $longest = ( ( $width / 2 ) - 3 ) if( $longest >  ( ( $width / 2 ) - 3 ) );
    my $bar_width = $width - $longest - 3;

    #Do some output
    $body = $display."\n";
    foreach my $val ( sort { $attribs{$display}->{$b} <=> $attribs{$display}->{$a} }
                      keys( %{$attribs{$display}} ) ) {
      $body .= sprintf( "  %-${longest}s %s\n",
                        $val?$val:'(none)',
                        make_hash( $attribs{$display}->{$val}, $count, $bar_width ),
                      );
    }
  }
  $maintext->text( $body );
 
  #Set the menu options
  if( $oldmenu ne join( '', keys( %attribs ) ) ) {
    $cui->delete('topmenu');
    my @menus;
    foreach my $attrib ( keys %attribs ) {
      #TODO pick up here: Better handle event loop
      push( @menus, { -label    => $attrib,
                      -noexpand => 1, #WARNING this option is not upstream
                      -value    => sub { $display = $attrib } #WARNING this option is not upstream
                    } );
    }
    $topmenu = $cui->add( 'topmenu','Menubar',
                          -fg   => 'blue',
                          -menu => \@menus
                        );
    $oldmenu = join( '', keys( %attribs ) );
    $topmenu->focus();
  }
  $cui->draw();
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

  push( @buffer, { 'ip'  => $ip,
                   'tcp' => $tcp } );
  shift( @buffer ) while( scalar @buffer > $buffer_len );
  $cui->delete('bottommenu');
  my $bottommenu = $cui->add( 'bottommenu', 'Menubar',
                               -menu => [ { -label => 'Presss ctrl+q to exit ('.(scalar @buffer).')',
                                            -value => \&exit_dialog } ],
                               -fg   => "blue",
                               -y    => $cui->height-1, #WARNING: This option is not upstream
                            );
}

sub update_attribs {
  %attribs = ();
  foreach my $p ( @buffer ) {
    #Go through IP attributes
    foreach my $attrib ( qw( flags tos ttl proto src_ip dest_ip options ) ) {
      if(   exists( $p->{'ip'}->{$attrib} )
         && exists( $p->{'tcp'}->{$attrib} ) ) {
        $attribs{"ether-$attrib"}->{$p->{'ip'}->{$attrib}}++;
      } else {
        $attribs{$attrib}->{$p->{'ip'}->{$attrib}}++;
      }
    }

    #Go through the TCP attributes
    #Skipping options TODO fix
    foreach my $attrib ( qw( src_port dest_port flags winsize urg ) ) {
      if(   exists( $p->{'ip'}->{$attrib} )
         && exists( $p->{'tcp'}->{$attrib} ) ) {
        $attribs{"tcp-$attrib"}->{$p->{'tcp'}->{$attrib}}++;
      } else {
        $attribs{$attrib}->{$p->{'tcp'}->{$attrib}}++;
      }
    }
  }

  $count = scalar @buffer;
}
