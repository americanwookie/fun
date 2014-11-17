#!/usr/bin/perl

use strict;
use warnings;
use Carp qw( cluck );
use Time::HiRes ();
use POSIX ':sys_wait_h';
use Curses::UI;
use JSON::XS;
use Fcntl;
use lib './lib';

package Curses::Tabbed;

sub new {
  my $class = shift;
  my %args = @_;
  my $self = bless {}, $class;
  $Curses::Tabbed::self = $self; #This is mighty gross . . .
  $self->{'cui'} = Curses::UI->new( -color_support => 1 );

  foreach my $cb ( qw( callregularly change_maintext ) ) {
    if(   $args{$cb}
       && ref( $args{$cb} ) eq 'CODE' ) {
      $self->{'callbacks'}->{$cb} = $args{$cb};
    }
  }

  #Build base menubars
  $self->{'topmenu'} = $self->{'cui'}->add( 'topmenu', 'Menubar',
                                            -menu => [ { -label    => 'find-attack.pl alpha',
                                                         -noexpand => 1, #WARNING this option is not upstream
                                                       } ]
                                          );
  $self->{'bottommenu'} = $self->{'cui'}->add( 'bottommenu', 'Menubar',
                                               -menu => [ { -label => 'Presss q to exit',
                                                            -value => \&exit_dialog } ],
                                               -y    => $self->{'cui'}->height-1, #WARNING: This option is not upstream
                                             );

  #Main text window
  $self->{'window'} = $self->{'cui'}->add( 'win1', 'Window',
                                           -border => 1,
                                           -y      => 1,
                                           -height => $self->{'cui'}->height-2,
                                           -bfg    => 'red',
                                         );

  #Setup our initial window
  $self->{'textbox'} = $self->{'window'}->add( "textbox", "TextViewer",
                                               -text       => "Loading initial data, please wait . . .",
                                               -vscrollbar => 1,
                                               -height     => $self->{'cui'}->height-2,
                                             );

  #Key Bindings
  $self->{'cui'}->set_binding( \&update_maintext, 'u' );
  $self->{'cui'}->set_binding( \&cycle_focus, "\t");
  $self->{'cui'}->set_binding( \&exit_dialog , "q");

  #Looping Vars
  $self->{'focus'} = 'topmenu';

  #Initial Display
  $self->{'topmenu'}->focus();
  $self->{'cui'}->set_timer( 'callregularly', \&callregularly );

  return $self;
}

#Public methods
sub loop {
  my $self = shift;
  $self->{'cui'}->mainloop;
}

sub body {
  my $self = shift;
  my $new_text = shift;

  if( $new_text ) {
    $self->{'cui'}->{'textbox'}->text( $new_text );
  } else {
    return $self->{'cui'}->{'textbox'}->text();
  }
}

sub top {
  my $self = shift;
  my @options = @_;
  return $self->{'topmenu_string'} if( !@options && exists $self->{'topmenu_string'} );
  return '' if( !@options );

  $self->{'cui'}->delete('topmenu');
  my @menus;
  foreach my $option ( @options ) {
    push( @menus, { -label    => $option,
                    -noexpand => 1, #WARNING this option is not upstream
                  } );
  }
  $self->{'topmenu'} = $self->{'cui'}->add( 'topmenu','Menubar',
                                            -onchange => \&update_maintext, #WARNING this option is not upstream
                                            -menu     => \@menus
                                          );
  $self->{'topmenu'}->focus();
  update_maintext();
  $self->{'topmenu_string'} = join(', ', @options );
}

sub bottom {
  my $self  = shift;
  my @texts = @_;
  my $bottom_text  = '';

  #Figure out how wide each field should be
  my $field_width = int( ( $self->get_width() - ( length(" | ") * ( scalar @texts ) - 1 ) ) / scalar @texts );

  #Prepare text . . .
  foreach my $rate ( @texts ) {
    $bottom_text .= sprintf( "%-${field_width}s | ", $rate );
  }
  $bottom_text =~ s/ \| $//;

  #Rebuild menu
  $self->{'cui'}->delete('bottommenu');
  $self->{'bottommenu'} = $self->{'cui'}->add( 'bottommenu', 'Menubar',
                                               -menu => [ { -label => $bottom_text } ],
                                               -y    => $self->{'cui'}->height-1, #WARNING: This option is not upstream
                                             );
  $self->{'cui'}->draw();
}

sub get_width {
  my $self = shift;
  my $width = $self->{'cui'}->width-5;
  $width-- if( $width % 2 );
  return $width;
}

sub get_selected { #TODO change this to a setter and getter so that the caller can force a pane
  my $self = shift;
  return $self->{'topmenu'}->selected();
}

sub die {
  my $self = shift;
  my $msg  = shift;
  $self->{'cui'}->dialog(
      -message   => $msg,
      -title     => 'Error',
      -buttons   => ['ok'],
  );
  $self->{'cui'}->mainloopExit;
}

#internal subs called by coderefs
sub exit_dialog {
  $Curses::Tabbed::self->{'cui'}->dialog(
      -message   => "Do you really want to quit?",
      -title     => "Are you sure???",
      -buttons   => ['yes', 'no'],
  ) && $Curses::Tabbed::self->{'cui'}->mainloopExit;
}

sub cycle_focus() {
  if( $Curses::Tabbed::self->{'focus'} eq 'topmenu' ) {
    $Curses::Tabbed::self->{'textbox'}->focus();
    $Curses::Tabbed::self->{'focus'} = 'textbox';
  } elsif( $Curses::Tabbed::self->{'focus'} eq 'textbox' ) {
    $Curses::Tabbed::self->{'topmenu'}->focus();
    $Curses::Tabbed::self->{'focus'} = 'topmenu';
  }
}

sub update_maintext {
  my $selected = $Curses::Tabbed::self->{'topmenu'}->selected(); #WARNING: This isn't implemented upstream
  my $text = $Curses::Tabbed::self->{'callbacks'}->{'change_maintext'}->($selected);
  $Curses::Tabbed::self->{'textbox'}->text( $text );
  $Curses::Tabbed::self->{'cui'}->draw();
}

sub callregularly {
  $Curses::Tabbed::self->{'cui'}->disable_timer('callregularly');
  $Curses::Tabbed::self->{'callbacks'}->{'callregularly'}->( $Curses::Tabbed::self );
  $Curses::Tabbed::self->{'cui'}->enable_timer('callregularly');
}

1;
