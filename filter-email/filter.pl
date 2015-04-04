#!/usr/local/bin/perl

use strict;
use Net::IMAP::Simple::SSL ();
use Email::Simple          ();
use Util                   ();
use DateTime               ();

#Settings
my $config = Util::load_config();

#CLI Args
my $days = 1;
if(   $ARGV[0]
   && $ARGV[0] =~ /^(\d+)$/ ) {
  $days += $1;
} elsif( $ARGV[0] ) {
  print "First argument can be either NULL or a number of days back to filter for. In other words, if you want to include yesterdays E-mail in the filtering, provide the number 1\n";
  exit(1);
}

# Create the object
my $imap = Net::IMAP::Simple::SSL->new( $config->{'server'}->{'imap_server'} ) ||
  die "Unable to connect to IMAP: $Net::IMAP::Simple::errstr\n";

if(!$imap->login( $config->{'server'}->{'user'}, $config->{'server'}->{'pass'} )){
  print STDERR "Login failed: " . $imap->errstr . "\n";
  exit(64);
}

my %mailboxes = map { $_ => 1 } $imap->mailboxes();
die($config->{'server'}->{'main_folder'}.' isn\'t a mailbox') if( !exists( $mailboxes{$config->{'server'}->{'main_folder'}} ) );

my $max_messages = $imap->select( $config->{'server'}->{'main_folder'} );

#Only sift through today's messages
my $date = DateTime->now;
$date->subtract( 'days' => $days );
my @ids = $imap->search_since($date->day.'-'.$date->month_abbr.'-'.$date->year);

print "Looking at ".scalar @ids." messages\n";
my $count = 0;
foreach my $i ( @ids ) {
  unless( $count % 100 ) {
    print "On $count\n" if( $count );
  }

  my $es = Email::Simple->new(join '', @{ $imap->top($i) } );
  foreach my $filter ( @{$config->{'filters'}} ) {
    my $do;
    my $boolean = $filter->{'boolean'} || 'AND';
    if( $boolean eq 'AND' ) {
      $do = 1;
    } elsif( $boolean eq 'OR' ) {
      $do = 0;
    } else {
      warn "Unknown boolean logic $i for filter named $filter->{'name'}";
      next;
    }
    if( !@{ $filter->{'rules'} } ) {
      warn "No rules for filter named $filter->{'name'}";
      next;
    }
    if( $filter->{'action'} ne 'move' ) {
      warn "No such action $filter->{'action'} for filter named $filter->{'name'}";
      next;
    }
    if( !exists( $mailboxes{$filter->{'destination'}} ) ) {
      warn "Destination mailbox $filter->{'destination'} doesn't exist for filter named $filter->{'name'}";
      next;
    }

    if(   $es->header('Subject') eq 'Test'
       && $es->header('From') =~ /americanwookie/ ) {
      print "i'm here\n";
    }

    foreach my $rule ( @{ $filter->{'rules'} } )  {
      if(   (   ref($rule->{'value'}) eq 'Regexp'
             && $es->header( $rule->{'header'} ) =~ $rule->{'value'} )
         || (   !ref($rule->{'value'})
             && $es->header( $rule->{'header'} ) eq $rule->{'value'} ) ) {
        if( $boolean eq 'OR' ) {
          $do = 1;
          last;
        }
      } else {
        if( $boolean eq 'AND' ) {
          $do = 0;
          last;
        }
      }
    }

    if( $do ) {
      $filter->{'matching'} ||= [];
      push( @{$filter->{'matching'}}, $i );
      #if( $filter->{'action'} eq 'move' ) {
      #  $imap->copy( $i, $filter->{'destination'} ) && $imap->delete( $i ) && print "Moved and deleted $i well\n";
      #}
      last;
    }
  }
} continue {
  $count++;
}
foreach my $filter ( @{$config->{'filters'}} ) {
  $filter->{'matching'} ||= [];
  while( @{$filter->{'matching'}} ) {
    my @sub = @{$filter->{'matching'}};
    my $per_run = 99;
    if( scalar @{$filter->{'matching'}} > $per_run ) {
      @sub = @{$filter->{'matching'}}[0..$per_run];
      $filter->{'matching'} = [ @{$filter->{'matching'}}[($per_run+1)..$#{$filter->{'matching'}}] ];
    } else {
      @sub = @{$filter->{'matching'}};
      $filter->{'matching'} = [];
    }
    my $list = Util::list2range( @sub );
    if( $imap->copy( $list, $filter->{'destination'} ) ) {
      if( $imap->delete( $list ) ) {
        print "Moved and deleted ".scalar @sub." messages for $filter->{'name'}\n";
      } else {
        die "Error ".$imap->errstr." encountered when deleting for $filter->{'name'}";
      }
    } else {
      die "Error ".$imap->errstr." encountered when copying for $filter->{'name'}\n";
    }
  }
}
$imap->expunge_mailbox( $config->{'server'}->{'main_folder'} );
