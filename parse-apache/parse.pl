#!/usr/bin/perl

#NOTES: This looks like it's simply re-implementing File::Tail::Multi with some buffering.
#       Me thinks this should be reimplemented using File::Tail::Multi, with a goal of being
#       subclass and then invokable from that.
use strict;
use Fcntl qw(SEEK_END);

my $nginx_log = '/www/nginx1/logs/access-tc.log';
my $debug = 0;

my $inode = (stat( $nginx_log ))[1];
open( my $log, '<', $nginx_log ) or die("Can't open access-tc: $!");
seek( $log, (-100*100000), SEEK_END ); #22s is about 800,000 Bytes Roughly 20s * 100, so that's 2000s or a little bit more than 1/2 hour
my $foo = <$log>;  #Throw away the incomplete line that we could be getting

#Exit after 50 rounds, and while loop the program, there's some sort of long running bug (TODO look for this)
for( my $i=0; $i<50; $i++ ) {
  my $cnt;
  my $unq;
  print "Starting sample\n" if( $debug );
  my @sampling;
  my %byip;
  #Really need to put a timer here for low traffic times
  while( 1 ) {
    $_ = <$log>;
    if( !$_ ) {
      print "Not enough data, we have ".scalar @sampling." lines\n" if( $debug );
      sleep(1);
      next;
    }
    chomp;

    if( /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d+) ([\d.]+) ([\d.]+) (\d+) (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" (\d+)/ ) {
      my %tmp =  ( 'ip'      => $1,
                   'rc'      => $2,
                   'time'    => $3,
                   'ukn1'    => $4,
                   'ukn2'    => $5,
                   'ukn3'    => $6,
                   'ukn4'    => $7,
                   'request' => $8,
                   'ref'     => $9,
                   'ua'      => $10,
                   'ukn6'    => $11,
                   'ukn7'    => $12 );
      push( @sampling, \%tmp );
      $byip{$tmp{'ip'}} = [] if( !exists($byip{$tmp{'ip'}}));
      push( @{$byip{$tmp{'ip'}}}, \%tmp );
      last if( @sampling > 5000 );
    } else {
      print "Unrecognized line: $_\n";
    }

    #Make sure the file hasn't been replaced
    my $current_inode;
    while( !$current_inode ) {
      $current_inode = (stat( $nginx_log ))[1];
      if( !$current_inode ) {
        print "Tried to stat $nginx_log but failed. Sleeping for 1s\n";
        sleep(1);
      }
    }
    if( $current_inode != $inode ) {
      print "Reopening $nginx_log, looks like it got rotated out\n";
      close( $log );
      open( $log, '<', $nginx_log ) or die("Can't open access-tc: $!");
      $inode = $current_inode;
    }
  }
  $unq = scalar( keys( %byip ) );
  print "Done\n" if( $debug );

  my $now = time();

  #Do something
}


sub load_list {
  my $file = shift;
  my %ret;

  open( my $in, '<', $file ) or die ("Can't open log file $file: $!");
  foreach(<$in>) {
    chomp;
    my @info = split(/\s+/, $_, 4);
    $info[1] ||= '';
    $info[2] ||= 0;
    $info[3] ||= 0;
    $ret{$info[0]} = { 'lasturl' => $info[3],
                       'count'   => 0,
                       'lastreq' => $info[2] };
  }
  close($in);

  return \%ret;
}

sub save_list {
  my $hash = shift;
  my $file = shift;

  open( my $out, '>', "$file.tmp.$$" ) or die( "Can't open log file $file for write: $!");
  foreach( keys( %{$hash} ) ) {
    if( ref( $hash->{$_} ) ne 'HASH' ) {
      $hash->{$_} = { 'lasturl' => '',
                      'count'   => 0,
                      'lastreq' => 0 };
    }
    print {$out} "$_ $hash->{$_}->{'count'} $hash->{$_}->{'lastreq'} $hash->{$_}->{'lasturl'}\n";
  }
  close($out);
  rename("$file.tmp.$$", $file);
}
