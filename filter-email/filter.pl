#!/usr/local/bin/perl

use strict;
use Net::IMAP::Simple::SSL ();
use Email::Simple          ();
use JSON::XS               ();
use Data::Dumper;

#Settings
my $config = load_config();

# Create the object
my $imap = Net::IMAP::Simple::SSL->new( $config->{'server'}->{'imap_server'} ) ||
  die "Unable to connect to IMAP: $Net::IMAP::Simple::errstr\n";

if(!$imap->login( $config->{'server'}->{'user'}, $config->{'server'}->{'pass'} )){
  print STDERR "Login failed: " . $imap->errstr . "\n";
  exit(64);
}

my %mailboxes = map { $_ => 1 } $imap->mailboxes();
die($config->{'server'}->{'main_folder'}.' isn\'t a mailbox') if( !exists( $mailboxes{$config->{'server'}->{'main_folder'}} ) );

my $nm = $imap->select( $config->{'server'}->{'main_folder'} );
print "Looking at $nm messages\n";
for(my $i = 1; $i <= $nm; $i++){
  print "On $i\n" unless( $i % 1000);

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
}
foreach my $filter ( @{$config->{'filters'}} ) {
  $filter->{'matching'} ||= [];
  while( @{$filter->{'matching'}} ) {
    my @sub = @{$filter->{'matching'}};
#TODO: Make messages per run configuratble
#    if( scalar @{$filter->{'matching'}} > 1000 ) {
#      @sub = @{$filter->{'matching'}}[0..999];
#      $filter->{'matching'} = [ @{$filter->{'matching'}}[1000..$#{$filter->{'matching'}}] ];
#    } else {
      $filter->{'matching'} = [];
#    }
    my $list = list2range( @sub );
    my $es = Email::Simple->new(join '', @{ $imap->top($list) } );
    print Dumper $es;
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

sub load_config {
  my $file = shift || 'config.json';
  open( my $config_fd, '<', 'config.json' ) or die( "Can't load config: $!" );
  my $config_txt;
  {
    local $/ = undef;
    $config_txt = <$config_fd>;
  }
  close($config_fd);
  my $config;
  eval {
    $config = JSON::XS::decode_json( $config_txt );
  };
  if( $@ ) {
    die( "Syntax problem detected with config file: $@" );
  }
  if( !$config || ref($config) ne 'HASH' ) {
    print "Config file is not a hash";
  }
  foreach my $filter ( @{ $config->{'filters'} } ) {
    foreach my $rule ( @{ $filter->{'rules'} } ) {
      if( $rule->{'value'} =~ /^\/([A-Za-z0-9 ]+)\/$/ ) {
        $rule->{'value'} = qr( $1 );
      }
    }
  }
  if(   !exists( $config->{'server'}->{'user'} )
     || !exists( $config->{'server'}->{'pass'} )
     || !exists( $config->{'server'}->{'imap_server'} ) ) {
    die( "Config doesn't either user, pass, or imap_server" );
  }
  return $config;
}

#Shamelessly copied from a newer version of Net::IMAP::Simple
sub list2range {
#    my $self_or_class = shift;
    my %h;
    my @a = sort { $a<=>$b } grep {!$h{$_}++} grep {m/^\d+/} grep {defined $_} @_;
    my @b;

    while(@a) {
        my $e = 0;

        $e++ while $e+1 < @a and $a[$e]+1 == $a[$e+1];

        push @b, ($e>0 ? [$a[0], $a[$e]] : [$a[0]]);
        splice @a, 0, $e+1;
    }

    return join(",", map {join(":", @$_)} @b);
}
