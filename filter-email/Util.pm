#!/usr/local/bin/perl

use strict;
use JSON::XS ();
package Util;

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
      if( $rule->{'value'} =~ /^\/([.A-Za-z0-9@\\ !_-]+)\/$/ ) {
        $rule->{'value'} = qr($1);
      } elsif (   $rule->{'value'} =~ /^\//
               && $rule->{'value'} =~ /\/$/ ) {
        warn "Rule $rule->{'value'} looks like a regex but contains invalid characters";
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

1;
