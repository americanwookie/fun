#!/usr/local/bin/perl

use strict;
use Net::IMAP::Simple::SSL ();
use Email::Simple          ();
use Util;

#Settings
my $config = Util::load_config();

# Create the object
my $imap = Net::IMAP::Simple::SSL->new( $config->{'server'}->{'imap_server'} ) ||
  die "Unable to connect to IMAP: $Net::IMAP::Simple::errstr\n";

if(!$imap->login( $config->{'server'}->{'user'}, $config->{'server'}->{'pass'} )){
  print STDERR "Login failed: " . $imap->errstr . "\n";
  exit(64);
}

my %mailboxes = map { $_ => 1 } $imap->mailboxes();
my $mailbox;
if( $ARGV[0] ) {
  die( $ARGV[0].' isn\'t a mailbox. Run without an argument for a list of mailboxes' ) if( !exists( $mailboxes{$ARGV[0]} ) );
  $mailbox = $ARGV[0];
} else {
  print "The first argument to this command must be a mailbox name. Here is a list of mailboxes:\n";
  print join("\n", sort keys( %mailboxes ) )."\n";
  exit(1);
}

$imap->select( $mailbox );
my @ids = $imap->search("UNSEEN");
if($imap->see( Util::list2range( @ids ) ) ) {
  print "Marked ".scalar @ids." messages as read\n";
} else {
  print "Problems encountered when trying to mark ".scalar @ids." as read\n";
}
