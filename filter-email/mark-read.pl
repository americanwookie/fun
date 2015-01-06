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
if( !@ARGV ) {
  print "This command accepts a list of mailboxes as its argument. Here is a list of mailboxes:\n";
  print join("\n", sort keys( %mailboxes ) )."\n";
  exit(1);
}

foreach my $mailbox ( @ARGV ) {
  if( !exists( $mailboxes{$mailbox} ) ) {
    warn $mailbox.' isn\'t a mailbox. Run without an argument for a list of mailboxes';
    next;
  }

  $imap->select( $mailbox );
  my @ids = $imap->search("UNSEEN");
  if( @ids ) {
    if($imap->see( Util::list2range( @ids ) ) ) {
      print "Marked ".scalar @ids." messages as read in $mailbox\n";
    } else {
      print "Problems encountered when trying to mark ".scalar @ids." messages as read in $mailbox\n";
    }
  } else {
    print "No unread messages found in $mailbox\n";
  }
}
