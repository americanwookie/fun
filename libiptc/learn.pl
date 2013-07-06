#!/usr/local/bin/perl

use strict;
#Need to put my sysadmin hat on and fix the make install
use Data::Dumper;
use lib '/usr/local/lib64/perl5/site_perl/5.8.8/x86_64-linux-thread-multi';
$ENV{'IPTABLES_LIB_DIR'} = '/lib64/iptables';
use IPTables::libiptc;

#Intro: So, this is mostly a copy and paste job/learning experience based on
#       the docs found at:
# http://search.cpan.org/~hawk/IPTables-libiptc-0.52/lib/IPTables/libiptc.pm
#       the idea here is to try each feature individually to get a feel for
#       the module and then integrate it into pre-existing work.

#First, pull in the default filter
my $table = IPTables::libiptc::init('filter') or die("No init");

#Get information about the default policy
foreach my $chain ( qw( INPUT FORWARD OUTPUT ) ) {
  my ( $policy, $pkt_cnt, $byte_cnt ) = $table->get_policy( $chain );
  print "Chain $chain:\n";
  print "-------------\n";
  print "Default Policy: $policy\n";
  print "Number of packets that have flowed through this chain: $pkt_cnt\n";
  print "Number of bytes that have flowed through this chain: $byte_cnt\n\n";
}

#Set a default policy
my @old_policy = $table->get_policy('FORWARD');
print "Setting FORWARD chain to a default policy of DROP (from $old_policy[0])\n";
my $ret = $table->set_policy('FORWARD', 'DROP');
$table->commit();
$table = IPTables::libiptc::init('filter');
print "Check it out yourself and press ENTER to continue\n";
<STDIN>;
$table->set_policy('FORWARD', $old_policy[0]);
$table->commit();
$table = IPTables::libiptc::init('filter');

#Create a chain
print "Creating chain test\n";
$ret = $table->create_chain('test');
$table->commit();
$table = IPTables::libiptc::init('filter');
print "Check it out yourself and press ENTER to continue\n";
<STDIN>;

#Checking
my $refs = $table->get_references('test');
print "Chain test has $refs references\n\n";

#Removing
print "Removing that test chain\n";
$ret = $table->delete_chain('test');
$table->commit();
$table = IPTables::libiptc::init('filter');
print "Check it out yourself and press ENTER to continue\n";
<STDIN>;

print "List of chains:\n";
print "---------------\n";
foreach my $chain ( $table->list_chains() ) {
  print "$chain\n";
}
print "\n";

print "List of rule IPs for INPUT:\n";
print "-----------------\n";
foreach my $rule ( $table->list_rules_IPs('src', 'INPUT') ) {
  print "$rule\n";
}
print "\n";

print "Adding a rule -s 2.3.4.5 -p tcp --dport 22 -j DROP to INPUT";
my $ret = $table->iptables_do_command( [ qw( -I INPUT
                                             -s 3.4.5.6
                                             -m tcp
                                             -p tcp
                                             --dport 22
                                             -j DROP ) ] );
print "\n$ret and $!\n";

print "Let's try . . .\n";
print Dumper( $table->iptables_do_command([ '-vnL', 'INPUT']) );
#well the above was kinda useless, it just prints to stdout.

#I've create list_rules and this tests it
print Dumper( $table->list_rules( 'INPUT' ) );

$table->commit();
