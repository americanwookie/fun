#!/usr/local/bin/perl

use strict;
use JSON::XS;
print JSON::XS->new->pretty(1)->encode( { 'server'  => { 'user'        => 'scott',
                                                         'pass'        => 'pass',
                                                         'imap_server' => 'example.com',
                                                         'main_folder' => 'INBOX' },
                                          'filters' => [ { 'rules'       => [ { 'header' => 'From',
                                                                                'value'  => qq(/Cron Daemon/) } ],
                                                           'action'      => 'move',
                                                           'name'        => 'Cron',
                                                           'destination' => 'INBOX.Cron' },
                                                         { 'rules'       => [ { 'header' => 'From',
                                                                                'value'  => qq(/americanwookie/) },
                                                                              { 'header' => 'Subject',
                                                                                'value'  => 'Test' } ],
                                                           'boolean'     => 'AND',
                                                           'action'      => 'move',
                                                           'name'        => 'Testing',
                                                           'destination' => 'INBOX.Asterisk' } ] } );

