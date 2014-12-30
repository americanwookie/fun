#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <libipset/linux_ip_set.h>
#include <libipset/data.h>
#include <libipset/errcode.h>
#include <libipset/linux_ip_set_bitmap.h>
#include <libipset/linux_ip_set_hash.h>
#include <libipset/linux_ip_set_list.h>
#include <libipset/mnl.h>
#include <libipset/nf_inet_addr.h>
#include <libipset/nfproto.h>
#include <libipset/parse.h>
#include <libipset/pfxlen.h>
#include <libipset/print.h>
#include <libipset/session.h>
#include <libipset/transport.h>
#include <libipset/types.h>
#include <libipset/ui.h>
#include <libipset/utils.h>

#include "const-c.inc"

MODULE = Mytest4		PACKAGE = Mytest4		

INCLUDE: const-xs.inc

void
test()
  CODE:
    printf("Hi");
    ipset_load_types();
    printf("Bye");
