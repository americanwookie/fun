#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_12 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_CREATE IPSET_NO_ARG IPSET_OPT_GC IPSET_OPT_IP NFNETLINK_V0
     NFPROTO_IPV4 NFPROTO_IPV6 */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case '0':
    if (memEQ(name, "NFNETLINK_V", 11)) {
    /*                          0      */
#ifdef NFNETLINK_V0
      *iv_return = NFNETLINK_V0;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '4':
    if (memEQ(name, "NFPROTO_IPV", 11)) {
    /*                          4      */
      *iv_return = NFPROTO_IPV4;
      return PERL_constant_ISIV;
    }
    break;
  case '6':
    if (memEQ(name, "NFPROTO_IPV", 11)) {
    /*                          6      */
      *iv_return = NFPROTO_IPV6;
      return PERL_constant_ISIV;
    }
    break;
  case 'C':
    if (memEQ(name, "IPSET_OPT_G", 11)) {
    /*                          C      */
      *iv_return = IPSET_OPT_GC;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_CREAT", 11)) {
    /*                          E      */
      *iv_return = IPSET_CREATE;
      return PERL_constant_ISIV;
    }
    break;
  case 'G':
    if (memEQ(name, "IPSET_NO_AR", 11)) {
    /*                          G      */
      *iv_return = IPSET_NO_ARG;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_OPT_I", 11)) {
    /*                          P      */
      *iv_return = IPSET_OPT_IP;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_13 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ASSERT_UNUSED IPSET_ADT_MAX IPSET_ATTR_GC IPSET_ATTR_IP IPSET_CMD_ADD
     IPSET_CMD_DEL IPSET_CMD_MAX IPSET_DIM_MAX IPSET_DIM_ONE IPSET_DIM_TWO
     IPSET_MSG_MAX IPSET_OPT_IP2 IPSET_OPT_MAX IPSET_SETNAME IPSET_WARNING */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'A':
    if (memEQ(name, "IPSET_WARNING", 13)) {
    /*                      ^            */
      *iv_return = IPSET_WARNING;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "IPSET_ADT_MAX", 13)) {
    /*                      ^            */
      *iv_return = IPSET_ADT_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_SETNAME", 13)) {
    /*                      ^            */
      *iv_return = IPSET_SETNAME;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_DIM_MAX", 13)) {
    /*                      ^            */
      *iv_return = IPSET_DIM_MAX;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_DIM_ONE", 13)) {
    /*                      ^            */
      *iv_return = IPSET_DIM_ONE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_DIM_TWO", 13)) {
    /*                      ^            */
      *iv_return = IPSET_DIM_TWO;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_CMD_ADD", 13)) {
    /*                      ^            */
      *iv_return = IPSET_CMD_ADD;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_DEL", 13)) {
    /*                      ^            */
      *iv_return = IPSET_CMD_DEL;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_MAX", 13)) {
    /*                      ^            */
      *iv_return = IPSET_CMD_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_OPT_IP2", 13)) {
    /*                      ^            */
      *iv_return = IPSET_OPT_IP2;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_MAX", 13)) {
    /*                      ^            */
      *iv_return = IPSET_OPT_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_MSG_MAX", 13)) {
    /*                      ^            */
      *iv_return = IPSET_MSG_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_ATTR_GC", 13)) {
    /*                      ^            */
      *iv_return = IPSET_ATTR_GC;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ATTR_IP", 13)) {
    /*                      ^            */
      *iv_return = IPSET_ATTR_IP;
      return PERL_constant_ISIV;
    }
    break;
  case 'U':
    if (memEQ(name, "ASSERT_UNUSED", 13)) {
    /*                      ^            */
#ifdef ASSERT_UNUSEDFFWE
      *iv_return = ASSERT_UNUSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_14 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_ADT IPSET_ATTR_IP2 IPSET_CADT_MAX IPSET_CMD_HELP IPSET_CMD_LIST
     IPSET_CMD_NONE IPSET_CMD_QUIT IPSET_CMD_SAVE IPSET_CMD_SWAP IPSET_CMD_TEST
     IPSET_CMD_TYPE IPSET_DIM_UMAX IPSET_DIM_ZERO IPSET_ERR_BUSY IPSET_ERR_LOOP
     IPSET_ERR_NAME IPSET_LIST_XML IPSET_OPT_CIDR IPSET_OPT_ELEM IPSET_OPT_NAME
     IPSET_OPT_NONE IPSET_OPT_PORT IPSET_OPT_SIZE IPSET_OPT_TYPE IPSET_PROTOCOL
     NFPROTO_BRIDGE NFPROTO_DECNET NFPROTO_UNSPEC */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'A':
    if (memEQ(name, "IPSET_CADT_MAX", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CADT_MAX;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_SWAP", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_SWAP;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_DIM_UMAX", 14)) {
    /*                           ^        */
#ifdef IPSET_DIM_UMAX
      *iv_return = IPSET_DIM_UMAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "IPSET_ATTR_ADT", 14)) {
    /*                           ^        */
      *iv_return = IPSET_ATTR_ADT;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_CIDR", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_CIDR;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_OPT_ELEM", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_ELEM;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "NFPROTO_DECNET", 14)) {
    /*                           ^        */
      *iv_return = NFPROTO_DECNET;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "NFPROTO_UNSPEC", 14)) {
    /*                           ^        */
      *iv_return = NFPROTO_UNSPEC;
      return PERL_constant_ISIV;
    }
    break;
  case 'G':
    if (memEQ(name, "NFPROTO_BRIDGE", 14)) {
    /*                           ^        */
      *iv_return = NFPROTO_BRIDGE;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_CMD_QUIT", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_QUIT;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_CMD_HELP", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_HELP;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_ERR_NAME", 14)) {
    /*                           ^        */
      *iv_return = IPSET_ERR_NAME;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_LIST_XML", 14)) {
    /*                           ^        */
      *iv_return = IPSET_LIST_XML;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_NAME", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_NAME;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_CMD_NONE", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_NONE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_NONE", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_NONE;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "IPSET_ERR_LOOP", 14)) {
    /*                           ^        */
      *iv_return = IPSET_ERR_LOOP;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_PROTOCOL", 14)) {
    /*                           ^        */
#ifdef IPSET_PROTOCOL
      *iv_return = IPSET_PROTOCOL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ATTR_IP2", 14)) {
    /*                           ^        */
      *iv_return = IPSET_ATTR_IP2;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_TYPE", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_TYPE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_TYPE", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_TYPE;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "IPSET_DIM_ZERO", 14)) {
    /*                           ^        */
      *iv_return = IPSET_DIM_ZERO;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_PORT", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_PORT;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_CMD_LIST", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_LIST;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_TEST", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_TEST;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_BUSY", 14)) {
    /*                           ^        */
      *iv_return = IPSET_ERR_BUSY;
      return PERL_constant_ISIV;
    }
    break;
  case 'V':
    if (memEQ(name, "IPSET_CMD_SAVE", 14)) {
    /*                           ^        */
      *iv_return = IPSET_CMD_SAVE;
      return PERL_constant_ISIV;
    }
    break;
  case 'Z':
    if (memEQ(name, "IPSET_OPT_SIZE", 14)) {
    /*                           ^        */
      *iv_return = IPSET_OPT_SIZE;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_15 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ADT_FLAGS IPSET_ATTR_CIDR IPSET_ATTR_DATA IPSET_ATTR_NAME
     IPSET_ATTR_PORT IPSET_ATTR_SIZE IPSET_CMD_FLUSH IPSET_DIM_THREE
     IPSET_ENV_EXIST IPSET_ENV_QUIET IPSET_ERR_EXIST IPSET_FLAGS_ALL
     IPSET_INV_MATCH IPSET_KERNEL_OK IPSET_LIST_NONE IPSET_LIST_SAVE
     IPSET_OPT_CIDR2 IPSET_OPT_ETHER IPSET_OPT_EXIST IPSET_OPT_FLAGS
     IPSET_OPT_IFACE IPSET_OPT_IP_TO IPSET_OPT_PROTO IPSET_OUTBUFLEN */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'A':
    if (memEQ(name, "IPSET_INV_MATCH", 15)) {
    /*                          ^          */
      *iv_return = IPSET_INV_MATCH;
      return PERL_constant_ISIV;
    }
    break;
  case 'C':
    if (memEQ(name, "IPSET_ATTR_CIDR", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ATTR_CIDR;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "IPSET_ATTR_DATA", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ATTR_DATA;
      return PERL_constant_ISIV;
    }
    break;
  case 'F':
    if (memEQ(name, "IPSET_OPT_IFACE", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_IFACE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OUTBUFLEN", 15)) {
    /*                          ^          */
#ifdef IPSET_OUTBUFLEN
      *iv_return = IPSET_OUTBUFLEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "IPSET_DIM_THREE", 15)) {
    /*                          ^          */
      *iv_return = IPSET_DIM_THREE;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_OPT_CIDR2", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_CIDR2;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_ADT_FLAGS", 15)) {
    /*                          ^          */
#ifdef IPSET_ADT_FLAGS
      *iv_return = IPSET_ADT_FLAGS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "IPSET_CMD_FLUSH", 15)) {
    /*                          ^          */
      *iv_return = IPSET_CMD_FLUSH;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_KERNEL_OK", 15)) {
    /*                          ^          */
      *iv_return = IPSET_KERNEL_OK;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_FLAGS", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_FLAGS;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_ATTR_NAME", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ATTR_NAME;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_LIST_NONE", 15)) {
    /*                          ^          */
      *iv_return = IPSET_LIST_NONE;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ATTR_PORT", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ATTR_PORT;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_IP_TO", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_IP_TO;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "IPSET_OPT_PROTO", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_PROTO;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_ATTR_SIZE", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ATTR_SIZE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_LIST_SAVE", 15)) {
    /*                          ^          */
      *iv_return = IPSET_LIST_SAVE;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_OPT_ETHER", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_ETHER;
      return PERL_constant_ISIV;
    }
    break;
  case 'U':
    if (memEQ(name, "IPSET_ENV_QUIET", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ENV_QUIET;
      return PERL_constant_ISIV;
    }
    break;
  case 'X':
    if (memEQ(name, "IPSET_ENV_EXIST", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ENV_EXIST;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_EXIST", 15)) {
    /*                          ^          */
      *iv_return = IPSET_ERR_EXIST;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_EXIST", 15)) {
    /*                          ^          */
      *iv_return = IPSET_OPT_EXIST;
      return PERL_constant_ISIV;
    }
    break;
  case '_':
    if (memEQ(name, "IPSET_FLAGS_ALL", 15)) {
    /*                          ^          */
#ifdef IPSET_FLAGS_ALL
      *iv_return = IPSET_FLAGS_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_CIDR2 IPSET_ATTR_ETHER IPSET_ATTR_FLAGS IPSET_ATTR_IFACE
     IPSET_ATTR_IP_TO IPSET_ATTR_PROTO IPSET_CMD_COMMIT IPSET_CMD_CREATE
     IPSET_CMD_HEADER IPSET_CMD_RENAME IPSET_ENV_SORTED IPSET_ERR_BEFORE
     IPSET_FLAG_EXIST IPSET_INVALID_ID IPSET_LIST_PLAIN IPSET_MAXNAMELEN
     IPSET_OPT_BEFORE IPSET_OPT_FAMILY IPSET_OPT_IP2_TO IPSET_OPT_LINENO
     IPSET_OPT_PROBES IPSET_OPT_RESIZE NFPROTO_NUMPROTO */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case '2':
    if (memEQ(name, "IPSET_OPT_IP2_TO", 16)) {
    /*                           ^          */
      *iv_return = IPSET_OPT_IP2_TO;
      return PERL_constant_ISIV;
    }
    break;
  case 'A':
    if (memEQ(name, "IPSET_CMD_HEADER", 16)) {
    /*                           ^          */
      *iv_return = IPSET_CMD_HEADER;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "IPSET_INVALID_ID", 16)) {
    /*                           ^          */
#ifdef IPSET_INVALID_ID
      *iv_return = IPSET_INVALID_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_CMD_CREATE", 16)) {
    /*                           ^          */
      *iv_return = IPSET_CMD_CREATE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_MAXNAMELEN", 16)) {
    /*                           ^          */
#ifdef IPSET_MAXNAMELEN
      *iv_return = IPSET_MAXNAMELEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "IPSET_ATTR_IFACE", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ATTR_IFACE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_BEFORE", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ERR_BEFORE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_BEFORE", 16)) {
    /*                           ^          */
      *iv_return = IPSET_OPT_BEFORE;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_ATTR_CIDR2", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ATTR_CIDR2;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_ATTR_FLAGS", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ATTR_FLAGS;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_LIST_PLAIN", 16)) {
    /*                           ^          */
      *iv_return = IPSET_LIST_PLAIN;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_CMD_COMMIT", 16)) {
    /*                           ^          */
      *iv_return = IPSET_CMD_COMMIT;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_FAMILY", 16)) {
    /*                           ^          */
      *iv_return = IPSET_OPT_FAMILY;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_CMD_RENAME", 16)) {
    /*                           ^          */
      *iv_return = IPSET_CMD_RENAME;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_LINENO", 16)) {
    /*                           ^          */
      *iv_return = IPSET_OPT_LINENO;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "IPSET_OPT_PROBES", 16)) {
    /*                           ^          */
      *iv_return = IPSET_OPT_PROBES;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ATTR_IP_TO", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ATTR_IP_TO;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "IPSET_ATTR_PROTO", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ATTR_PROTO;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ENV_SORTED", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ENV_SORTED;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "NFPROTO_NUMPROTO", 16)) {
    /*                           ^          */
      *iv_return = NFPROTO_NUMPROTO;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_OPT_RESIZE", 16)) {
    /*                           ^          */
      *iv_return = IPSET_OPT_RESIZE;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_ATTR_ETHER", 16)) {
    /*                           ^          */
      *iv_return = IPSET_ATTR_ETHER;
      return PERL_constant_ISIV;
    }
    break;
  case 'X':
    if (memEQ(name, "IPSET_FLAG_EXIST", 16)) {
    /*                           ^          */
      *iv_return = IPSET_FLAG_EXIST;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_17 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_FAMILY IPSET_ATTR_IP2_TO IPSET_ATTR_LINENO IPSET_ATTR_PROBES
     IPSET_ATTR_RESIZE IPSET_ATTR_UNSPEC IPSET_CMD_DESTROY IPSET_CMD_RESTORE
     IPSET_CMD_VERSION IPSET_DIM_ONE_SRC IPSET_DIM_TWO_SRC IPSET_ENV_RESOLVE
     IPSET_ERRORBUFLEN IPSET_ERR_NAMEREF IPSET_ERR_PRIVATE IPSET_ERR_TIMEOUT
     IPSET_FLAG_BEFORE IPSET_OPT_IP_FROM IPSET_OPT_MAXELEM IPSET_OPT_MEMSIZE
     IPSET_OPT_NAMEREF IPSET_OPT_NETMASK IPSET_OPT_NOMATCH IPSET_OPT_PHYSDEV
     IPSET_OPT_PORT_TO IPSET_OPT_TIMEOUT */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'A':
    if (memEQ(name, "IPSET_ATTR_FAMILY", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ATTR_FAMILY;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_ATTR_RESIZE", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ATTR_RESIZE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_DIM_ONE_SRC", 17)) {
    /*                           ^           */
      *iv_return = IPSET_DIM_ONE_SRC;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_FLAG_BEFORE", 17)) {
    /*                           ^           */
      *iv_return = IPSET_FLAG_BEFORE;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_ATTR_LINENO", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ATTR_LINENO;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_PRIVATE", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ERR_PRIVATE;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_ERR_NAMEREF", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ERR_NAMEREF;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_TIMEOUT", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ERR_TIMEOUT;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_MEMSIZE", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_MEMSIZE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_NAMEREF", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_NAMEREF;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_NOMATCH", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_NOMATCH;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_TIMEOUT", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_TIMEOUT;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_ATTR_UNSPEC", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ATTR_UNSPEC;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "IPSET_DIM_TWO_SRC", 17)) {
    /*                           ^           */
      *iv_return = IPSET_DIM_TWO_SRC;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ATTR_IP2_TO", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ATTR_IP2_TO;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "IPSET_ATTR_PROBES", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ATTR_PROBES;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_VERSION", 17)) {
    /*                           ^           */
      *iv_return = IPSET_CMD_VERSION;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_PORT_TO", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_PORT_TO;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_CMD_DESTROY", 17)) {
    /*                           ^           */
      *iv_return = IPSET_CMD_DESTROY;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_CMD_RESTORE", 17)) {
    /*                           ^           */
      *iv_return = IPSET_CMD_RESTORE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ENV_RESOLVE", 17)) {
    /*                           ^           */
      *iv_return = IPSET_ENV_RESOLVE;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_OPT_NETMASK", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_NETMASK;
      return PERL_constant_ISIV;
    }
    break;
  case 'U':
    if (memEQ(name, "IPSET_ERRORBUFLEN", 17)) {
    /*                           ^           */
#ifdef IPSET_ERRORBUFLEN
      *iv_return = IPSET_ERRORBUFLEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "IPSET_OPT_MAXELEM", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_MAXELEM;
      return PERL_constant_ISIV;
    }
    break;
  case 'Y':
    if (memEQ(name, "IPSET_OPT_PHYSDEV", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_PHYSDEV;
      return PERL_constant_ISIV;
    }
    break;
  case '_':
    if (memEQ(name, "IPSET_OPT_IP_FROM", 17)) {
    /*                           ^           */
      *iv_return = IPSET_OPT_IP_FROM;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_ADT_MAX IPSET_ATTR_CMD_MAX IPSET_ATTR_IP_FROM
     IPSET_ATTR_MAXELEM IPSET_ATTR_MEMSIZE IPSET_ATTR_NAMEREF
     IPSET_ATTR_NETMASK IPSET_ATTR_PORT_TO IPSET_ATTR_SETNAME
     IPSET_ATTR_TIMEOUT IPSET_CMD_PROTOCOL IPSET_CREATE_FLAGS
     IPSET_ERR_MAX_SETS IPSET_ERR_PROTOCOL IPSET_FLAG_CMD_MAX
     IPSET_FLAG_NOMATCH IPSET_FLAG_PHYSDEV IPSET_OPTIONAL_ARG
     IPSET_OPT_ELEMENTS IPSET_OPT_HASHSIZE IPSET_OPT_REVISION
     IPSET_OPT_SETNAME2 IPSET_OPT_TYPENAME */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case '2':
    if (memEQ(name, "IPSET_OPT_SETNAME", 17)) {
    /*                                2      */
      *iv_return = IPSET_OPT_SETNAME2;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_ATTR_MEMSIZ", 17)) {
    /*                                E      */
      *iv_return = IPSET_ATTR_MEMSIZE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ATTR_SETNAM", 17)) {
    /*                                E      */
      *iv_return = IPSET_ATTR_SETNAME;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_HASHSIZ", 17)) {
    /*                                E      */
      *iv_return = IPSET_OPT_HASHSIZE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_TYPENAM", 17)) {
    /*                                E      */
      *iv_return = IPSET_OPT_TYPENAME;
      return PERL_constant_ISIV;
    }
    break;
  case 'F':
    if (memEQ(name, "IPSET_ATTR_NAMERE", 17)) {
    /*                                F      */
      *iv_return = IPSET_ATTR_NAMEREF;
      return PERL_constant_ISIV;
    }
    break;
  case 'G':
    if (memEQ(name, "IPSET_OPTIONAL_AR", 17)) {
    /*                                G      */
      *iv_return = IPSET_OPTIONAL_ARG;
      return PERL_constant_ISIV;
    }
    break;
  case 'H':
    if (memEQ(name, "IPSET_FLAG_NOMATC", 17)) {
    /*                                H      */
      *iv_return = IPSET_FLAG_NOMATCH;
      return PERL_constant_ISIV;
    }
    break;
  case 'K':
    if (memEQ(name, "IPSET_ATTR_NETMAS", 17)) {
    /*                                K      */
      *iv_return = IPSET_ATTR_NETMASK;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_CMD_PROTOCO", 17)) {
    /*                                L      */
      *iv_return = IPSET_CMD_PROTOCOL;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_PROTOCO", 17)) {
    /*                                L      */
      *iv_return = IPSET_ERR_PROTOCOL;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_ATTR_IP_FRO", 17)) {
    /*                                M      */
      *iv_return = IPSET_ATTR_IP_FROM;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ATTR_MAXELE", 17)) {
    /*                                M      */
      *iv_return = IPSET_ATTR_MAXELEM;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_OPT_REVISIO", 17)) {
    /*                                N      */
      *iv_return = IPSET_OPT_REVISION;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "IPSET_ATTR_PORT_T", 17)) {
    /*                                O      */
      *iv_return = IPSET_ATTR_PORT_TO;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_CREATE_FLAG", 17)) {
    /*                                S      */
#ifdef IPSET_CREATE_FLAGS
      *iv_return = IPSET_CREATE_FLAGS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "IPSET_ERR_MAX_SET", 17)) {
    /*                                S      */
      *iv_return = IPSET_ERR_MAX_SETS;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_ELEMENT", 17)) {
    /*                                S      */
      *iv_return = IPSET_OPT_ELEMENTS;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_ATTR_TIMEOU", 17)) {
    /*                                T      */
      *iv_return = IPSET_ATTR_TIMEOUT;
      return PERL_constant_ISIV;
    }
    break;
  case 'V':
    if (memEQ(name, "IPSET_FLAG_PHYSDE", 17)) {
    /*                                V      */
      *iv_return = IPSET_FLAG_PHYSDEV;
      return PERL_constant_ISIV;
    }
    break;
  case 'X':
    if (memEQ(name, "IPSET_ATTR_ADT_MA", 17)) {
    /*                                X      */
#ifdef IPSET_ATTR_ADT_MAX
      *iv_return = IPSET_ATTR_ADT_MAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "IPSET_ATTR_CMD_MA", 17)) {
    /*                                X      */
#ifdef IPSET_ATTR_CMD_MAX
      *iv_return = IPSET_ATTR_CMD_MAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "IPSET_FLAG_CMD_MA", 17)) {
    /*                                X      */
      *iv_return = IPSET_FLAG_CMD_MAX;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_CADT_MAX IPSET_ATTR_ELEMENTS IPSET_ATTR_HASHSIZE
     IPSET_ATTR_PROTOCOL IPSET_ATTR_REVISION IPSET_ATTR_SETNAME2
     IPSET_ATTR_TYPENAME IPSET_DIM_THREE_SRC IPSET_ENV_BIT_EXIST
     IPSET_ENV_BIT_QUIET IPSET_ERR_FIND_TYPE IPSET_ERR_HASH_ELEM
     IPSET_ERR_HASH_FULL IPSET_ERR_LIST_FULL IPSET_ERR_REF_EXIST
     IPSET_FLAG_CADT_MAX IPSET_MANDATORY_ARG IPSET_OPT_PORT_FROM
     NFPROTO_IPSET_IPV46 ipset_print_portnum */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case '4':
    if (memEQ(name, "NFPROTO_IPSET_IPV46", 19)) {
    /*                                ^        */
      *iv_return = NFPROTO_IPSET_IPV46;
      return PERL_constant_ISIV;
    }
    break;
  case 'A':
    if (memEQ(name, "IPSET_ATTR_CADT_MAX", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_CADT_MAX;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_FLAG_CADT_MAX", 19)) {
    /*                                ^        */
      *iv_return = IPSET_FLAG_CADT_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_ATTR_SETNAME2", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_SETNAME2;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ENV_BIT_QUIET", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ENV_BIT_QUIET;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_HASH_ELEM", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ERR_HASH_ELEM;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_ERR_HASH_FULL", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ERR_HASH_FULL;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_LIST_FULL", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ERR_LIST_FULL;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_ATTR_TYPENAME", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_TYPENAME;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "IPSET_ATTR_PROTOCOL", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_PROTOCOL;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ATTR_REVISION", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_REVISION;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_PORT_FROM", 19)) {
    /*                                ^        */
      *iv_return = IPSET_OPT_PORT_FROM;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ERR_FIND_TYPE", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ERR_FIND_TYPE;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "IPSET_DIM_THREE_SRC", 19)) {
    /*                                ^        */
      *iv_return = IPSET_DIM_THREE_SRC;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_MANDATORY_ARG", 19)) {
    /*                                ^        */
      *iv_return = IPSET_MANDATORY_ARG;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "IPSET_ENV_BIT_EXIST", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ENV_BIT_EXIST;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_REF_EXIST", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ERR_REF_EXIST;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_ATTR_ELEMENTS", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_ELEMENTS;
      return PERL_constant_ISIV;
    }
    break;
  case 'Z':
    if (memEQ(name, "IPSET_ATTR_HASHSIZE", 19)) {
    /*                                ^        */
      *iv_return = IPSET_ATTR_HASHSIZE;
      return PERL_constant_ISIV;
    }
    break;
  case 'u':
    if (memEQ(name, "ipset_print_portnum", 19)) {
    /*                                ^        */
#ifdef ipset_print_portnumfewjoi
      *iv_return = ipset_print_portnum;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_20 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_PORT_FROM IPSET_ENV_BIT_SORTED IPSET_ERR_HASH_RANGE
     IPSET_ERR_REFERENCED IPSET_FLAG_BIT_EXIST IPSET_MANDATORY_ARG2
     IPSET_OPT_CADT_FLAGS IPSET_OPT_REFERENCES __IPSET_ATTR_ADT_MAX
     __IPSET_ATTR_CMD_MAX */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'A':
    if (memEQ(name, "IPSET_ERR_HASH_RANGE", 20)) {
    /*                          ^               */
      *iv_return = IPSET_ERR_HASH_RANGE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_CADT_FLAGS", 20)) {
    /*                          ^               */
      *iv_return = IPSET_OPT_CADT_FLAGS;
      return PERL_constant_ISIV;
    }
    break;
  case 'B':
    if (memEQ(name, "IPSET_FLAG_BIT_EXIST", 20)) {
    /*                          ^               */
      *iv_return = IPSET_FLAG_BIT_EXIST;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_ERR_REFERENCED", 20)) {
    /*                          ^               */
      *iv_return = IPSET_ERR_REFERENCED;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_OPT_REFERENCES", 20)) {
    /*                          ^               */
      *iv_return = IPSET_OPT_REFERENCES;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_ENV_BIT_SORTED", 20)) {
    /*                          ^               */
      *iv_return = IPSET_ENV_BIT_SORTED;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ATTR_PORT_FROM", 20)) {
    /*                          ^               */
      *iv_return = IPSET_ATTR_PORT_FROM;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "__IPSET_ATTR_ADT_MAX", 20)) {
    /*                          ^               */
      *iv_return = __IPSET_ATTR_ADT_MAX;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "__IPSET_ATTR_CMD_MAX", 20)) {
    /*                          ^               */
      *iv_return = __IPSET_ATTR_CMD_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_MANDATORY_ARG2", 20)) {
    /*                          ^               */
      *iv_return = IPSET_MANDATORY_ARG2;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_CADT_FLAGS IPSET_ATTR_CREATE_MAX IPSET_ATTR_IPADDR_MAX
     IPSET_ATTR_REFERENCES IPSET_ENV_BIT_RESOLVE IPSET_ENV_LIST_HEADER
     IPSET_ERR_IPADDR_IPV4 IPSET_ERR_IPADDR_IPV6 IPSET_FLAG_BIT_BEFORE
     IPSET_KERNEL_MISMATCH */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'A':
    if (memEQ(name, "IPSET_ATTR_CADT_FLAGS", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_ATTR_CADT_FLAGS;
      return PERL_constant_ISIV;
    }
    break;
  case 'C':
    if (memEQ(name, "IPSET_ATTR_REFERENCES", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_ATTR_REFERENCES;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "IPSET_ENV_LIST_HEADER", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_ENV_LIST_HEADER;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_ENV_BIT_RESOLVE", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_ENV_BIT_RESOLVE;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_ATTR_CREATE_MAX", 21)) {
    /*                                 ^         */
#ifdef IPSET_ATTR_CREATE_MAX
      *iv_return = IPSET_ATTR_CREATE_MAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "IPSET_ATTR_IPADDR_MAX", 21)) {
    /*                                 ^         */
#ifdef IPSET_ATTR_IPADDR_MAX
      *iv_return = IPSET_ATTR_IPADDR_MAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "IPSET_FLAG_BIT_BEFORE", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_FLAG_BIT_BEFORE;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ERR_IPADDR_IPV4", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_ERR_IPADDR_IPV4;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_IPADDR_IPV6", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_ERR_IPADDR_IPV6;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_KERNEL_MISMATCH", 21)) {
    /*                                 ^         */
      *iv_return = IPSET_KERNEL_MISMATCH;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_CADT_LINENO IPSET_ATTR_IPADDR_IPV4 IPSET_ATTR_IPADDR_IPV6
     IPSET_ENV_LIST_SETNAME IPSET_ERR_BITMAP_RANGE IPSET_ERR_INVALID_CIDR
     IPSET_FLAG_BIT_NOMATCH IPSET_FLAG_BIT_PHYSDEV IPSET_FLAG_LIST_HEADER
     IPSET_OPT_REVISION_MIN */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'A':
    if (memEQ(name, "IPSET_ENV_LIST_SETNAME", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_ENV_LIST_SETNAME;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "IPSET_FLAG_BIT_PHYSDEV", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_FLAG_BIT_PHYSDEV;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_FLAG_LIST_HEADER", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_FLAG_LIST_HEADER;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "IPSET_ATTR_CADT_LINENO", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_ATTR_CADT_LINENO;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "IPSET_ERR_INVALID_CIDR", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_ERR_INVALID_CIDR;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_OPT_REVISION_MIN", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_OPT_REVISION_MIN;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_ERR_BITMAP_RANGE", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_ERR_BITMAP_RANGE;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ATTR_IPADDR_IPV4", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_ATTR_IPADDR_IPV4;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ATTR_IPADDR_IPV6", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_ATTR_IPADDR_IPV6;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_FLAG_BIT_NOMATCH", 22)) {
    /*                                  ^         */
      *iv_return = IPSET_FLAG_BIT_NOMATCH;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ATTR_PROTOCOL_MIN IPSET_ATTR_REVISION_MIN IPSET_ERR_INVALID_PROTO
     IPSET_ERR_MISSING_PROTO IPSET_ERR_TYPE_MISMATCH IPSET_ERR_TYPE_SPECIFIC
     IPSET_FLAG_LIST_SETNAME __IPSET_ATTR_CREATE_MAX __IPSET_ATTR_IPADDR_MAX */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'C':
    if (memEQ(name, "IPSET_ERR_TYPE_SPECIFIC", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_ERR_TYPE_SPECIFIC;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "__IPSET_ATTR_CREATE_MAX", 23)) {
    /*                                 ^           */
      *iv_return = __IPSET_ATTR_CREATE_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_ATTR_PROTOCOL_MIN", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_ATTR_PROTOCOL_MIN;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "IPSET_ERR_TYPE_MISMATCH", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_ERR_TYPE_MISMATCH;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_ATTR_REVISION_MIN", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_ATTR_REVISION_MIN;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "IPSET_ERR_INVALID_PROTO", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_ERR_INVALID_PROTO;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "IPSET_ERR_MISSING_PROTO", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_ERR_MISSING_PROTO;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "__IPSET_ATTR_IPADDR_MAX", 23)) {
    /*                                 ^           */
      *iv_return = __IPSET_ATTR_IPADDR_MAX;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "IPSET_FLAG_LIST_SETNAME", 23)) {
    /*                                 ^           */
      *iv_return = IPSET_FLAG_LIST_SETNAME;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     IPSET_ENV_BIT_LIST_HEADER IPSET_ERR_INVALID_NETMASK
     IPSET_KERNEL_CHECK_NEEDED */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'I':
    if (memEQ(name, "IPSET_ENV_BIT_LIST_HEADER", 25)) {
    /*                          ^                    */
      *iv_return = IPSET_ENV_BIT_LIST_HEADER;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "IPSET_KERNEL_CHECK_NEEDED", 25)) {
    /*                          ^                    */
      *iv_return = IPSET_KERNEL_CHECK_NEEDED;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "IPSET_ERR_INVALID_NETMASK", 25)) {
    /*                          ^                    */
      *iv_return = IPSET_ERR_INVALID_NETMASK;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(ASSERT_UNUSED IPSET_ADT_FLAGS IPSET_ATTR_ADT_MAX
	       IPSET_ATTR_CMD_MAX IPSET_ATTR_CREATE_MAX IPSET_ATTR_IPADDR_MAX
	       IPSET_CREATE_FLAGS IPSET_DIM_UMAX IPSET_ERRORBUFLEN
	       IPSET_FLAGS_ALL IPSET_INVALID_ID IPSET_MAXNAMELEN
	       IPSET_OUTBUFLEN IPSET_PROTOCOL NFNETLINK_V0 UNUSED
	       ipset_print_portnum),
            {name=>"IPSET_ADD", type=>"IV", macro=>"1"},
            {name=>"IPSET_ADT_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_ADT", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_CADT_FLAGS", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_CADT_LINENO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_CADT_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_CIDR", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_CIDR2", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_DATA", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_ELEMENTS", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_ETHER", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_FAMILY", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_FLAGS", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_GC", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_HASHSIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IFACE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IP", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IP2", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IP2_TO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IPADDR_IPV4", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IPADDR_IPV6", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IP_FROM", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_IP_TO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_LINENO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_MAXELEM", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_MEMSIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_NAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_NAMEREF", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_NETMASK", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PORT", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PORT_FROM", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PORT_TO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PROBES", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PROTO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PROTOCOL", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_PROTOCOL_MIN", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_REFERENCES", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_RESIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_REVISION", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_REVISION_MIN", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_SETNAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_SETNAME2", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_SIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_TIMEOUT", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_TYPENAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_ATTR_UNSPEC", type=>"IV", macro=>"1"},
            {name=>"IPSET_CADT_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_ADD", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_COMMIT", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_CREATE", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_DEL", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_DESTROY", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_FLUSH", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_HEADER", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_HELP", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_LIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_NONE", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_PROTOCOL", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_QUIT", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_RENAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_RESTORE", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_SAVE", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_SWAP", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_TEST", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_TYPE", type=>"IV", macro=>"1"},
            {name=>"IPSET_CMD_VERSION", type=>"IV", macro=>"1"},
            {name=>"IPSET_CREATE", type=>"IV", macro=>"1"},
            {name=>"IPSET_DEL", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_ONE", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_ONE_SRC", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_THREE", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_THREE_SRC", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_TWO", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_TWO_SRC", type=>"IV", macro=>"1"},
            {name=>"IPSET_DIM_ZERO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_BIT_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_BIT_LIST_HEADER", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_BIT_LIST_SETNAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_BIT_QUIET", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_BIT_RESOLVE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_BIT_SORTED", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_LIST_HEADER", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_LIST_SETNAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_QUIET", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_RESOLVE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ENV_SORTED", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERROR", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_BEFORE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_BITMAP_RANGE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_BITMAP_RANGE_SIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_BUSY", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_EXIST_SETNAME2", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_FIND_TYPE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_HASH_ELEM", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_HASH_FULL", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_HASH_RANGE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_HASH_RANGE_UNSUPPORTED", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_INVALID_CIDR", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_INVALID_FAMILY", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_INVALID_NETMASK", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_INVALID_PROTO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_IPADDR_IPV4", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_IPADDR_IPV6", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_LIST_FULL", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_LOOP", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_MAX_SETS", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_MISSING_PROTO", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_NAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_NAMEREF", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_PRIVATE", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_PROTOCOL", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_REFERENCED", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_REF_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_TIMEOUT", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_TYPE_MISMATCH", type=>"IV", macro=>"1"},
            {name=>"IPSET_ERR_TYPE_SPECIFIC", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BEFORE", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BIT_BEFORE", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BIT_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BIT_LIST_HEADER", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BIT_LIST_SETNAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BIT_NOMATCH", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_BIT_PHYSDEV", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_CADT_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_CMD_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_LIST_HEADER", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_LIST_SETNAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_NOMATCH", type=>"IV", macro=>"1"},
            {name=>"IPSET_FLAG_PHYSDEV", type=>"IV", macro=>"1"},
            {name=>"IPSET_INV_MATCH", type=>"IV", macro=>"1"},
            {name=>"IPSET_KERNEL_CHECK_NEEDED", type=>"IV", macro=>"1"},
            {name=>"IPSET_KERNEL_MISMATCH", type=>"IV", macro=>"1"},
            {name=>"IPSET_KERNEL_OK", type=>"IV", macro=>"1"},
            {name=>"IPSET_LIST_NONE", type=>"IV", macro=>"1"},
            {name=>"IPSET_LIST_PLAIN", type=>"IV", macro=>"1"},
            {name=>"IPSET_LIST_SAVE", type=>"IV", macro=>"1"},
            {name=>"IPSET_LIST_XML", type=>"IV", macro=>"1"},
            {name=>"IPSET_MANDATORY_ARG", type=>"IV", macro=>"1"},
            {name=>"IPSET_MANDATORY_ARG2", type=>"IV", macro=>"1"},
            {name=>"IPSET_MSG_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_NO_ARG", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPTIONAL_ARG", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_BEFORE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_CADT_FLAGS", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_CIDR", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_CIDR2", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_ELEM", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_ELEMENTS", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_ETHER", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_EXIST", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_FAMILY", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_FLAGS", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_GC", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_HASHSIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_IFACE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_IP", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_IP2", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_IP2_TO", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_IP_FROM", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_IP_TO", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_LINENO", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_MAX", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_MAXELEM", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_MEMSIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_NAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_NAMEREF", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_NETMASK", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_NOMATCH", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_NONE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_PHYSDEV", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_PORT", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_PORT_FROM", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_PORT_TO", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_PROBES", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_PROTO", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_REFERENCES", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_RESIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_REVISION", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_REVISION_MIN", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_SETNAME2", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_SIZE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_TIMEOUT", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_TYPE", type=>"IV", macro=>"1"},
            {name=>"IPSET_OPT_TYPENAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_SETNAME", type=>"IV", macro=>"1"},
            {name=>"IPSET_TEST", type=>"IV", macro=>"1"},
            {name=>"IPSET_WARNING", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_ARP", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_BRIDGE", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_DECNET", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_IPSET_IPV46", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_IPV4", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_IPV6", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_NUMPROTO", type=>"IV", macro=>"1"},
            {name=>"NFPROTO_UNSPEC", type=>"IV", macro=>"1"},
            {name=>"__IPSET_ATTR_ADT_MAX", type=>"IV", macro=>"1"},
            {name=>"__IPSET_ATTR_CMD_MAX", type=>"IV", macro=>"1"},
            {name=>"__IPSET_ATTR_CREATE_MAX", type=>"IV", macro=>"1"},
            {name=>"__IPSET_ATTR_IPADDR_MAX", type=>"IV", macro=>"1"});

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Mytest4", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Mytest4", $types);
__END__
   */

  switch (len) {
  case 6:
    if (memEQ(name, "UNUSED", 6)) {
#ifdef UNUSEDfewf
      *iv_return = UNUSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 9:
    /* Names all of length 9.  */
    /* IPSET_ADD IPSET_DEL */
    /* Offset 7 gives the best switch position.  */
    switch (name[7]) {
    case 'D':
      if (memEQ(name, "IPSET_ADD", 9)) {
      /*                      ^       */
        *iv_return = IPSET_ADD;
        return PERL_constant_ISIV;
      }
      break;
    case 'E':
      if (memEQ(name, "IPSET_DEL", 9)) {
      /*                      ^       */
        *iv_return = IPSET_DEL;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 10:
    if (memEQ(name, "IPSET_TEST", 10)) {
      *iv_return = IPSET_TEST;
      return PERL_constant_ISIV;
    }
    break;
  case 11:
    /* Names all of length 11.  */
    /* IPSET_ERROR NFPROTO_ARP */
    /* Offset 10 gives the best switch position.  */
    switch (name[10]) {
    case 'P':
      if (memEQ(name, "NFPROTO_AR", 10)) {
      /*                         P      */
        *iv_return = NFPROTO_ARP;
        return PERL_constant_ISIV;
      }
      break;
    case 'R':
      if (memEQ(name, "IPSET_ERRO", 10)) {
      /*                         R      */
        *iv_return = IPSET_ERROR;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 12:
    return constant_12 (aTHX_ name, iv_return);
    break;
  case 13:
    return constant_13 (aTHX_ name, iv_return);
    break;
  case 14:
    return constant_14 (aTHX_ name, iv_return);
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 16:
    return constant_16 (aTHX_ name, iv_return);
    break;
  case 17:
    return constant_17 (aTHX_ name, iv_return);
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    return constant_20 (aTHX_ name, iv_return);
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    /* Names all of length 24.  */
    /* IPSET_ERR_EXIST_SETNAME2 IPSET_ERR_INVALID_FAMILY */
    /* Offset 10 gives the best switch position.  */
    switch (name[10]) {
    case 'E':
      if (memEQ(name, "IPSET_ERR_EXIST_SETNAME2", 24)) {
      /*                         ^                    */
        *iv_return = IPSET_ERR_EXIST_SETNAME2;
        return PERL_constant_ISIV;
      }
      break;
    case 'I':
      if (memEQ(name, "IPSET_ERR_INVALID_FAMILY", 24)) {
      /*                         ^                    */
        *iv_return = IPSET_ERR_INVALID_FAMILY;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    /* Names all of length 26.  */
    /* IPSET_ENV_BIT_LIST_SETNAME IPSET_FLAG_BIT_LIST_HEADER */
    /* Offset 6 gives the best switch position.  */
    switch (name[6]) {
    case 'E':
      if (memEQ(name, "IPSET_ENV_BIT_LIST_SETNAME", 26)) {
      /*                     ^                          */
        *iv_return = IPSET_ENV_BIT_LIST_SETNAME;
        return PERL_constant_ISIV;
      }
      break;
    case 'F':
      if (memEQ(name, "IPSET_FLAG_BIT_LIST_HEADER", 26)) {
      /*                     ^                          */
        *iv_return = IPSET_FLAG_BIT_LIST_HEADER;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 27:
    /* Names all of length 27.  */
    /* IPSET_ERR_BITMAP_RANGE_SIZE IPSET_FLAG_BIT_LIST_SETNAME */
    /* Offset 6 gives the best switch position.  */
    switch (name[6]) {
    case 'E':
      if (memEQ(name, "IPSET_ERR_BITMAP_RANGE_SIZE", 27)) {
      /*                     ^                           */
        *iv_return = IPSET_ERR_BITMAP_RANGE_SIZE;
        return PERL_constant_ISIV;
      }
      break;
    case 'F':
      if (memEQ(name, "IPSET_FLAG_BIT_LIST_SETNAME", 27)) {
      /*                     ^                           */
        *iv_return = IPSET_FLAG_BIT_LIST_SETNAME;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 32:
    if (memEQ(name, "IPSET_ERR_HASH_RANGE_UNSUPPORTED", 32)) {
      *iv_return = IPSET_ERR_HASH_RANGE_UNSUPPORTED;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

