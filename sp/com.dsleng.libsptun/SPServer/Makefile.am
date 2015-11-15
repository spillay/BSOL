prefix = @prefix@
SBIN_DIR = ${prefix}/sbin
BIN_DIR  = ${prefix}/bin
MAN_DIR  = ${prefix}/share/man
ETC_DIR  = ${prefix}/etc
VAR_DIR  = ${prefix}/var

PID_FILE = ${VAR_DIR}/run/vtund.pid
CFG_FILE = ${ETC_DIR}/vtund.conf
STAT_DIR = ${VAR_DIR}/log/vtund
LOCK_DIR = ${VAR_DIR}/lock/vtund
DEFS = -DVTUN_CONFIG_FILE=\"$(CFG_FILE)\" -DVTUN_PID_FILE=\"$(PID_FILE)\" \
       -DVTUN_STAT_DIR=\"$(STAT_DIR)\" -DVTUN_LOCK_DIR=\"$(LOCK_DIR)\"


#AM_CPPFLAGS = -I/usr/include/ $(DEFS) 

ACLOCAL_AMFLAGS=-I ../m4
bin_PROGRAMS=SPServer
# Sources for the a.out 
SPServer_SOURCES= SPServer.c

# Libraries for a.out
SPServer_LDADD = $(top_srcdir)/libsptun/libsptun.la -lz -llzo2 -lcrypto -lc -lm -ll

# Linker options for a.out
SPServer_LDFLAGS = -rpath `cd $(top_srcdir);pwd`/libsptun/.libs 

# Compiler options for a.out
SPServer_CPPFLAGS = -I$(top_srcdir)/include $(DEFS) 
