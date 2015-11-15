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


AM_CPPFLAGS = -I/usr/include/ $(DEFS) 
AM_LDFLAGS = -lz -llzo2 -lcrypto -lc -lm -ll
PARSER = cfg_file.tab.c cfg_file.lex.c lex.yy.c
BUILT_SOURCES = cfg_file.tab.h
AM_YFLAGS = -d
AM_LFLAGS = -t


OBJS = libsptun.c main.c server.c client.c lib.c \
       llist.c auth.c tunnel.c lock.c netlib.c  \
       tun_dev.c tap_dev.c pty_dev.c pipe_dev.c \
       tcp_proto.c udp_proto.c \
       linkfd.c spinfo.c
LFD_OBJS = lfd_shaper.c lfd_zlib.c lfd_lzo.c lfd_encrypt.c lfd_legacy_encrypt.c

lib_LTLIBRARIES = libsptun.la
libsptun_la_SOURCES = $(PARSER) $(OBJS) $(LFD_OBJS)
libsptun_la_CPPFLAGS = -I$(top_srcdir)/include
libsptun_la_LDFLAGS = -version-info 0:0:0


#cfg_file.tab.h:
#	$(YACC) $(YACCFLAGS) -b cfg_file cfg_file.y

cfg_file.tab.c: cfg_file.y cfg_kwords.h  cfg_file.tab.h
	$(YACC) $(YACCFLAGS) -b cfg_file cfg_file.y
cfg_file.lex.c: cfg_file.l cfg_kwords.h  cfg_file.tab.h
	$(LEX) $(LEXFLAGS) cfg_file.l > cfg_file.lex.c 