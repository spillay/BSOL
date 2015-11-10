# put common definitions in here
CC = gcc
CFLAGS = -g -O2 -fPIC -I/usr/include/lzo -I/usr/include/openssl
LDFLAGS =   -lz -llzo2 -lcrypto -lc
SOFLAGS = -shared -fPIC -Wl,-soname,libspvtun.so.1

YACC = bison -y
YACCFLAGS = -d

LEX = flex
LEXFLAGS = -t 

INSTALL = /usr/bin/install -c
INSTALL_OWNER = -o root -g 0

prefix = /usr/local
exec_prefix = ${prefix}

SBIN_DIR = ${exec_prefix}/sbin
BIN_DIR  = ${exec_prefix}/bin
MAN_DIR  = ${prefix}/share/man
ETC_DIR  = ${prefix}/etc
VAR_DIR  = ${prefix}/var

PID_FILE = ${VAR_DIR}/run/vtund.pid
CFG_FILE = ${ETC_DIR}/vtund.conf
STAT_DIR = ${VAR_DIR}/log/vtund
LOCK_DIR = ${VAR_DIR}/lock/vtund

DEFS = -DVTUN_CONFIG_FILE=\"$(CFG_FILE)\" -DVTUN_PID_FILE=\"$(PID_FILE)\" \
       -DVTUN_STAT_DIR=\"$(STAT_DIR)\" -DVTUN_LOCK_DIR=\"$(LOCK_DIR)\"

.SILENT :
