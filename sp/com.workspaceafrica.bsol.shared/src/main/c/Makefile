include ../../../Makefile.inc

all: SPClient
	@echo "compiling base for Vtun"
	
OBJS = main.o cfg_file.tab.o cfg_file.lex.o server.o client.o lib.o \
       llist.o auth.o tunnel.o lock.o netlib.o  \
       tun_dev.o tap_dev.o pty_dev.o pipe_dev.o \
       tcp_proto.o udp_proto.o \
       linkfd.o 
	
LFD_OBJS = lfd_shaper.o lfd_zlib.o lfd_lzo.o lfd_encrypt.o lfd_legacy_encrypt.o
	
	
%.o: %.c vtun.h lib.h
	$(CC) $(CFLAGS) $(DEFS) -c $<

SPClient: $(OBJS) $(LFD_OBJS)
	$(CC) $(CFLAGS) -o SPClient $(OBJS) $(LFD_OBJS) $(LDFLAGS)
	
cfg_file.tab.h:
	$(YACC) $(YACCFLAGS) -b cfg_file cfg_file.y

cfg_file.tab.c: cfg_file.y cfg_kwords.h config.h cfg_file.tab.h

cfg_file.lex.c: cfg_file.l cfg_kwords.h config.h cfg_file.tab.h
	$(LEX) $(LEXFLAGS) cfg_file.l > cfg_file.lex.c 
	
clean:
	rm -f core cfg_file.tab.* cfg_file.lex.* *.o *~ .#* *.bak SPClient