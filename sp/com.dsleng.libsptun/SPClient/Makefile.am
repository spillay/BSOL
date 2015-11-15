ACLOCAL_AMFLAGS=-I ../m4
bin_PROGRAMS=SPClient
# Sources for the a.out 
SPClient_SOURCES= SPClient.c

# Libraries for a.out
SPClient_LDADD = $(top_srcdir)/libsptun/libsptun.la -lz -llzo2 -lcrypto -lc -lm -ll

# Linker options for a.out
SPClient_LDFLAGS = -rpath `cd $(top_srcdir);pwd`/libsptun/.libs 

# Compiler options for a.out
SPClient_CPPFLAGS = -I$(top_srcdir)/include
