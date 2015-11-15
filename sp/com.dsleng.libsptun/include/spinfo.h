/*
 * spinfo.h
 *
 *  Created on: 15 Nov 2015
 *      Author: suresh
 */

#ifndef SPINFO_H_
#define SPINFO_H_

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/mman.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#define CHAR_SIZE 1024

void showFDIP(int fd,char* desc);

#endif /* SPINFO_H_ */
